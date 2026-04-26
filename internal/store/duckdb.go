package store

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/marcboeker/go-duckdb"
)

const embeddingDim = 768

type DB struct {
	db *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db: db}, nil
}

func (s *DB) Close() error {
	return s.db.Close()
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id        VARCHAR PRIMARY KEY,
			ecosystem VARCHAR NOT NULL,
			package   VARCHAR NOT NULL,
			severity  VARCHAR,
			fixed_in  VARCHAR,
			content   TEXT,
			embedding FLOAT[768]
		);
		CREATE INDEX IF NOT EXISTS idx_eco_pkg ON vulnerabilities (ecosystem, package);
	`)
	return err
}

func (s *DB) Upsert(v *Vulnerability, embedding []float32) error {
	if len(embedding) != embeddingDim {
		return fmt.Errorf("embedding must be %d-dimensional, got %d", embeddingDim, len(embedding))
	}
	content := v.Summary
	if v.Details != "" {
		content += "\n" + v.Details
	}
	if len(content) > 4000 {
		content = content[:4000]
	}
	_, err := s.db.Exec(`
		INSERT INTO vulnerabilities (id, ecosystem, package, severity, fixed_in, content, embedding)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			ecosystem = excluded.ecosystem,
			package   = excluded.package,
			severity  = excluded.severity,
			fixed_in  = excluded.fixed_in,
			content   = excluded.content,
			embedding = excluded.embedding
	`,
		v.ID, v.Ecosystem, v.Package, v.Severity, v.FixedIn, content, floatSliceToArray(embedding),
	)
	return err
}

type SearchResult struct {
	ID        string
	Ecosystem string
	Package   string
	Severity  string
	FixedIn   string
	Content   string
	Score     float64
}

func (s *DB) Search(ecosystem string, embedding []float32, limit int) ([]SearchResult, error) {
	rows, err := s.db.Query(`
		SELECT id, ecosystem, package, severity, fixed_in, content,
		       array_cosine_similarity(embedding, ?::FLOAT[768]) AS score
		FROM vulnerabilities
		WHERE ecosystem = ?
		  AND array_cosine_similarity(embedding, ?::FLOAT[768]) > 0.5
		ORDER BY score DESC
		LIMIT ?
	`, floatSliceToArray(embedding), ecosystem, floatSliceToArray(embedding), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.ID, &r.Ecosystem, &r.Package, &r.Severity, &r.FixedIn, &r.Content, &r.Score); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

func (s *DB) Count(ecosystem string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE ecosystem = ?`, ecosystem).Scan(&n)
	return n, err
}

func (s *DB) Exists(id string) bool {
	var n int
	s.db.QueryRow(`SELECT 1 FROM vulnerabilities WHERE id = ? LIMIT 1`, id).Scan(&n)
	return n == 1
}

type EmbeddedVuln struct {
	Vuln      *Vulnerability
	Embedding []float32
}

// UpsertBatch writes a slice of pre-embedded vulnerabilities in a single transaction.
func (s *DB) UpsertBatch(batch []EmbeddedVuln) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO vulnerabilities (id, ecosystem, package, severity, fixed_in, content, embedding)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			ecosystem = excluded.ecosystem,
			package   = excluded.package,
			severity  = excluded.severity,
			fixed_in  = excluded.fixed_in,
			content   = excluded.content,
			embedding = excluded.embedding
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, item := range batch {
		v := item.Vuln
		content := v.Summary
		if v.Details != "" {
			content += "\n" + v.Details
		}
		if len(content) > 4000 {
			content = content[:4000]
		}
		if _, err := stmt.Exec(v.ID, v.Ecosystem, v.Package, v.Severity, v.FixedIn, content, floatSliceToArray(item.Embedding)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// floatSliceToArray converts []float32 to DuckDB array literal string.
func floatSliceToArray(v []float32) string {
	parts := make([]string, len(v))
	for i, f := range v {
		parts[i] = fmt.Sprintf("%g", f)
	}
	return "[" + strings.Join(parts, ",") + "]"
}
