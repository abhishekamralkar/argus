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
	// Create tables (no-op if they already exist with original schema)
	if _, err := db.Exec(`
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

		CREATE TABLE IF NOT EXISTS vulnerability_chunks (
			chunk_id  VARCHAR PRIMARY KEY,
			vuln_id   VARCHAR NOT NULL,
			content   TEXT NOT NULL,
			embedding FLOAT[768]
		);
		CREATE INDEX IF NOT EXISTS idx_chunks_vuln ON vulnerability_chunks (vuln_id);

		CREATE TABLE IF NOT EXISTS ingest_log (
			source      VARCHAR PRIMARY KEY,
			last_run_at TIMESTAMPTZ NOT NULL
		);
	`); err != nil {
		return err
	}

	// Additive migrations — safe to run on any existing DB.
	migrations := []string{
		`ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS aliases VARCHAR`,
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			return fmt.Errorf("migration %q: %w", m, err)
		}
	}
	return nil
}

// UpsertVulnMeta stores only the vulnerability metadata (no embedding).
func (s *DB) UpsertVulnMeta(v *Vulnerability) error {
	aliases := strings.Join(v.Aliases, ",")
	_, err := s.db.Exec(`
		INSERT INTO vulnerabilities (id, ecosystem, package, severity, fixed_in, aliases, content)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			severity = excluded.severity,
			fixed_in = excluded.fixed_in,
			aliases  = excluded.aliases,
			content  = excluded.content
	`, v.ID, v.Ecosystem, v.Package, v.Severity, v.FixedIn, aliases, v.Summary+"\n"+v.Details)
	return err
}

// DeleteChunksForVuln removes all chunks for a vulnerability ID before re-ingesting.
func (s *DB) DeleteChunksForVuln(vulnID string) error {
	_, err := s.db.Exec(`DELETE FROM vulnerability_chunks WHERE vuln_id = ?`, vulnID)
	return err
}

// TouchIngestLog records a successful ingest run for the given source name.
func (s *DB) TouchIngestLog(source string) error {
	_, err := s.db.Exec(`
		INSERT INTO ingest_log (source, last_run_at) VALUES (?, NOW())
		ON CONFLICT (source) DO UPDATE SET last_run_at = excluded.last_run_at
	`, source)
	return err
}

// StatusReport holds DB statistics for the status subcommand.
type StatusReport struct {
	Ecosystem  string
	VulnCount  int64
	ChunkCount int64
	LastIngest string
}

// Status returns per-ecosystem statistics.
func (s *DB) Status() ([]StatusReport, error) {
	rows, err := s.db.Query(`
		SELECT v.ecosystem,
		       COUNT(DISTINCT v.id)      AS vuln_count,
		       COUNT(c.chunk_id)         AS chunk_count
		FROM vulnerabilities v
		LEFT JOIN vulnerability_chunks c ON c.vuln_id = v.id
		GROUP BY v.ecosystem
		ORDER BY v.ecosystem
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StatusReport
	for rows.Next() {
		var r StatusReport
		if err := rows.Scan(&r.Ecosystem, &r.VulnCount, &r.ChunkCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Attach last ingest times
	logRows, err := s.db.Query(`SELECT source, last_run_at FROM ingest_log`)
	if err != nil {
		return out, nil // ingest_log may be empty
	}
	defer logRows.Close()
	logMap := make(map[string]string)
	for logRows.Next() {
		var src, ts string
		if logRows.Scan(&src, &ts) == nil {
			logMap[src] = ts
		}
	}
	for i, r := range out {
		if ts, ok := logMap[r.Ecosystem]; ok {
			out[i].LastIngest = ts
		}
	}
	return out, nil
}

type ChunkItem struct {
	ChunkID   string
	VulnID    string
	Content   string
	Embedding []float32
}

// UpsertChunkBatch writes a slice of embedded chunks in a single transaction.
func (s *DB) UpsertChunkBatch(chunks []ChunkItem) error {
	if len(chunks) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range chunks {
		_, err := tx.Exec(fmt.Sprintf(`
			INSERT INTO vulnerability_chunks (chunk_id, vuln_id, content, embedding)
			VALUES (?, ?, ?, %s::FLOAT[768])
			ON CONFLICT (chunk_id) DO UPDATE SET
				content   = excluded.content,
				embedding = excluded.embedding
		`, floatSliceToArray(c.Embedding)),
			c.ChunkID, c.VulnID, c.Content,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ExistsVuln returns true if any chunks have been stored for this vulnerability ID.
func (s *DB) ExistsVuln(id string) bool {
	var n int
	s.db.QueryRow(`SELECT 1 FROM vulnerability_chunks WHERE vuln_id = ? LIMIT 1`, id).Scan(&n)
	return n == 1
}

// SearchBest searches vulnerability_chunks when available, falling back to
// the legacy vulnerabilities.embedding for DBs ingested without chunking.
func (s *DB) SearchBest(ecosystem string, embedding []float32, limit int) ([]SearchResult, error) {
	// Check whether the chunks table has any data for this ecosystem.
	var chunkCount int64
	s.db.QueryRow(`
		SELECT COUNT(*) FROM vulnerability_chunks c
		JOIN vulnerabilities v ON c.vuln_id = v.id
		WHERE v.ecosystem = ? LIMIT 1
	`, ecosystem).Scan(&chunkCount)

	if chunkCount > 0 {
		return s.searchChunks(ecosystem, embedding, limit)
	}
	return s.Search(ecosystem, embedding, limit)
}

// searchChunks finds the best-matching chunk per vulnerability and deduplicates.
func (s *DB) searchChunks(ecosystem string, embedding []float32, limit int) ([]SearchResult, error) {
	arr := floatSliceToArray(embedding)
	// Retrieve more candidates than limit to allow deduplication.
	rows, err := s.db.Query(fmt.Sprintf(`
		SELECT c.vuln_id, v.ecosystem, v.package, v.severity, v.fixed_in, COALESCE(v.aliases,''), c.content,
		       array_cosine_similarity(c.embedding, %s::FLOAT[768]) AS score
		FROM vulnerability_chunks c
		JOIN vulnerabilities v ON c.vuln_id = v.id
		WHERE v.ecosystem = ?
		  AND array_cosine_similarity(c.embedding, %s::FLOAT[768]) > 0.5
		ORDER BY score DESC
		LIMIT ?
	`, arr, arr), ecosystem, limit*3)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := make(map[string]bool)
	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var aliasStr string
		if err := rows.Scan(&r.ID, &r.Ecosystem, &r.Package, &r.Severity, &r.FixedIn, &aliasStr, &r.Content, &r.Score); err != nil {
			return nil, err
		}
		r.Aliases = splitAliases(aliasStr)
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		results = append(results, r)
		if len(results) >= limit {
			break
		}
	}
	return results, rows.Err()
}

func (s *DB) CountChunks(ecosystem string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM vulnerability_chunks c
		JOIN vulnerabilities v ON c.vuln_id = v.id
		WHERE v.ecosystem = ?
	`, ecosystem).Scan(&n)
	return n, err
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
	_, err := s.db.Exec(fmt.Sprintf(`
		INSERT INTO vulnerabilities (id, ecosystem, package, severity, fixed_in, content, embedding)
		VALUES (?, ?, ?, ?, ?, ?, %s::FLOAT[768])
		ON CONFLICT (id) DO UPDATE SET
			severity  = excluded.severity,
			fixed_in  = excluded.fixed_in,
			content   = excluded.content,
			embedding = excluded.embedding
	`, floatSliceToArray(embedding)),
		v.ID, v.Ecosystem, v.Package, v.Severity, v.FixedIn, content,
	)
	return err
}

type SearchResult struct {
	ID        string
	Ecosystem string
	Package   string
	Severity  string
	FixedIn   string
	Aliases   []string
	Content   string
	Score     float64
}

func (s *DB) Search(ecosystem string, embedding []float32, limit int) ([]SearchResult, error) {
	rows, err := s.db.Query(`
		SELECT id, ecosystem, package, severity, fixed_in, COALESCE(aliases,''), content,
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
		var aliasStr string
		if err := rows.Scan(&r.ID, &r.Ecosystem, &r.Package, &r.Severity, &r.FixedIn, &aliasStr, &r.Content, &r.Score); err != nil {
			return nil, err
		}
		r.Aliases = splitAliases(aliasStr)
		results = append(results, r)
	}
	return results, rows.Err()
}

func splitAliases(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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

	for _, item := range batch {
		v := item.Vuln
		content := v.Summary
		if v.Details != "" {
			content += "\n" + v.Details
		}
		if len(content) > 4000 {
			content = content[:4000]
		}
		aliases := strings.Join(v.Aliases, ",")
		_, err := tx.Exec(fmt.Sprintf(`
			INSERT INTO vulnerabilities (id, ecosystem, package, severity, fixed_in, aliases, content, embedding)
			VALUES (?, ?, ?, ?, ?, ?, ?, %s::FLOAT[768])
			ON CONFLICT (id) DO UPDATE SET
				severity  = excluded.severity,
				fixed_in  = excluded.fixed_in,
				aliases   = excluded.aliases,
				content   = excluded.content,
				embedding = excluded.embedding
		`, floatSliceToArray(item.Embedding)),
			v.ID, v.Ecosystem, v.Package, v.Severity, v.FixedIn, aliases, content,
		)
		if err != nil {
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
