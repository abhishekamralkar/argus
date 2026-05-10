package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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
		_ = db.Close()
		return nil, err
	}
	return &DB{db: db}, nil
}

func (s *DB) Close() error {
	return s.db.Close()
}

func migrate(db *sql.DB) error {
	// Create tables (no-op if they already exist with original schema)
	if _, err := db.ExecContext(context.Background(), `
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
		`ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_score FLOAT`,
		`ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_vector VARCHAR`,
	}
	for _, m := range migrations {
		if _, err := db.ExecContext(context.Background(), m); err != nil {
			return fmt.Errorf("migration %q: %w", m, err)
		}
	}
	return nil
}

// buildVulnContent constructs the text content for a vulnerability, truncated
// to 4000 characters. Shared by Upsert, UpsertBatch, and UpsertVulnMeta.
func buildVulnContent(v *Vulnerability) string {
	content := v.Summary + "\n" + v.Details
	if len(content) > 4000 {
		content = content[:4000]
	}
	return content
}

// UpsertVulnMeta stores only the vulnerability metadata (no embedding).
func (s *DB) UpsertVulnMeta(ctx context.Context, v *Vulnerability) error {
	aliases := strings.Join(v.Aliases, ",")
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, ecosystem, package, severity, fixed_in, aliases, content, cvss_score, cvss_vector)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			severity    = excluded.severity,
			fixed_in    = excluded.fixed_in,
			aliases     = excluded.aliases,
			content     = excluded.content,
			cvss_score  = excluded.cvss_score,
			cvss_vector = excluded.cvss_vector
	`, v.ID, v.Ecosystem, v.Package, v.Severity, v.FixedIn, aliases, buildVulnContent(v), v.CVSSScore, v.CVSSVector)
	return err
}

// DeleteChunksForVuln removes all chunks for a vulnerability ID before re-ingesting.
func (s *DB) DeleteChunksForVuln(ctx context.Context, vulnID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vulnerability_chunks WHERE vuln_id = ?`, vulnID)
	return err
}

// GetLastIngest returns the timestamp of the most recent successful ingest run
// for the given source, and true if a record exists.
func (s *DB) GetLastIngest(ctx context.Context, source string) (time.Time, bool, error) {
	var ts time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT last_run_at FROM ingest_log WHERE source = ?`, source,
	).Scan(&ts)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return ts, true, nil
}

// Fingerprint returns a SHA-256 hex digest and the total vulnerability count
// that together uniquely identify the DB state. The digest changes whenever
// vulns are added/updated or an ingest run is recorded.
func (s *DB) Fingerprint(ctx context.Context) (digest string, total int64, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.ecosystem, COUNT(DISTINCT v.id), COALESCE(MAX(l.last_run_at::TEXT), '')
		FROM vulnerabilities v
		LEFT JOIN ingest_log l ON l.source LIKE '%' || v.ecosystem || '%'
		GROUP BY v.ecosystem
		ORDER BY v.ecosystem
	`)
	if err != nil {
		return "", 0, fmt.Errorf("fingerprint query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var lines []string
	for rows.Next() {
		var eco, lastIngest string
		var count int64
		if err := rows.Scan(&eco, &count, &lastIngest); err != nil {
			return "", 0, err
		}
		total += count
		lines = append(lines, fmt.Sprintf("%s:%d:%s", eco, count, lastIngest))
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return fmt.Sprintf("sha256:%x", h), total, nil
}

// TouchIngestLog records a successful ingest run for the given source name.
func (s *DB) TouchIngestLog(ctx context.Context, source string) error {
	_, err := s.db.ExecContext(ctx, `
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
func (s *DB) Status(ctx context.Context) ([]StatusReport, error) {
	rows, err := s.db.QueryContext(ctx, `
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
	defer func() { _ = rows.Close() }()

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
	logRows, err := s.db.QueryContext(ctx, `SELECT source, last_run_at FROM ingest_log`)
	if err != nil {
		return out, nil // ingest_log may be empty
	}
	defer func() { _ = logRows.Close() }()
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

// UpsertChunkBatch writes a slice of embedded chunks in a single transaction
// using one multi-value INSERT statement.
func (s *DB) UpsertChunkBatch(ctx context.Context, chunks []ChunkItem) error {
	if len(chunks) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var sb strings.Builder
	sb.WriteString("INSERT INTO vulnerability_chunks (chunk_id, vuln_id, content, embedding) VALUES ")
	args := make([]any, 0, len(chunks)*3)
	for i, c := range chunks {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "(?,?,?,%s::FLOAT[768])", floatSliceToArray(c.Embedding))
		args = append(args, c.ChunkID, c.VulnID, c.Content)
	}
	sb.WriteString(" ON CONFLICT (chunk_id) DO UPDATE SET content=excluded.content, embedding=excluded.embedding")

	if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
		return err
	}
	return tx.Commit()
}

// ExistsVuln returns true if any chunks have been stored for this vulnerability ID.
func (s *DB) ExistsVuln(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM vulnerability_chunks WHERE vuln_id = ? LIMIT 1`, id).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return n == 1, err
}

// DefaultSimilarityThreshold is the cosine similarity cutoff used when no
// explicit threshold is provided. Raise it to reduce false positives; lower
// it to improve recall on unusual package names.
const DefaultSimilarityThreshold = 0.5

// SearchBest searches vulnerability_chunks when available, falling back to
// the legacy vulnerabilities.embedding for DBs ingested without chunking.
func (s *DB) SearchBest(ctx context.Context, ecosystem string, embedding []float32, limit int, threshold float64) ([]SearchResult, error) {
	// Check whether the chunks table has any data for this ecosystem.
	var chunkCount int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM vulnerability_chunks c
		JOIN vulnerabilities v ON c.vuln_id = v.id
		WHERE v.ecosystem = ? LIMIT 1
	`, ecosystem).Scan(&chunkCount)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("check chunk table: %w", err)
	}

	if chunkCount > 0 {
		return s.searchChunks(ctx, ecosystem, embedding, limit, threshold)
	}
	return s.Search(ctx, ecosystem, embedding, limit, threshold)
}

// searchChunks finds the best-matching chunk per vulnerability using a SQL
// window function to deduplicate, returning at most one result per vuln_id.
func (s *DB) searchChunks(ctx context.Context, ecosystem string, embedding []float32, limit int, threshold float64) ([]SearchResult, error) {
	arr := floatSliceToArray(embedding)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		WITH scored AS (
			SELECT c.vuln_id, v.ecosystem, v.package, v.severity, v.fixed_in,
			       COALESCE(v.aliases,'') AS aliases, c.content,
			       COALESCE(v.cvss_score, 0.0) AS cvss_score,
			       COALESCE(v.cvss_vector, '') AS cvss_vector,
			       array_cosine_similarity(c.embedding, %s::FLOAT[768]) AS score
			FROM vulnerability_chunks c
			JOIN vulnerabilities v ON c.vuln_id = v.id
			WHERE v.ecosystem = ?
		),
		ranked AS (
			SELECT *, ROW_NUMBER() OVER (PARTITION BY vuln_id ORDER BY score DESC) AS rn
			FROM scored
			WHERE score > ?
		)
		SELECT vuln_id, ecosystem, package, severity, fixed_in, aliases, content, score, cvss_score, cvss_vector
		FROM ranked
		WHERE rn = 1
		ORDER BY score DESC
		LIMIT ?
	`, arr), ecosystem, threshold, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var aliasStr string
		if err := rows.Scan(&r.ID, &r.Ecosystem, &r.Package, &r.Severity, &r.FixedIn, &aliasStr, &r.Content, &r.Score, &r.CVSSScore, &r.CVSSVector); err != nil {
			return nil, err
		}
		r.Aliases = splitAliases(aliasStr)
		results = append(results, r)
	}
	return results, rows.Err()
}

func (s *DB) CountChunks(ctx context.Context, ecosystem string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM vulnerability_chunks c
		JOIN vulnerabilities v ON c.vuln_id = v.id
		WHERE v.ecosystem = ?
	`, ecosystem).Scan(&n)
	return n, err
}

func (s *DB) Upsert(ctx context.Context, v *Vulnerability, embedding []float32) error {
	if len(embedding) != embeddingDim {
		return fmt.Errorf("embedding must be %d-dimensional, got %d", embeddingDim, len(embedding))
	}
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO vulnerabilities (id, ecosystem, package, severity, fixed_in, content, embedding)
		VALUES (?, ?, ?, ?, ?, ?, %s::FLOAT[768])
		ON CONFLICT (id) DO UPDATE SET
			severity  = excluded.severity,
			fixed_in  = excluded.fixed_in,
			content   = excluded.content,
			embedding = excluded.embedding
	`, floatSliceToArray(embedding)),
		v.ID, v.Ecosystem, v.Package, v.Severity, v.FixedIn, buildVulnContent(v),
	)
	return err
}

type SearchResult struct {
	ID         string
	Ecosystem  string
	Package    string
	Severity   string
	FixedIn    string
	Aliases    []string
	Content    string
	Score      float64 // vector cosine-similarity score
	CVSSScore  float64 // CVSS v3 base score (0 = not available)
	CVSSVector string  // raw CVSS v3 vector string
}

func (s *DB) Search(ctx context.Context, ecosystem string, embedding []float32, limit int, threshold float64) ([]SearchResult, error) {
	arr := floatSliceToArray(embedding)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT id, ecosystem, package, severity, fixed_in, COALESCE(aliases,''), content,
		       array_cosine_similarity(embedding, %s::FLOAT[768]) AS score,
		       COALESCE(cvss_score, 0.0), COALESCE(cvss_vector, '')
		FROM vulnerabilities
		WHERE ecosystem = ?
		  AND array_cosine_similarity(embedding, %s::FLOAT[768]) > ?
		ORDER BY score DESC
		LIMIT ?
	`, arr, arr), ecosystem, threshold, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var aliasStr string
		if err := rows.Scan(&r.ID, &r.Ecosystem, &r.Package, &r.Severity, &r.FixedIn, &aliasStr, &r.Content, &r.Score, &r.CVSSScore, &r.CVSSVector); err != nil {
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

func (s *DB) Count(ctx context.Context, ecosystem string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE ecosystem = ?`, ecosystem).Scan(&n)
	return n, err
}

func (s *DB) Exists(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM vulnerabilities WHERE id = ? LIMIT 1`, id).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return n == 1, err
}

type EmbeddedVuln struct {
	Vuln      *Vulnerability
	Embedding []float32
}

// UpsertBatch writes a slice of pre-embedded vulnerabilities in a single
// transaction using one multi-value INSERT statement.
func (s *DB) UpsertBatch(ctx context.Context, batch []EmbeddedVuln) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var sb strings.Builder
	sb.WriteString("INSERT INTO vulnerabilities (id, ecosystem, package, severity, fixed_in, aliases, content, cvss_score, cvss_vector, embedding) VALUES ")
	args := make([]any, 0, len(batch)*9)
	for i, item := range batch {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "(?,?,?,?,?,?,?,?,?,%s::FLOAT[768])", floatSliceToArray(item.Embedding))
		v := item.Vuln
		args = append(args, v.ID, v.Ecosystem, v.Package, v.Severity, v.FixedIn, strings.Join(v.Aliases, ","), buildVulnContent(v), v.CVSSScore, v.CVSSVector)
	}
	sb.WriteString(` ON CONFLICT (id) DO UPDATE SET
		severity    = excluded.severity,
		fixed_in    = excluded.fixed_in,
		aliases     = excluded.aliases,
		content     = excluded.content,
		cvss_score  = excluded.cvss_score,
		cvss_vector = excluded.cvss_vector,
		embedding   = excluded.embedding`)

	if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
		return err
	}
	return tx.Commit()
}

// floatSliceToArray converts []float32 to a DuckDB array literal string.
// Uses strconv.AppendFloat to avoid per-element allocations.
func floatSliceToArray(v []float32) string {
	var b strings.Builder
	b.Grow(len(v)*8 + 2)
	b.WriteByte('[')
	buf := make([]byte, 0, 16)
	for i, f := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		buf = strconv.AppendFloat(buf[:0], float64(f), 'g', -1, 32)
		b.Write(buf)
	}
	b.WriteByte(']')
	return b.String()
}
