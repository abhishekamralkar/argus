package store

import (
	"context"
	"encoding/json"
	"time"
)

// BaselineEntry holds the stored scan state for one dependency.
type BaselineEntry struct {
	DepName   string
	Ecosystem string
	VulnIDs   []string
	ScannedAt time.Time
}

// ensureBaselineTable creates scan_baseline if it doesn't exist.
// Called lazily so existing DBs don't need a migration step.
func (s *DB) ensureBaselineTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS scan_baseline (
			project_key VARCHAR NOT NULL,
			dep_name    VARCHAR NOT NULL,
			ecosystem   VARCHAR NOT NULL,
			vuln_ids    VARCHAR NOT NULL,
			scanned_at  TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (project_key, dep_name, ecosystem)
		)
	`)
	return err
}

// LoadBaseline returns the stored vuln ID set for every dependency in the
// project, keyed by "dep_name\x00ecosystem".
func (s *DB) LoadBaseline(ctx context.Context, projectKey string) (map[string][]string, error) {
	if err := s.ensureBaselineTable(ctx); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT dep_name, ecosystem, vuln_ids
		FROM scan_baseline
		WHERE project_key = ?
	`, projectKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]string)
	for rows.Next() {
		var depName, ecosystem, raw string
		if err := rows.Scan(&depName, &ecosystem, &raw); err != nil {
			return nil, err
		}
		var ids []string
		if err := json.Unmarshal([]byte(raw), &ids); err != nil {
			return nil, err
		}
		out[depName+"\x00"+ecosystem] = ids
	}
	return out, rows.Err()
}

// SaveBaseline upserts scan results for the project. Entries with an empty
// VulnIDs slice are still stored so a "clean" scan replaces old findings.
func (s *DB) SaveBaseline(ctx context.Context, projectKey string, entries []BaselineEntry) error {
	if err := s.ensureBaselineTable(ctx); err != nil {
		return err
	}

	for _, e := range entries {
		raw, err := json.Marshal(e.VulnIDs)
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO scan_baseline (project_key, dep_name, ecosystem, vuln_ids, scanned_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (project_key, dep_name, ecosystem)
			DO UPDATE SET vuln_ids = excluded.vuln_ids, scanned_at = excluded.scanned_at
		`, projectKey, e.DepName, e.Ecosystem, string(raw), e.ScannedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

// ResetBaseline removes all stored baseline entries for the project.
func (s *DB) ResetBaseline(ctx context.Context, projectKey string) error {
	if err := s.ensureBaselineTable(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM scan_baseline WHERE project_key = ?`, projectKey)
	return err
}

// ListBaseline returns all stored entries for the project.
func (s *DB) ListBaseline(ctx context.Context, projectKey string) ([]BaselineEntry, error) {
	if err := s.ensureBaselineTable(ctx); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT dep_name, ecosystem, vuln_ids, scanned_at
		FROM scan_baseline
		WHERE project_key = ?
		ORDER BY dep_name, ecosystem
	`, projectKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []BaselineEntry
	for rows.Next() {
		var e BaselineEntry
		var raw string
		if err := rows.Scan(&e.DepName, &e.Ecosystem, &raw, &e.ScannedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &e.VulnIDs); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
