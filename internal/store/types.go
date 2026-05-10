package store

import "time"

// ScanRun records the aggregate outcome of a single argus scan invocation.
type ScanRun struct {
	ID            string
	ProjectDir    string
	ScannedAt     time.Time
	DepCount      int
	TotalFindings int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
}

type Vulnerability struct {
	ID         string
	Ecosystem  string
	Package    string
	Aliases    []string
	Summary    string
	Details    string
	Severity   string
	FixedIn    string
	Published  time.Time
	Modified   time.Time // last modification date; used for incremental ingest filtering; not persisted
	CVSSScore  float64   // numeric CVSS v3 base score (0 = not available)
	CVSSVector string    // raw CVSS v3 vector string, e.g. "CVSS:3.1/AV:N/..."
}
