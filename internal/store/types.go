package store

import "time"

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
	CVSSScore  float64 // numeric CVSS v3 base score (0 = not available)
	CVSSVector string  // raw CVSS v3 vector string, e.g. "CVSS:3.1/AV:N/..."
}
