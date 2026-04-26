package store

import "time"

type Vulnerability struct {
	ID        string
	Ecosystem string
	Package   string
	Aliases   []string
	Summary   string
	Details   string
	Severity  string
	FixedIn   string
	Published time.Time
}
