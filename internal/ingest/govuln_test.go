package ingest

import (
	"math"
	"testing"
)

func TestCvssScoreToSeverity(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{10.0, "CRITICAL"},
		{9.0, "CRITICAL"},
		{8.9, "HIGH"},
		{7.0, "HIGH"},
		{6.9, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.9, "LOW"},
		{0.1, "LOW"},
		{0.0, ""},
	}
	for _, c := range cases {
		if got := cvssScoreToSeverity(c.score); got != c.want {
			t.Errorf("cvssScoreToSeverity(%.1f) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestParseCVSSScore(t *testing.T) {
	cases := []struct {
		vector    string
		wantScore float64
		wantOK    bool
	}{
		// CVSS 3.1 — standard NVD test vectors
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, true},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, true},
		// CVSS 4.0 — network attack, no subsequent-system impact → 9.30 per spec
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.30, true},
		// Malformed / unrecognised
		{"notavector", 0, false},
		{"CVSS:3.1/AV:N/AC:L", 0, false},
	}
	for _, c := range cases {
		got, ok := parseCVSSScore(c.vector)
		if ok != c.wantOK {
			t.Errorf("parseCVSSScore(%q) ok=%v, want %v", c.vector, ok, c.wantOK)
			continue
		}
		if ok && math.Abs(got-c.wantScore) > 0.15 {
			t.Errorf("parseCVSSScore(%q) = %.2f, want ~%.2f", c.vector, got, c.wantScore)
		}
	}
}

func TestSeverityFromGoVuln_DatabaseSpecific(t *testing.T) {
	rec := &goVulnRecord{}
	rec.DatabaseSpecific.Severity = "HIGH"
	if got := severityFromGoVuln(rec); got != "HIGH" {
		t.Errorf("got %q, want HIGH", got)
	}
}

func TestSeverityFromGoVuln_NormalizesCase(t *testing.T) {
	rec := &goVulnRecord{}
	rec.DatabaseSpecific.Severity = "moderate"
	// "moderate" normalizes to "MEDIUM" via normalizeSeverity
	if got := severityFromGoVuln(rec); got != "MEDIUM" {
		t.Errorf("got %q, want MEDIUM", got)
	}
}

func TestSeverityFromGoVuln_FallsBackToCVSS(t *testing.T) {
	rec := &goVulnRecord{}
	// No database_specific.severity — should use CVSS vector
	rec.Severity = []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	got := severityFromGoVuln(rec)
	if got != "CRITICAL" {
		t.Errorf("got %q, want CRITICAL", got)
	}
}

func TestSeverityFromGoVuln_EmptyWhenNoData(t *testing.T) {
	rec := &goVulnRecord{}
	if got := severityFromGoVuln(rec); got != "" {
		t.Errorf("got %q, want empty string when no severity data", got)
	}
}

func TestSeverityFromGoVuln_IgnoresNonCVSSV3(t *testing.T) {
	rec := &goVulnRecord{}
	rec.Severity = []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{
		{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
	}
	// CVSS v2 is not handled — should return ""
	if got := severityFromGoVuln(rec); got != "" {
		t.Errorf("got %q, want empty string for CVSS v2 input", got)
	}
}
