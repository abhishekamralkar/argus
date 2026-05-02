package version

import "testing"

func TestAffectsVersion(t *testing.T) {
	cases := []struct {
		scanned string
		fixedIn string
		want    bool
	}{
		// older than fix → vulnerable
		{"1.0.0", "1.0.1", true},
		{"1.2.3", "1.3.0", true},
		{"0.9.0", "1.0.0", true},
		// at fix or newer → not vulnerable
		{"1.0.1", "1.0.1", false},
		{"1.1.0", "1.0.9", false},
		{"2.0.0", "1.9.9", false},
		// v-prefix stripped
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.1", "v1.0.1", false},
		// pre-release stripped
		{"1.0.0-beta", "1.0.1", true},
		// no fix → always vulnerable
		{"1.0.0", "", true},
		// unparseable → conservative
		{"unknown", "1.0.0", true},
	}

	for _, c := range cases {
		got := AffectsVersion(c.scanned, c.fixedIn)
		if got != c.want {
			t.Errorf("AffectsVersion(%q, %q) = %v, want %v", c.scanned, c.fixedIn, got, c.want)
		}
	}
}
