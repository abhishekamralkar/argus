package version

import "testing"

func TestAffectsVersion(t *testing.T) {
	tests := []struct {
		name    string
		scanned string
		fixedIn string
		want    bool
	}{
		{
			name:    "empty fixedIn means still vulnerable",
			scanned: "1.0.0",
			fixedIn: "",
			want:    true,
		},
		{
			name:    "scanned older than fix is vulnerable",
			scanned: "1.2.0",
			fixedIn: "1.3.0",
			want:    true,
		},
		{
			name:    "scanned equal to fix is not vulnerable",
			scanned: "1.3.0",
			fixedIn: "1.3.0",
			want:    false,
		},
		{
			name:    "scanned newer than fix is not vulnerable",
			scanned: "1.4.0",
			fixedIn: "1.3.0",
			want:    false,
		},
		{
			name:    "v-prefixed scanned version handled correctly",
			scanned: "v1.2.0",
			fixedIn: "v1.3.0",
			want:    true,
		},
		{
			name:    "v-prefixed equal versions not vulnerable",
			scanned: "v1.3.0",
			fixedIn: "v1.3.0",
			want:    false,
		},
		{
			name:    "go pseudo-version older than fix is vulnerable",
			scanned: "0.0.0-20240101000000-abcdef123456",
			fixedIn: "0.0.1",
			want:    true,
		},
		{
			name:    "major version bump: newer than fix is not vulnerable",
			scanned: "2.0.0",
			fixedIn: "1.9.9",
			want:    false,
		},
		// retained from original test cases for full coverage
		{
			name:    "patch older than fix is vulnerable",
			scanned: "1.0.0",
			fixedIn: "1.0.1",
			want:    true,
		},
		{
			name:    "minor older than fix is vulnerable",
			scanned: "0.9.0",
			fixedIn: "1.0.0",
			want:    true,
		},
		{
			name:    "pre-release suffix stripped before comparison",
			scanned: "1.0.0-beta",
			fixedIn: "1.0.1",
			want:    true,
		},
		{
			name:    "unparseable version is conservative",
			scanned: "unknown",
			fixedIn: "1.0.0",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AffectsVersion(tt.scanned, tt.fixedIn)
			if got != tt.want {
				t.Errorf("AffectsVersion(%q, %q) = %v, want %v", tt.scanned, tt.fixedIn, got, tt.want)
			}
		})
	}
}
