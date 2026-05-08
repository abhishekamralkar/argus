package version

import "testing"

func TestAffectsVersion(t *testing.T) {
	tests := []struct {
		name    string
		scanned string
		fixedIn string
		want    bool
	}{
		// ── basic cases ──────────────────────────────────────────────────────────
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
			name:    "major version bump: newer than fix is not vulnerable",
			scanned: "2.0.0",
			fixedIn: "1.9.9",
			want:    false,
		},
		// ── v-prefixed versions ───────────────────────────────────────────────
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
		// ── pre-release ordering (the key fix) ────────────────────────────────
		{
			name:    "pre-release is older than its own release — still vulnerable",
			scanned: "1.0.0-beta",
			fixedIn: "1.0.0",
			want:    true,
		},
		{
			name:    "rc is older than release — still vulnerable",
			scanned: "1.0.0-rc.1",
			fixedIn: "1.0.0",
			want:    true,
		},
		{
			name:    "pre-release is older than next patch — still vulnerable",
			scanned: "1.0.0-beta",
			fixedIn: "1.0.1",
			want:    true,
		},
		{
			name:    "pre-release is older than same version without pre-release",
			scanned: "v2.3.0-alpha",
			fixedIn: "v2.3.0",
			want:    true,
		},
		{
			name:    "release is not older than itself — not vulnerable",
			scanned: "1.0.0",
			fixedIn: "1.0.0-beta",
			want:    false,
		},
		// ── build metadata (ignored in comparison per semver spec) ────────────
		{
			name:    "build metadata is ignored — versions are equal",
			scanned: "1.0.0+build.1",
			fixedIn: "1.0.0",
			want:    false,
		},
		// ── Go pseudo-versions ────────────────────────────────────────────────
		{
			name:    "go pseudo-version older than fix is vulnerable",
			scanned: "0.0.0-20240101000000-abcdef123456",
			fixedIn: "0.0.1",
			want:    true,
		},
		// ── non-semver / fallback path ────────────────────────────────────────
		{
			name:    "two-part version older than fix is vulnerable",
			scanned: "1.2",
			fixedIn: "1.3",
			want:    true,
		},
		{
			name:    "two-part version newer than fix is not vulnerable",
			scanned: "1.4",
			fixedIn: "1.3",
			want:    false,
		},
		{
			name:    "date-based all-numeric version uses numeric fallback",
			scanned: "2024.01.01",
			fixedIn: "2024.02.01",
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
				t.Errorf("AffectsVersion(%q, %q) = %v, want %v",
					tt.scanned, tt.fixedIn, got, tt.want)
			}
		})
	}
}

func TestCanonicalSemver(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" means invalid semver
	}{
		{"1.2.3", "v1.2.3"},
		{"v1.2.3", "v1.2.3"},
		{"V1.2.3", "v1.2.3"},
		{"1.2.3-beta", "v1.2.3-beta"},
		{"1.2.3-rc.1", "v1.2.3-rc.1"},
		{"1.2.3+build", "v1.2.3+build"},
		{"0.0.0-20240101000000-abcdef123456", "v0.0.0-20240101000000-abcdef123456"},
		{"1.2", "v1.2"}, // two-part: x/mod/semver accepts this
		{"1.2.3.4", ""}, // four-part: not valid semver
		{"unknown", ""},
	}
	for _, c := range cases {
		got := canonicalSemver(c.in)
		if got != c.want {
			t.Errorf("canonicalSemver(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
