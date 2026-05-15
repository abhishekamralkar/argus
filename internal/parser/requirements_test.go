package parser

import "testing"

func TestParseRequirement_CompoundConstraints(t *testing.T) {
	cases := []struct {
		input   string
		name    string
		version string
	}{
		{"requests==2.28.0", "requests", "2.28.0"},
		{"flask>=2.0,<3.0", "flask", "2.0"},
		{"django~=4.2.0", "django", "4.2.0"},
		{"numpy", "numpy", ""},
		{"scipy>=1.0,<=2.0,!=1.5", "scipy", "1.0"},
		{"urllib3>=1.26.0, <2.0", "urllib3", "1.26.0"},
	}
	for _, c := range cases {
		name, version := parseRequirement(c.input)
		if name != c.name || version != c.version {
			t.Errorf("parseRequirement(%q) = (%q, %q), want (%q, %q)",
				c.input, name, version, c.name, c.version)
		}
	}
}
