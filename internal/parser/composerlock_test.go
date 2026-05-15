package parser_test

import (
	"testing"

	"github.com/abhishekamralkar/argus/internal/parser"
)

func TestParseComposerLock(t *testing.T) {
	deps, err := parser.ParseComposerLock("testdata/composer.lock")
	if err != nil {
		t.Fatalf("ParseComposerLock: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"doctrine/orm", "2.15.0"},
		{"phpunit/phpunit", "10.3.2"},
		{"symfony/http-kernel", "v6.3.4"},
	}
	for _, c := range cases {
		d, ok := byName[c.name]
		if !ok {
			t.Errorf("missing dependency %s", c.name)
			continue
		}
		if d.Version != c.version {
			t.Errorf("%s: want version %q, got %q", c.name, c.version, d.Version)
		}
		if d.Ecosystem != "php" {
			t.Errorf("%s: want ecosystem php, got %s", c.name, d.Ecosystem)
		}
	}
}
