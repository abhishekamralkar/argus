package parser

import (
	"testing"
)

func TestParsePoetryLock(t *testing.T) {
	deps, err := ParsePoetryLock("testdata/poetry.lock")
	if err != nil {
		t.Fatalf("ParsePoetryLock: %v", err)
	}
	want := map[string]string{
		"certifi":  "2023.7.22",
		"requests": "2.31.0",
		"urllib3":  "2.0.4",
	}
	if len(deps) != len(want) {
		t.Fatalf("got %d deps, want %d", len(deps), len(want))
	}
	for _, d := range deps {
		if d.Ecosystem != "python" {
			t.Errorf("%s: ecosystem = %q, want python", d.Name, d.Ecosystem)
		}
		wantVer, ok := want[d.Name]
		if !ok {
			t.Errorf("unexpected dep %q", d.Name)
			continue
		}
		if d.Version != wantVer {
			t.Errorf("%s: version = %q, want %q", d.Name, d.Version, wantVer)
		}
	}
}

func TestParseUVLock(t *testing.T) {
	deps, err := ParseUVLock("testdata/uv.lock")
	if err != nil {
		t.Fatalf("ParseUVLock: %v", err)
	}
	want := map[string]string{
		"flask":    "3.0.2",
		"jinja2":   "3.1.3",
		"werkzeug": "3.0.1",
	}
	if len(deps) != len(want) {
		t.Fatalf("got %d deps, want %d", len(deps), len(want))
	}
	for _, d := range deps {
		if d.Ecosystem != "python" {
			t.Errorf("%s: ecosystem = %q, want python", d.Name, d.Ecosystem)
		}
		wantVer, ok := want[d.Name]
		if !ok {
			t.Errorf("unexpected dep %q", d.Name)
			continue
		}
		if d.Version != wantVer {
			t.Errorf("%s: version = %q, want %q", d.Name, d.Version, wantVer)
		}
	}
}

func TestParsePipfileLock(t *testing.T) {
	deps, err := ParsePipfileLock("testdata/Pipfile.lock")
	if err != nil {
		t.Fatalf("ParsePipfileLock: %v", err)
	}
	want := map[string]string{
		"django":   "4.2.3",
		"requests": "2.31.0",
		"pytest":   "7.4.0",
		"black":    "23.7.0",
	}
	if len(deps) != len(want) {
		t.Fatalf("got %d deps, want %d", len(deps), len(want))
	}
	for _, d := range deps {
		if d.Ecosystem != "python" {
			t.Errorf("%s: ecosystem = %q, want python", d.Name, d.Ecosystem)
		}
		wantVer, ok := want[d.Name]
		if !ok {
			t.Errorf("unexpected dep %q", d.Name)
			continue
		}
		if d.Version != wantVer {
			t.Errorf("%s: version = %q, want %q", d.Name, d.Version, wantVer)
		}
	}
}
