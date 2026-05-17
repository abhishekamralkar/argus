package parser

import (
	"testing"
)

func TestParsePodfileLock(t *testing.T) {
	deps, err := ParsePodfileLock("testdata/Podfile.lock")
	if err != nil {
		t.Fatalf("ParsePodfileLock: %v", err)
	}
	want := map[string]string{
		"Alamofire":   "5.6.4",
		"Kingfisher":  "7.6.2",
		"SwiftyJSON":  "5.0.1",
	}
	if len(deps) != len(want) {
		t.Fatalf("got %d deps, want %d: %+v", len(deps), len(want), deps)
	}
	for _, d := range deps {
		if d.Ecosystem != "swift" {
			t.Errorf("%s: ecosystem = %q, want swift", d.Name, d.Ecosystem)
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

func TestParsePackageResolvedV2(t *testing.T) {
	deps, err := ParsePackageResolved("testdata/Package.resolved")
	if err != nil {
		t.Fatalf("ParsePackageResolved: %v", err)
	}
	want := map[string]string{
		"alamofire":        "5.6.4",
		"swift-algorithms": "1.0.0",
	}
	if len(deps) != len(want) {
		t.Fatalf("got %d deps, want %d: %+v", len(deps), len(want), deps)
	}
	for _, d := range deps {
		if d.Ecosystem != "swift" {
			t.Errorf("%s: ecosystem = %q, want swift", d.Name, d.Ecosystem)
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

func TestParsePubspecLock(t *testing.T) {
	deps, err := ParsePubspecLock("testdata/pubspec.lock")
	if err != nil {
		t.Fatalf("ParsePubspecLock: %v", err)
	}
	want := map[string]string{
		"http":         "0.13.6",
		"collection":   "1.17.0",
		"flutter_lints": "2.0.2",
	}
	if len(deps) != len(want) {
		t.Fatalf("got %d deps, want %d: %+v", len(deps), len(want), deps)
	}
	for _, d := range deps {
		if d.Ecosystem != "dart" {
			t.Errorf("%s: ecosystem = %q, want dart", d.Name, d.Ecosystem)
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
