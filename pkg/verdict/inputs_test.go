package verdict

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

var updateInputs = flag.Bool("update-inputs", false, "regenerate testdata/inputs with the label-derived test keys")

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestVerifyInputs: each testdata/inputs case is read with ReadInputs and
// either verifies to its expected digests or fails with its expected error
// before any Verified exists.
func TestVerifyInputs(t *testing.T) {
	if *updateInputs {
		generateInputs(t)
	}
	now := mustTime(t, inputsNow)
	for _, tc := range inputCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join("testdata", "inputs", tc.name)
			raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			var want struct {
				Error         string `json:"error"`
				BundleDigest  string `json:"bundle_digest"`
				ProfileDigest string `json:"profile_digest"`
				FloorEpoch    int64  `json:"floor_epoch"`
			}
			if err = json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			if want.Error != tc.want {
				t.Fatalf("expected.json error %q, case table says %q: run with -update-inputs", want.Error, tc.want)
			}
			in, err := ReadInputs(os.DirFS(dir), "bobthecorp", "keyring.json", "profile.dsse.json", "floor.dsse.json", "bundles")
			if err != nil {
				t.Fatal(err)
			}
			v, err := VerifyInputs(in, now)
			if want.Error != "" {
				if v != nil || err == nil || !strings.Contains(err.Error(), want.Error) {
					t.Fatalf("want error containing %q and no result, got %v, %v", want.Error, v != nil, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.BundleDigest != want.BundleDigest || v.ProfileDigest != want.ProfileDigest || v.Floor.Epoch != want.FloorEpoch {
				t.Fatalf("got %s %s %d, want %s %s %d", v.BundleDigest, v.ProfileDigest, v.Floor.Epoch, want.BundleDigest, want.ProfileDigest, want.FloorEpoch)
			}
			if len(v.Bundles) != 2 || v.Revocations.Epoch() != 1 || len(v.Warnings) != 0 {
				t.Fatalf("bundles %d, epoch %d, warnings %v", len(v.Bundles), v.Revocations.Epoch(), v.Warnings)
			}
		})
	}
}

// countingFS counts opens per path.
type countingFS struct {
	fs.FS
	mu    sync.Mutex
	opens map[string]int
}

func (c *countingFS) Open(name string) (fs.File, error) {
	c.mu.Lock()
	c.opens[name]++
	c.mu.Unlock()
	return c.FS.Open(name)
}

// TestReadOnce: ReadInputs opens every input file exactly once, and what is
// verified and handed to evaluation are those bytes: changing the files or
// the Inputs afterwards changes nothing.
func TestReadOnce(t *testing.T) {
	src := os.DirFS(filepath.Join("testdata", "inputs", "valid"))
	mfs := fstest.MapFS{}
	err := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == "expected.json" {
			return err
		}
		b, err := fs.ReadFile(src, p)
		mfs[p] = &fstest.MapFile{Data: b}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	cfs := &countingFS{FS: mfs, opens: map[string]int{}}
	in, err := ReadInputs(cfs, "bobthecorp", "keyring.json", "profile.dsse.json", "floor.dsse.json", "bundles")
	if err != nil {
		t.Fatal(err)
	}
	for p := range mfs {
		if cfs.opens[p] != 1 {
			t.Errorf("%s opened %d times, want 1", p, cfs.opens[p])
		}
	}
	graph := "bundles/bobthecorp-soc2/" + GraphFile
	orig := bytes.Clone(mfs[graph].Data)
	mfs[graph].Data = []byte(`{"rules":[]}`) // a write after the read
	mfs["profile.dsse.json"].Data = []byte(`{}`)
	v, err := VerifyInputs(in, mustTime(t, inputsNow))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range in.Bundles { // a caller changing its Inputs afterwards
		for name := range b.Files {
			b.Files[name][0] ^= 0xff
		}
	}
	for _, b := range v.Bundles {
		if g, ok := b.Files[GraphFile]; ok && !bytes.Equal(g, orig) {
			t.Fatalf("verified graph.json is not the bytes read: %q", g)
		}
		if c := b.Files[ControlsFile]; c[0] != '[' {
			t.Fatal("verified controls.json shares memory with the Inputs")
		}
	}
}

func TestReadInputsRejects(t *testing.T) {
	base := fstest.MapFS{
		"keyring.json": {Data: []byte(`{}`)}, "profile.dsse.json": {Data: []byte(`{}`)}, "floor.dsse.json": {Data: []byte(`{}`)},
		"bundles/a/" + ManifestFile: {Data: []byte(`{}`)},
	}
	for name, tc := range map[string]struct {
		path string
		file *fstest.MapFile
		want string
	}{
		"symlink":       {"bundles/a/" + GraphFile, &fstest.MapFile{Mode: fs.ModeSymlink}, "not a regular file"},
		"unknown file":  {"bundles/a/extra.json", &fstest.MapFile{}, "not a bundle file"},
		"loose file":    {"bundles/b.json", &fstest.MapFile{}, "not a bundle directory"},
		"no manifest":   {"bundles/b/" + ControlsFile, &fstest.MapFile{}, ManifestFile + " missing"},
		"too large":     {"bundles/a/" + ControlsFile, &fstest.MapFile{Data: make([]byte, maxFile+1)}, "file too large"},
		"nested dir":    {"bundles/a/sub/" + ControlsFile, &fstest.MapFile{}, "not a regular file"},
		"profile dir":   {"profile.dsse.json", &fstest.MapFile{Mode: fs.ModeDir}, "profile.dsse.json: not a regular file"},
		"keyring large": {"keyring.json", &fstest.MapFile{Data: make([]byte, maxKeyringBytes+1)}, "file too large"},
	} {
		t.Run(name, func(t *testing.T) {
			mfs := fstest.MapFS{}
			for k, v := range base {
				mfs[k] = v
			}
			mfs[tc.path] = tc.file
			_, err := ReadInputs(mfs, "bobthecorp", "keyring.json", "profile.dsse.json", "floor.dsse.json", "bundles")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestParseManifestTexts pins the provider's three manifest decode texts.
func TestParseManifestTexts(t *testing.T) {
	for in, want := range map[string]string{
		`{"format":"x","extra":1}`:    "manifest: unknown member or wrong value type",
		`{"format":1}`:                "manifest: unknown member or wrong value type",
		`{"format":"x"} {}`:           "manifest: trailing data",
		`{"format":"x","format":"y"}`: "manifest: not strict JSON (null, duplicate or non-[a-z0-9_] member name)",
		`{"format":null}`:             "manifest: not strict JSON (null, duplicate or non-[a-z0-9_] member name)",
		`{"extra":1`:                  "manifest: not strict JSON (null, duplicate or non-[a-z0-9_] member name)",
		`{"format":`:                  "manifest: not strict JSON (null, duplicate or non-[a-z0-9_] member name)",
	} {
		if _, err := parseManifest([]byte(in)); err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %q", in, err, want)
		}
	}
}

// TestWrapperOrderVectorsParse: every min_wrapper_version of the provider's
// order vectors (testdata/wrapper_order.json, a byte-identical copy) parses
// here as it does in the provider, so both accept the same signed floors.
func TestWrapperOrderVectorsParse(t *testing.T) {
	raw, err := os.ReadFile("testdata/wrapper_order.json")
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		Check []struct{ V, Min string }     `json:"check"`
		Max   []struct{ A, B, Want string } `json:"max"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	mins := []string{}
	for _, c := range w.Check {
		mins = append(mins, c.Min)
	}
	for _, c := range w.Max {
		mins = append(mins, c.A, c.B, c.Want)
	}
	if len(mins) == 0 {
		t.Fatal("no vectors")
	}
	for _, m := range mins {
		if m != "" && !semverRE.MatchString(m) {
			t.Errorf("min_wrapper_version %q does not parse", m)
		}
	}
	if semverRE.MatchString("dev") {
		t.Error("dev parses as a semantic version")
	}
}
