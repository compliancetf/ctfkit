package verdict

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// The baseline vectors were computed by the terraform provider at the
// commit testdata/baseline/SOURCE.json names: its Load accepts
// valid/baseline.json, and its digests are the expected ones.

type baselineExpected struct {
	Now             string    `json:"now"`
	BaselineKey     vectorKey `json:"baseline_key"`
	StatementKey    vectorKey `json:"statement_key"`
	SignedSHA256    string    `json:"signed_sha256"`
	StatementSHA256 []string  `json:"statement_signed_sha256"`
	EntryDigests    []string  `json:"entry_digests"`
}

type controlExpected struct {
	Index  int    `json:"index"`
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

const baselineVector = "testdata/baseline/valid/baseline.json"

// TestBaselineVector: parse, both signature kinds, signed bytes, entry
// digests, and the entry's digests tie to the read digest and control
// manifest vectors.
func TestBaselineVector(t *testing.T) {
	raw, err := os.ReadFile(baselineVector)
	if err != nil {
		t.Fatal(err)
	}
	var want baselineExpected
	readJSON(t, "testdata/baseline/valid/expected.json", &want)
	now, err := time.Parse(time.RFC3339, want.Now)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseBaseline(raw)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignedBytes(raw)
	if err != nil || sha256Hex(signed) != want.SignedSHA256 {
		t.Fatalf("signed bytes %s %v", sha256Hex(signed), err)
	}
	if err := Verify(raw, doc.Signature, publicKeys(t, []vectorKey{want.BaselineKey}), nil, "baseline", now); err != nil {
		t.Fatalf("baseline signature: %v", err)
	}
	if err := Verify(raw, doc.Signature, publicKeys(t, []vectorKey{want.BaselineKey}), nil, "verdict", now); err == nil {
		t.Fatal("baseline signature accepted for use verdict")
	}
	if len(doc.Entries) != len(want.EntryDigests) {
		t.Fatalf("%d entries", len(doc.Entries))
	}
	for i, e := range doc.Entries {
		if d, err := EntryDigest(e); err != nil || d != want.EntryDigests[i] {
			t.Errorf("entry %d digest %s %v", i, d, err)
		}
		st, _ := json.Marshal(e.ApproverStatement)
		stSigned, err := SignedBytes(st)
		if err != nil || sha256Hex(stSigned) != want.StatementSHA256[i] {
			t.Errorf("entry %d statement signed bytes %v", i, err)
		}
		if err := Verify(st, e.ApproverStatement.Signature, publicKeys(t, []vectorKey{want.StatementKey}), nil, "receipt", now); err != nil {
			t.Errorf("entry %d statement: %v", i, err)
		}
	}
	var rd struct {
		Cases []struct{ Name, Digest string } `json:"cases"`
	}
	readJSON(t, "testdata/readdigest/cases.json", &rd)
	var ctl []controlExpected
	readJSON(t, "testdata/controlmanifest/expected.json", &ctl)
	if doc.Entries[0].ReadDigest != rd.Cases[0].Digest || doc.Entries[0].ControlManifestDigest != ctl[0].Digest {
		t.Fatal("entry 0 does not bind the readdigest base case and control 0")
	}
}

// TestParseBaselineRefuses: the strict parse rules of Parse hold for a
// baseline, nested statements included.
func TestParseBaselineRefuses(t *testing.T) {
	raw, err := os.ReadFile(baselineVector)
	if err != nil {
		t.Fatal(err)
	}
	edits := map[string][2]string{
		"wrong format":       {`"format": "compliancetf.baseline/v1"`, `"format": "compliancetf.baseline/v2"`},
		"number":             {`"control_major": "2"`, `"control_major": 2`},
		"null":               {`"ticket": "BOB-123"`, `"ticket": null`},
		"unknown member":     {`"ticket": "BOB-123"`, `"ticket": "BOB-123", "note": "x"`},
		"missing member":     {`"approver": "alice@bobthecorp.example",`, ``},
		"duplicate member":   {`"org_id": "bobthecorp",`, `"org_id": "bobthecorp", "org_id": "bobthecorp",`},
		"case variant":       {`"run_id": "run-obs-1"`, `"Run_ID": "run-obs-1"`},
		"statement member":   {`"role": "baseline_approver",`, `"role": "baseline_approver", "extra": "x",`},
		"identity not flat":  {`"id": "bkt-1"`, `"id": ["bkt-1"]`},
		"signature trailing": {`"alg": "ES256"`, `"alg": "ES256", "x": "y"`},
	}
	for name, e := range edits {
		if !bytes.Contains(raw, []byte(e[0])) {
			t.Fatalf("%s: %q not in the vector", name, e[0])
		}
		if _, err := ParseBaseline(bytes.Replace(raw, []byte(e[0]), []byte(e[1]), 1)); err != ErrInvalidBaseline {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestControlManifestVectors: equal digests for omitted-when-empty members
// and member order, a different one for any changed input.
func TestControlManifestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/controlmanifest/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	var ctls []json.RawMessage
	if err := json.Unmarshal(raw, &ctls); err != nil {
		t.Fatal(err)
	}
	var want []controlExpected
	readJSON(t, "testdata/controlmanifest/expected.json", &want)
	if len(ctls) != len(want) {
		t.Fatalf("%d controls, %d expected", len(ctls), len(want))
	}
	for i, c := range ctls {
		if got, err := ControlManifestDigest(c); err != nil || got != want[i].Digest {
			t.Errorf("control %d (%s): %s %v, want %s", i, want[i].ID, got, err, want[i].Digest)
		}
	}
	if want[0].Digest != want[1].Digest || want[0].Digest != want[2].Digest || want[0].Digest == want[3].Digest {
		t.Fatal("vectors no longer pin normalization and change detection")
	}
}

func TestControlManifestRefuses(t *testing.T) {
	ok := `{"id":"c_1","version":"1.0.0","kind":"resource","resource_type":"aws_s3_bucket","reads":["acl"],"action":"deny","severity":"high","message":"m"}`
	if _, err := ControlManifestDigest([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"null":             strings.Replace(ok, `"m"`, `null`, 1),
		"nested null":      strings.Replace(ok, `["acl"]`, `[null]`, 1),
		"duplicate":        strings.Replace(ok, `"message":"m"`, `"message":"m","message":"m"`, 1),
		"upper case":       strings.Replace(ok, `"message"`, `"Message"`, 1),
		"unknown member":   strings.Replace(ok, `"message":"m"`, `"message":"m","predicate":"x"`, 1),
		"nested bad key":   strings.Replace(ok, `"message":"m"`, `"message":"m","tool_refs":{"Checkov":["x"]}`, 1),
		"number":           strings.Replace(ok, `"m"`, `1`, 1),
		"trailing data":    ok + `{}`,
		"array":            `[` + ok + `]`,
		"invalid utf8":     strings.Replace(ok, `"m"`, "\"\xff\"", 1),
		"unknown in graph": strings.Replace(ok, `"message":"m"`, `"message":"m","graph":{"rule":"companion_present","x":"y"}`, 1),
	} {
		if d, err := ControlManifestDigest([]byte(doc)); err == nil {
			t.Errorf("%s: digested %s", name, d)
		}
	}
}

// TestBaselineSource: the provider-computed files are the bytes SOURCE.json
// records, so an edit by hand shows up.
func TestBaselineSource(t *testing.T) {
	var src struct {
		Files []struct{ Path, SHA256 string } `json:"files"`
	}
	readJSON(t, "testdata/baseline/SOURCE.json", &src)
	for _, f := range src.Files {
		b, err := os.ReadFile(strings.TrimPrefix(f.Path, "pkg/verdict/"))
		if err != nil || sha256Hex(b) != f.SHA256 {
			t.Errorf("%s: sha256 differs from SOURCE.json (%v)", f.Path, err)
		}
	}
	if len(src.Files) != 6 {
		t.Fatalf("%d files", len(src.Files))
	}
}
