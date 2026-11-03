package verdict

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const contentDir = "testdata/contentdigest"

// contentBundle is a verified bundle holding the files of a
// testdata/contentdigest case (absent files stay absent).
func contentBundle(t *testing.T, id, dir string, names ...string) VerifiedBundle {
	t.Helper()
	if names == nil {
		names = []string{ControlsFile, GraphFile, IAMActionsFile}
	}
	b := VerifiedBundle{Manifest: &Manifest{BundleID: id}, Files: map[string][]byte{}}
	for _, n := range names {
		body, err := os.ReadFile(filepath.Join(contentDir, dir, n))
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		b.Files[n] = body
	}
	return b
}

func mustContentDigest(t *testing.T, bs ...VerifiedBundle) string {
	t.Helper()
	d, err := ContentDigest(&Verified{Bundles: bs})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestContentDigestVectors: the digests equal the provider's for the same
// bytes (testdata/contentdigest/SOURCE.json), whatever the bundle order.
func TestContentDigestVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(contentDir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{
		"base":              mustContentDigest(t, contentBundle(t, "soc2-aws", "base")),
		"swap-graph":        mustContentDigest(t, contentBundle(t, "soc2-aws", "swap-graph")),
		"coverable-changed": mustContentDigest(t, contentBundle(t, "soc2-aws", "coverable-changed")),
		"controls-only":     mustContentDigest(t, contentBundle(t, "soc2-aws", "base", ControlsFile)),
		"two-bundles":       mustContentDigest(t, contentBundle(t, "soc2-aws", "base"), contentBundle(t, "soc2-aws-graph", "swap-graph")),
	}
	if len(got) != len(want) {
		t.Fatalf("expected.json has %d cases, test has %d", len(want), len(got))
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: %s, want %s", name, got[name], w)
		}
	}
	if d := mustContentDigest(t, contentBundle(t, "soc2-aws-graph", "swap-graph"), contentBundle(t, "soc2-aws", "base")); d != want["two-bundles"] {
		t.Errorf("bundle order changed the digest: %s", d)
	}
}

// TestContentDigestPreimage pins the preimage: JCS of {bundles, coverable},
// "" for an absent file, every control id listed, [] without kinds.
func TestContentDigestPreimage(t *testing.T) {
	// controls is already canonical, so its DigestJSON is sha256 of these bytes.
	controls := []byte(`[{"exemption_coverable":["baseline","grant"],"id":"b_ctl"},{"id":"a_ctl"},{"exemption_coverable":["baseline","grant"],"id":"b_ctl"}]`)
	graph := []byte(`{ "z": 1, "a": [true, null, 1.0] }`)
	b := VerifiedBundle{Manifest: &Manifest{BundleID: "bobthecorp-x"}, Files: map[string][]byte{ControlsFile: controls, GraphFile: graph}}
	sum := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return "sha256:" + hex.EncodeToString(h[:])
	}
	pre := `{"bundles":[{"bundle_id":"bobthecorp-x","controls":"` + sum(string(controls)) + `","graph":"` + sum(`{"a":[true,null,1],"z":1}`) +
		`","iam_actions":""}],"coverable":{"a_ctl":[],"b_ctl":["baseline","grant"]}}`
	if got := mustContentDigest(t, b); got != sum(pre) {
		t.Fatalf("preimage: %s, want %s", got, sum(pre))
	}
	if got := mustContentDigest(t); got != sum(`{"bundles":[],"coverable":{}}`) {
		t.Fatalf("no bundles: %s", got)
	}
}

// TestContentDigestBinds: a graph.json swap with controls unchanged, or a
// coverable change, moves the digest, and a verdict, candidate or approval
// bound to the old one is refused; nothing outside the bundle content moves it.
func TestContentDigestBinds(t *testing.T) {
	base := &Verified{Bundles: []VerifiedBundle{contentBundle(t, "soc2-aws", "base")}}
	old := mustContentDigest(t, base.Bundles...)
	for _, dir := range []string{"swap-graph", "coverable-changed"} {
		now := &Verified{Bundles: []VerifiedBundle{contentBundle(t, "soc2-aws", dir)}}
		bound := map[string]string{
			"verdict":   (&Document{ContentDigest: old}).ContentDigest,
			"candidate": old, // candidate.json content_digest
			"approval":  old, // break-glass approval content_digest
		}
		for what, d := range bound {
			if err := CheckContentDigest(now, d); !errors.Is(err, ErrContentDigest) {
				t.Errorf("%s: %s bound to the old digest: %v, want ErrContentDigest", dir, what, err)
			}
		}
		if err := CheckContentDigest(now, mustContentDigest(t, now.Bundles...)); err != nil {
			t.Errorf("%s: current digest refused: %v", dir, err)
		}
	}
	if err := CheckContentDigest(base, ""); !errors.Is(err, ErrContentDigest) {
		t.Errorf("empty binding: %v", err)
	}

	// Profile coverable lists, profile and bundle set digests, floor,
	// revocations, warnings and manifest signing data are not inputs; memo,
	// grants, sidecars, approvals, verdicts and baselines are not parameters.
	other := *base
	other.Profile = &Profile{Exceptions: json.RawMessage(`{"coverable":{"rds_bobthecorp_storage_encrypted":["grant"]}}`)}
	other.ProfileDigest, other.BundleDigest = "sha256:1", "sha256:2"
	other.Floor = &Floor{Epoch: 9}
	other.Warnings = []string{"grace"}
	other.Bundles = []VerifiedBundle{base.Bundles[0]}
	other.Bundles[0].Digest, other.Bundles[0].KeyID = "sha256:3", "kid"
	if d := mustContentDigest(t, other.Bundles...); d != old {
		t.Fatalf("a non-content input moved the digest: %s", d)
	}
	if err := CheckContentDigest(&other, old); err != nil {
		t.Fatal(err)
	}
}

// TestContentDigestRejects: input the provider refuses to load is an error,
// never a digest.
func TestContentDigestRejects(t *testing.T) {
	good := []byte(`[{"id":"a","exemption_coverable":["grant"]}]`)
	one := func(name string, body []byte) []VerifiedBundle {
		files := map[string][]byte{ControlsFile: good}
		files[name] = body
		return []VerifiedBundle{{Manifest: &Manifest{BundleID: "b"}, Files: files}}
	}
	cases := map[string][]VerifiedBundle{
		"empty graph":          one(GraphFile, []byte(``)),
		"duplicate member":     one(GraphFile, []byte(`{"a":1,"a":2}`)),
		"invalid utf-8":        one(GraphFile, []byte("\"\xff\"")),
		"unpaired surrogate":   one(GraphFile, []byte(`"\ud800"`)),
		"noncharacter":         one(IAMActionsFile, []byte("{\"\ufdd0\":1}")),
		"number out of range":  one(GraphFile, []byte(`1e400`)),
		"trailing data":        one(GraphFile, []byte(`{"a":1}x`)),
		"two documents":        one(GraphFile, []byte(`[1] [2]`)),
		"controls not array":   one(ControlsFile, []byte(`{"controls":[]}`)),
		"controls null":        one(ControlsFile, []byte(`null`)),
		"controls empty":       one(ControlsFile, []byte(`[]`)),
		"no manifest":          {{Files: map[string][]byte{ControlsFile: good}}},
		"control without id":   one(ControlsFile, []byte(`[{"exemption_coverable":[]}]`)),
		"unknown kind":         one(ControlsFile, []byte(`[{"id":"a","exemption_coverable":["waiver"]}]`)),
		"unsorted kinds":       one(ControlsFile, []byte(`[{"id":"a","exemption_coverable":["grant","baseline"]}]`)),
		"repeated kind":        one(ControlsFile, []byte(`[{"id":"a","exemption_coverable":["grant","grant"]}]`)),
		"conflict in a bundle": one(ControlsFile, []byte(`[{"id":"a","exemption_coverable":["grant"]},{"id":"a"}]`)),
		"conflict across bundles": {
			{Manifest: &Manifest{BundleID: "b1"}, Files: map[string][]byte{ControlsFile: good}},
			{Manifest: &Manifest{BundleID: "b2"}, Files: map[string][]byte{ControlsFile: []byte(`[{"id":"a","exemption_coverable":["baseline"]}]`)}},
		},
		"duplicate bundle_id": {
			{Manifest: &Manifest{BundleID: "b"}, Files: map[string][]byte{ControlsFile: good}},
			{Manifest: &Manifest{BundleID: "b"}, Files: map[string][]byte{ControlsFile: good}},
		},
	}
	for name, bs := range cases {
		if d, err := ContentDigest(&Verified{Bundles: bs}); err == nil {
			t.Errorf("%s: digest %s, want an error", name, d)
		}
	}
	if _, err := ContentDigest(nil); err == nil {
		t.Error("nil inputs: want an error")
	}
	if err := CheckContentDigest(nil, "sha256:x"); err == nil || errors.Is(err, ErrContentDigest) {
		t.Errorf("nil inputs: %v, want a non-mismatch error", err)
	}
}
