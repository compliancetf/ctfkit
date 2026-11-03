package verdict_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/readdigest"
	"github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
)

// The baseline identity goldens (spec B4): each base observation is
// the source of one baseline entry; each case is an update matched against
// its base's entry. expected.json was computed by the terraform provider
// (internal/baseline Load, ReadDigest, Grandfathered; internal/verdict Key)
// at the commit testdata/baselineid/SOURCE.json names. ctfkit recomputes
// every value from cases.json and must agree, and an entry's key tuple must
// decide grandfathering exactly as the provider did.

const baselineIDDir = "testdata/baselineid/"

type baselineIDObservation struct {
	Name         string                `json:"name"`
	Base         string                `json:"base"`
	Want         string                `json:"want"`
	OrgID        string                `json:"org_id"`
	Workspace    string                `json:"workspace"`
	Scope        verdict.BaselineScope `json:"scope"`
	Control      json.RawMessage       `json:"control"`
	Change       json.RawMessage       `json:"change"`
	RunSecretHex string                `json:"run_secret_hex"`
}

type baselineIDResult struct {
	Name                  string            `json:"name"`
	IdentityKind          string            `json:"identity_kind"`
	Identity              map[string]string `json:"identity"`
	InstanceKey           string            `json:"instance_key"`
	ReadDigest            string            `json:"read_digest"`
	PlannedReadDigest     string            `json:"planned_read_digest"`
	ControlManifestDigest string            `json:"control_manifest_digest"`
	ControlMajor          string            `json:"control_major"`
	Grandfathered         *bool             `json:"grandfathered"`
}

// baselineIDKey is what ctfkit computes for an observation: the entry key
// tuple, the read digests and the planned id (kind id must keep it).
type baselineIDKey struct {
	org, workspace, typ, control string
	scope                        verdict.BaselineScope
	res                          baselineIDResult
	plannedID                    any
}

func TestBaselineIDGoldens(t *testing.T) {
	var in struct {
		BaselineKeyHex string                  `json:"baseline_key_hex"`
		Bases          []baselineIDObservation `json:"bases"`
		Cases          []baselineIDObservation `json:"cases"`
	}
	bidReadJSON(t, baselineIDDir+"cases.json", &in)
	var want struct{ Bases, Cases []baselineIDResult }
	bidReadJSON(t, baselineIDDir+"expected.json", &want)
	schemaRaw, err := os.ReadFile(baselineIDDir + "schema.json")
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := tfjson.ParseSchemas(schemaRaw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := readdigest.ParseKey([]byte(in.BaselineKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Bases) != len(want.Bases) || len(in.Cases) != len(want.Cases) {
		t.Fatal("cases.json and expected.json differ in length")
	}
	bases := map[string]baselineIDKey{}
	for i, b := range in.Bases {
		k, ok := baselineIDCompute(t, key, schemas, b)
		if !ok || !baselineIDEqual(k.res, want.Bases[i], true) {
			t.Fatalf("base %s: ctfkit %+v, provider %+v", b.Name, k.res, want.Bases[i])
		}
		bases[b.Name] = k
	}
	seen := map[string]bool{}
	for i, c := range in.Cases {
		t.Run(c.Name, func(t *testing.T) {
			exp := want.Cases[i]
			k, ok := baselineIDCompute(t, key, schemas, c)
			switch {
			case exp.Name != c.Name || exp.Grandfathered == nil:
				t.Fatalf("expected.json entry %d is %q", i, exp.Name)
			case ok != (c.Want != "no_entry") || ok != (exp.IdentityKind != ""):
				t.Fatalf("entry identity: ctfkit %v, provider kind %q, want %s", ok, exp.IdentityKind, c.Want)
			case !baselineIDEqual(k.res, exp, ok):
				t.Fatalf("ctfkit %+v\nprovider %+v", k.res, exp)
			}
			base, known := bases[c.Base]
			if !known {
				t.Fatalf("unknown base %q", c.Base)
			}
			got := ok && baselineIDMatches(base, k)
			if got != *exp.Grandfathered || got != (c.Want == "stable") {
				t.Fatalf("grandfathered: ctfkit %v, provider %v, want %s", got, *exp.Grandfathered, c.Want)
			}
			seen[c.Want] = true
		})
	}
	if len(seen) != 3 {
		t.Fatalf("the goldens no longer cover stable, changed and no_entry: %v", seen)
	}
	// A new run secret changes the instance key and nothing the entry binds.
	byName := map[string]baselineIDResult{}
	for _, r := range want.Cases {
		byName[r.Name] = r
	}
	for _, f := range []string{"s3", "kms"} {
		a, b := byName[f+"-match"], byName[f+"-new-run-secret"]
		if a.InstanceKey == "" || a.InstanceKey == b.InstanceKey || a.ReadDigest != b.ReadDigest || !maps.Equal(a.Identity, b.Identity) {
			t.Errorf("%s: a new run secret must change the instance key only", f)
		}
	}
}

// baselineIDCompute derives an observation's values with ctfkit's own code:
// the tfjson adapter (identity precedence, instance key), EntryIdentity,
// readdigest and ControlManifestDigest. ok is false when no entry can be
// written; then only the control and read values are set.
func baselineIDCompute(t *testing.T, key [32]byte, schemas *tfjson.Schemas, o baselineIDObservation) (baselineIDKey, bool) {
	t.Helper()
	k := baselineIDKey{org: o.OrgID, workspace: o.Workspace, scope: o.Scope, res: baselineIDResult{Name: o.Name}}
	var ctl struct {
		ID, Version string
		Reads       []string
	}
	var err error
	if err = json.Unmarshal(o.Control, &ctl); err != nil {
		t.Fatal(err)
	}
	k.control = ctl.ID
	k.res.ControlMajor, _, _ = strings.Cut(ctl.Version, ".")
	if k.res.ControlManifestDigest, err = verdict.ControlManifestDigest(o.Control); err != nil {
		t.Fatal(err)
	}
	var ch struct {
		Type   string
		Change struct{ Before, After map[string]any }
	}
	dec := json.NewDecoder(bytes.NewReader(o.Change))
	dec.UseNumber()
	if err = dec.Decode(&ch); err != nil {
		t.Fatal(err)
	}
	k.typ, k.plannedID = ch.Type, ch.Change.After["id"]
	plan := []byte(`{"format_version":"1.2","resource_changes":[` + string(o.Change) + `]}`)
	secret, err := instancekey.ParseSecret([]byte(o.RunSecretHex))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, err := instancekey.Keys(secret)
	if err != nil {
		t.Fatal(err)
	}
	insts, err := tfjson.Instances(leaf, plan, schemas)
	if err != nil || len(insts) != 1 {
		t.Fatalf("%s: %d instances, %v", o.Name, len(insts), err)
	}
	if insts[0].Err != nil {
		return k, false
	}
	ki := insts[0].Keys[0]
	k.res.IdentityKind, k.res.InstanceKey = ki.PriorIdentityKind, ki.Key
	if k.res.Identity, err = verdict.EntryIdentity(ki.PriorIdentityKind, ki.Prior); err != nil {
		return k, false
	}
	if k.res.ReadDigest, err = readdigest.Digest(key, ctl.Reads, ki.Schema, ch.Change.Before); err != nil {
		t.Fatal(err)
	}
	if k.res.PlannedReadDigest, err = readdigest.Digest(key, ctl.Reads, ki.Schema, ch.Change.After); err != nil {
		t.Fatal(err)
	}
	return k, true
}

// baselineIDEqual compares ctfkit's values with the provider's; without an
// entry identity only the control values are comparable.
func baselineIDEqual(got, want baselineIDResult, entry bool) bool {
	same := got.Name == want.Name && got.ControlManifestDigest == want.ControlManifestDigest && got.ControlMajor == want.ControlMajor
	if !entry {
		return same && want.Identity == nil && want.InstanceKey == ""
	}
	return same && got.IdentityKind == want.IdentityKind && maps.Equal(got.Identity, want.Identity) &&
		got.InstanceKey == want.InstanceKey && got.ReadDigest == want.ReadDigest && got.PlannedReadDigest == want.PlannedReadDigest
}

// baselineIDMatches is the spec's key match of an entry written from base
// (grandfather requirements 3 and 4): org, workspace, scope, type, identity,
// control, control major and control manifest digest equal; the prior read
// digest equals the entry's and the planned one the prior; kind id keeps
// its id in the planned state. Listing, refresh, expiry, revocation and
// address are fixed in the goldens.
func baselineIDMatches(base, c baselineIDKey) bool {
	e, r := base.res, c.res
	return base.org == c.org && base.workspace == c.workspace && base.scope == c.scope && base.typ == c.typ &&
		e.IdentityKind == r.IdentityKind && maps.Equal(e.Identity, r.Identity) && base.control == c.control &&
		e.ControlMajor == r.ControlMajor && e.ControlManifestDigest == r.ControlManifestDigest &&
		e.ReadDigest == r.ReadDigest && r.PlannedReadDigest == r.ReadDigest &&
		(r.IdentityKind != "id" || c.plannedID == r.Identity["id"])
}

// TestBaselineIDSource: the provider-computed and hand-written files are
// the bytes SOURCE.json records.
func TestBaselineIDSource(t *testing.T) {
	var src struct {
		Files []struct{ Path, SHA256 string } `json:"files"`
	}
	bidReadJSON(t, baselineIDDir+"SOURCE.json", &src)
	if len(src.Files) != 4 {
		t.Fatalf("%d files", len(src.Files))
	}
	for _, f := range src.Files {
		b, err := os.ReadFile(strings.TrimPrefix(f.Path, "pkg/verdict/"))
		if err != nil || bidSHA256(b) != f.SHA256 {
			t.Errorf("%s: sha256 differs from SOURCE.json (%v)", f.Path, err)
		}
	}
}

func TestBaselineIDEntryIdentity(t *testing.T) {
	ok := []struct {
		kind  string
		prior any
		want  map[string]string
	}{
		{"identity", map[string]any{"bucket": "b", "region": nil}, map[string]string{"bucket": "b"}},
		{"identity", map[string]any{"bucket": ""}, map[string]string{"bucket": ""}},
		{"id", map[string]any{"id": "i-1"}, map[string]string{"id": "i-1"}},
	}
	for _, c := range ok {
		if got, err := verdict.EntryIdentity(c.kind, c.prior); err != nil || !maps.Equal(got, c.want) {
			t.Errorf("%s %v: %v %v", c.kind, c.prior, got, err)
		}
	}
	for name, c := range map[string]struct {
		kind  string
		prior any
	}{
		"kind none":           {"none", nil},
		"unknown kind":        {"other", map[string]any{"id": "x"}},
		"all null":            {"identity", map[string]any{"bucket": nil}},
		"empty object":        {"identity", map[string]any{}},
		"number member":       {"identity", map[string]any{"account_id": json.Number("1")}},
		"nested member":       {"identity", map[string]any{"a": map[string]any{"b": "c"}}},
		"empty id":            {"id", map[string]any{"id": ""}},
		"null id":             {"id", map[string]any{"id": nil}},
		"id with other names": {"id", map[string]any{"arn": "x"}},
		"not an object":       {"id", "x"},
	} {
		if got, err := verdict.EntryIdentity(c.kind, c.prior); err == nil {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func bidReadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func bidSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
