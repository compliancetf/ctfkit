package verdict

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const bgDir = "testdata/breakglass"

// TestRequestDigestVectors: request_digest.json was written by running the
// provider's breakglass.RequestDigest (see SOURCE.json); every case must match.
func TestRequestDigestVectors(t *testing.T) {
	var vs []struct {
		Name          string       `json:"name"`
		Input         RequestScope `json:"input"`
		RequestDigest string       `json:"request_digest"`
	}
	readJSON(t, filepath.Join(bgDir, "request_digest.json"), &vs)
	if len(vs) < 6 {
		t.Fatalf("only %d request_digest vectors", len(vs))
	}
	for _, v := range vs {
		in := slices.Clone(v.Input.Controls)
		got, err := RequestDigest(v.Input)
		if err != nil || got != v.RequestDigest {
			t.Errorf("%s: RequestDigest = %s, %v, want %s", v.Name, got, err, v.RequestDigest)
		}
		if !slices.Equal(in, v.Input.Controls) {
			t.Errorf("%s: RequestDigest reordered its input", v.Name)
		}
		slices.Reverse(v.Input.Controls)
		slices.Reverse(v.Input.InstanceKeys)
		if again, _ := RequestDigest(v.Input); again != got { //nolint:errcheck // compared below
			t.Errorf("%s: input order changed the digest", v.Name)
		}
	}
	// A nil list is null and an empty one [], as the provider marshals them.
	empty, _ := RequestDigest(RequestScope{Controls: []string{}, InstanceKeys: []string{}}) //nolint:errcheck // compared
	null, _ := RequestDigest(RequestScope{})                                                //nolint:errcheck // compared
	if empty == null {
		t.Error("nil and empty lists digest alike")
	}
}

// TestBreakGlassSamples checks the signed samples: both parse, the override,
// each approval statement and the receipt verify with a receipt key, and the
// receipt binds the override's digest and request scope.
// Regenerate with: go test ./pkg/verdict -run TestBreakGlassSamples -update,
// then re-record SOURCE.json with the provider: the new key changes the
// receipt digest, and the test fails until that is done.
func TestBreakGlassSamples(t *testing.T) {
	if *update {
		generateBreakGlass(t)
	}
	ovRaw, rcRaw := readFile(t, "override.json"), readFile(t, "consume-receipt.json")
	var vks []vectorKey
	readJSON(t, filepath.Join(bgDir, "keys.json"), &vks)
	keys := publicKeys(t, vks)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	o, err := ParseOverride(ovRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(ovRaw, o.Signature, keys, nil, UseReceipt, now); err != nil {
		t.Fatalf("override: %v", err)
	}
	for i, a := range o.Approvals {
		st, serr := ApprovalStatement(o, i)
		if serr != nil {
			t.Fatal(serr)
		}
		if serr = Verify(st, a.Signature, keys, nil, UseReceipt, now); serr != nil {
			t.Fatalf("approval %d: %v", i, serr)
		}
	}
	r, err := ParseReceipt(rcRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(rcRaw, r.Signature, keys, nil, UseReceipt, now); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if Verify(rcRaw, r.Signature, keys, nil, "verdict", now) == nil {
		t.Fatal("receipt verified with use verdict")
	}
	var src struct {
		ReceiptDigest string `json:"consume_receipt_digest"`
	}
	readJSON(t, filepath.Join(bgDir, "SOURCE.json"), &src)
	rcDigest, err := Digest(rcRaw)
	if err != nil || rcDigest != src.ReceiptDigest {
		t.Fatalf("receipt Digest = %s, %v, want the provider's %s (re-record SOURCE.json after -update)", rcDigest, err, src.ReceiptDigest)
	}
	ovDigest, err := Digest(ovRaw)
	if err != nil || r.OverrideDigest != ovDigest {
		t.Fatalf("override_digest = %s, want %s (%v)", r.OverrideDigest, ovDigest, err)
	}
	want, err := RequestDigest(o.Scope())
	if err != nil || r.RequestDigest != want {
		t.Fatalf("request_digest = %s, want %s (%v)", r.RequestDigest, want, err)
	}
	d := &Document{OrgID: o.OrgID, Workspace: o.Workspace, Environment: o.Environment, PlanDigest: o.PlanDigest,
		ContentDigest: o.ContentDigest, FloorEpoch: o.FloorEpoch}
	if got, _ := RequestDigest(r.Scope(d)); got != want { //nolint:errcheck // compared
		t.Fatalf("receipt scope digest = %s, want %s", got, want)
	}
}

// TestApprovalStatement pins the members an approval signature covers.
func TestApprovalStatement(t *testing.T) {
	o, err := ParseOverride(readFile(t, "override.json"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := ApprovalStatement(o, 1)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"approver":"carol@bobthecorp.example","content_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333",` +
		`"controls":["CTF.RDS.1","CTF.S3.2"],"environment":"production","expires_at":"2026-10-19T20:00:00Z","floor_epoch":"3",` +
		`"instance_keys":["sha256:6666666666666666666666666666666666666666666666666666666666666666","sha256:8888888888888888888888888888888888888888888888888888888888888888"],` +
		`"org_id":"bobthecorp","override_id":"ovr-01","plan_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444",` +
		`"role":"break_glass_approver","workspace":"prod"}`
	if string(st) != want {
		t.Fatalf("statement:\n%s\nwant\n%s", st, want)
	}
	if _, err := ApprovalStatement(o, 2); err == nil {
		t.Fatal("approval index 2 accepted")
	}
}

// TestParseBreakGlassRefuses: each edit of a valid sample is refused.
func TestParseBreakGlassRefuses(t *testing.T) {
	ov, rc := string(readFile(t, "override.json")), string(readFile(t, "consume-receipt.json"))
	ovEdits := map[string][2]string{
		"wrong format":        {`"compliancetf.override/v1"`, `"compliancetf.override/v2"`},
		"unknown member":      {`"ticket":`, `"note": "x", "ticket":`},
		"case variant member": {`"ticket":`, `"Ticket":`},
		"number":              {`"floor_epoch": "3"`, `"floor_epoch": 3`},
		"empty requester":     {`"requester": "alice@bobthecorp.example"`, `"requester": ""`},
		"bad override id":     {`"override_id": "ovr-01"`, `"override_id": "-ovr"`},
		"bad digest":          {`"plan_digest": "sha256:4444`, `"plan_digest": "sha256:444G`},
		"duplicate control":   {`"CTF.RDS.1"` + "\n", `"CTF.S3.2"` + "\n"},
		"empty controls":      {"\"controls\": [\n  \"CTF.S3.2\",\n  \"CTF.RDS.1\"\n ]", `"controls": []`},
		"ttl over 24h":        {`"issued_at": "2026-10-19T08:00:00Z"`, `"issued_at": "2026-10-18T19:59:59Z"`},
		"not utc":             {`"issued_at": "2026-10-19T08:00:00Z"`, `"issued_at": "2026-10-19T09:00:00+01:00"`},
		"approver requester":  {`"approver": "bob@bobthecorp.example"`, `"approver": "alice@bobthecorp.example"`},
		"same approver":       {`"approver": "bob@bobthecorp.example"`, `"approver": "carol@bobthecorp.example"`},
		"approval outlives":   {`"expires_at": "2026-10-19T19:00:00Z"`, `"expires_at": "2026-10-19T20:00:01Z"`},
		"empty role":          {`"role": "break_glass_approver"`, `"role": ""`},
		"empty predecessor":   {`"reason":`, `"predecessor_receipt_digest": "", "reason":`},
		"approval sig alg":    {`"alg": "ES256"`, `"alg": "RS256"`},
		"approval sig kid":    {`"kid": "sha256:cdd9`, `"kid": "sha256:CDD9`},
		"signature value":     {"\n  \"alg\": \"ES256\",\n  \"value\": \"MEY", "\n  \"alg\": \"ES256\",\n  \"value\": \"ME=Y"},
	}
	for name, e := range ovEdits {
		if !strings.Contains(ov, e[0]) {
			t.Fatalf("%s: %q not in override.json", name, e[0])
		}
		if _, err := ParseOverride([]byte(strings.Replace(ov, e[0], e[1], 1))); err == nil {
			t.Errorf("override %s accepted", name)
		}
	}
	rcEdits := map[string][2]string{
		"wrong format":      {`"compliancetf.consume-receipt/v1"`, `"compliancetf.consume-receipt/v2"`},
		"unknown member":    {`"run_id":`, `"note": "x", "run_id":`},
		"null predecessor":  {`"run_id":`, `"predecessor_receipt_digest": null, "run_id":`},
		"empty run":         {`"run_id": "run-1"`, `"run_id": ""`},
		"duplicate key":     {`"sha256:6666666666666666666666666666666666666666666666666666666666666666"` + "\n", `"sha256:8888888888888888888888888888888888888888888888888888888888888888"` + "\n"},
		"bad control token": {`"CTF.RDS.1"`, `"CTF RDS 1"`},
		"not utc":           {`"consumed_at": "2026-10-19T09:30:00Z"`, `"consumed_at": "2026-10-19T09:30:00"`},
		"one digit hour":    {`"consumed_at": "2026-10-19T09:30:00Z"`, `"consumed_at": "2026-10-19T9:30:00Z"`},
		"comma fraction":    {`"consumed_at": "2026-10-19T09:30:00Z"`, `"consumed_at": "2026-10-19T09:30:00,5Z"`},
		"empty predecessor": {`"run_id":`, `"predecessor_receipt_digest": "", "run_id":`},
		"signature kid":     {`"kid": "sha256:cdd9`, `"kid": "x`},
		"signature alg":     {`"alg": "ES256"`, `"alg": "Ed25519"`},
		"bad sig value":     {`"value": "MEUC`, `"value": "ME UC`},
	}
	for name, e := range rcEdits {
		if !strings.Contains(rc, e[0]) {
			t.Fatalf("%s: %q not in consume-receipt.json", name, e[0])
		}
		if _, err := ParseReceipt([]byte(strings.Replace(rc, e[0], e[1], 1))); err == nil {
			t.Errorf("receipt %s accepted", name)
		}
	}
	pred := `"predecessor_receipt_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", `
	if _, err := ParseOverride([]byte(strings.Replace(ov, `"reason":`, pred+`"reason":`, 1))); err != nil {
		t.Errorf("override with a predecessor refused: %v", err)
	}
	if _, err := ParseReceipt([]byte(strings.Replace(rc, `"run_id":`, pred+`"run_id":`, 1))); err != nil {
		t.Errorf("receipt with a predecessor refused: %v", err)
	}
	if _, err := ParseReceipt([]byte(ov)); err == nil {
		t.Error("an override parsed as a receipt")
	}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(bgDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const sampleOverride = `{
 "format": "compliancetf.override/v1", "override_id": "ovr-01", "org_id": "bobthecorp", "workspace": "prod",
 "environment": "production", "requester": "alice@bobthecorp.example",
 "plan_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
 "content_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
 "floor_epoch": "3",
 "issued_at": "2026-10-19T08:00:00Z",
 "expires_at": "2026-10-19T20:00:00Z",
 "instance_keys": ["sha256:8888888888888888888888888888888888888888888888888888888888888888", "sha256:6666666666666666666666666666666666666666666666666666666666666666"],
 "controls": ["CTF.S3.2", "CTF.RDS.1"],
 "approvals": [
  {"approver": "bob@bobthecorp.example", "role": "break_glass_approver", "approved_at": "2026-10-19T08:10:00Z", "expires_at": "2026-10-19T19:00:00Z"},
  {"approver": "carol@bobthecorp.example", "role": "break_glass_approver", "approved_at": "2026-10-19T08:20:00Z", "expires_at": "2026-10-19T20:00:00Z"}
 ],
 "reason": "restore service after incident (ü)", "ticket": "INC-1001"
}`

// generateBreakGlass rewrites the signed samples from a fresh in-memory
// receipt key; no private key is written.
func generateBreakGlass(t *testing.T) {
	t.Helper()
	priv, key := keyFor(t, elliptic.P256(), UseReceipt)
	sign := func(doc []byte) Signature {
		signed, err := SignedBytes(doc)
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(signed)
		der, err := ecdsa.SignASN1(rand.Reader, priv, d[:])
		if err != nil {
			t.Fatal(err)
		}
		return Signature{Kid: key.Kid, Alg: AlgES256, Value: base64.RawURLEncoding.EncodeToString(der)}
	}
	var o Override
	if err := json.Unmarshal([]byte(sampleOverride), &o); err != nil {
		t.Fatal(err)
	}
	o.Format = OverrideFormat
	for i := range o.Approvals {
		st, err := ApprovalStatement(&o, i)
		if err != nil {
			t.Fatal(err)
		}
		o.Approvals[i].Signature = sign(st)
	}
	o.Signature = Signature{}
	unsigned := marshalSample(t, &o)
	o.Signature = sign(unsigned)
	ovRaw := marshalSample(t, &o)

	ovDigest, err := Digest(ovRaw)
	if err != nil {
		t.Fatal(err)
	}
	reqDigest, err := RequestDigest(o.Scope())
	if err != nil {
		t.Fatal(err)
	}
	r := Receipt{Format: ReceiptFormat, OverrideID: o.OverrideID, OverrideDigest: ovDigest, OrgID: o.OrgID, RunID: "run-1",
		RequestDigest: reqDigest, Controls: o.Controls, InstanceKeys: o.InstanceKeys, PlanDigest: o.PlanDigest,
		ConsumedAt: "2026-10-19T09:30:00Z", ExpiresAt: "2026-10-19T20:00:00Z"}
	r.Signature = sign(marshalSample(t, &r))
	writeFile(t, filepath.Join(bgDir, "override.json"), ovRaw)
	writeFile(t, filepath.Join(bgDir, "consume-receipt.json"), marshalSample(t, &r))
	writeJSON(t, filepath.Join(bgDir, "keys.json"), []vectorKey{key})
}

func marshalSample(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}
