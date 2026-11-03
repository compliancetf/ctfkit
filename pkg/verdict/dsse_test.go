package verdict

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDSSEVectors runs the provider's DSSE vectors (testdata/dsse, see
// SOURCE.json) against the ported verifier.
func TestDSSEVectors(t *testing.T) {
	for _, name := range []string{"good", "bad-sig", "wrong-purpose", "revoked", "outside-window"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "dsse", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				PayloadType string          `json:"payload_type"`
				Keyring     json.RawMessage `json:"keyring"`
				Revocations json.RawMessage `json:"revocations"`
				Envelope    json.RawMessage `json:"envelope"`
				Want        struct {
					OK         bool
					KID, Error string
				} `json:"want"`
			}
			if err = json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			kr, err := ParseKeyring(v.Keyring)
			if err != nil {
				t.Fatal(err)
			}
			revs := NoRevocations()
			if len(v.Revocations) > 0 {
				if revs, err = ParseRevocations(v.Revocations); err != nil {
					t.Fatal(err)
				}
			}
			got, err := kr.verify(v.Envelope, v.PayloadType, revs)
			switch {
			case v.Want.OK && (err != nil || got.KeyID != v.Want.KID):
				t.Fatalf("want kid %s, got %q, %v", v.Want.KID, got.KeyID, err)
			case !v.Want.OK && (err == nil || !strings.Contains(err.Error(), v.Want.Error)):
				t.Fatalf("want error containing %q, got %v", v.Want.Error, err)
			}
		})
	}
}

func TestMergeRevocations(t *testing.T) {
	a, err := ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":3,"revoked_keys":[{"kid":"sha256:` + strings.Repeat("a", 64) + `","revoked_at":"2026-10-02T00:00:00Z"}],"revoked_bundles":[{"bundle_id":"x","below_version":4}],"revoked_controls":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":2,"revoked_keys":[],"revoked_bundles":[{"bundle_id":"x","below_version":2}],"revoked_controls":[{"id":"C.1","version":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Merge(b, a)
	switch {
	case err != nil:
		t.Fatal(err)
	case m.Epoch() != 3 || !m.KeyRevoked("sha256:"+strings.Repeat("a", 64)) || !m.BundleRevoked("x", 3) || m.BundleRevoked("x", 4) || !m.ControlRevoked("C.1", 1):
		t.Fatalf("merge lost an entry: %+v", m)
	case !(Revocations{}).KeyRevoked("any") || (Revocations{}).valid:
		t.Fatal("the zero set must fail closed")
	}
	if _, err := Merge(Revocations{}, a); err == nil {
		t.Fatal("merge of an invalid set must fail")
	}
}

// TestTrustParseRejects pins the reject paths and error texts of the ported
// keyring, revocations and strict JSON parsers (the provider's texts).
func TestTrustParseRejects(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dsse", "good.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keyring json.RawMessage `json:"keyring"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err = json.Compact(&buf, v.Keyring); err != nil {
		t.Fatal(err)
	}
	kr := buf.String()
	key := kr[strings.Index(kr, `[`)+1 : strings.LastIndex(kr, `]`)]
	sub := func(old, new string) string {
		if !strings.Contains(kr, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(kr, old, new, 1)
	}
	kid := `"sha256:` + strings.Repeat("a", 64) + `"`
	revs := func(body string) string {
		return `{"format":"compliancetf.revocations/v1",` + body + `}`
	}
	for _, c := range []struct{ name, in, want string }{
		{"ed25519", sub(`"ES256"`, `"Ed25519"`), "keyring: key 0: alg Ed25519 is not trusted in this build"},
		{"other alg", sub(`"ES256"`, `"RS256"`), `keyring: key 0: alg "RS256" not allowed`},
		{"duplicate kid", strings.Replace(kr, key, key+","+key, 1), "keyring: duplicate kid sha256:"},
		{"generation on bundle key", sub(`"purpose"`, `"generation":1,"purpose"`), "keyring: key 0: generation is only allowed on floor keys"},
		{"two purposes", sub(`["bundle"]`, `["bundle","profile"]`), "keyring: key 0: purpose must list exactly one entry"},
		{"folded duplicate name", sub(`"compliancetf.keyring/v1",`, `"compliancetf.keyring/v1","Format":"x",`), "keyring: duplicate member name"},
		{"unknown name", sub(`{"format"`, `{"extra":1,"format"`), "keyring: unknown member name"},
		{"null", sub(`"purpose":["bundle"]`, `"purpose":null`), "keyring: null value"},
		{"trailing", kr + "{}", "keyring: trailing data after JSON value"},
		{"too deep", `{"format":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`, "keyring: JSON nested too deep"},
		{"bad format", sub(`"compliancetf.keyring/v1"`, `"x"`), `keyring: format "x", want "compliancetf.keyring/v1"`},
	} {
		if _, err := ParseKeyring([]byte(c.in)); err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	for _, c := range []struct{ name, in, want string }{
		{"epoch 0", revs(`"epoch":0`), "revocations: epoch must be >= 1"},
		{"duplicate kid", revs(`"epoch":1,"revoked_keys":[{"kid":` + kid + `,"revoked_at":"2026-01-01T00:00:00Z"},{"kid":` + kid + `,"revoked_at":"2026-01-02T00:00:00Z"}]`), "revocations: duplicate kid"},
		{"bad revoked_at", revs(`"epoch":1,"revoked_keys":[{"kid":` + kid + `,"revoked_at":"yesterday"}]`), "revocations: revoked_at is not an RFC 3339 time"},
		{"bundle without floor", revs(`"epoch":1,"revoked_bundles":[{"bundle_id":"x","below_version":0}]`), "revocations: bundle entry needs bundle_id and below_version >= 1"},
		{"duplicate control", revs(`"epoch":1,"revoked_controls":[{"id":"C","version":1},{"id":"C","version":1}]`), "revocations: duplicate control"},
	} {
		if _, err := ParseRevocations([]byte(c.in)); err == nil || err.Error() != c.want {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}
