package verdict

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// baseDoc is the unsigned verdict every signature vector starts from
// (bobthecorp only). It covers each action shape, a deposed object, a
// non-ASCII address and an escaped character, so JCS ordering and escaping
// are part of what the vectors pin.
const baseDoc = `{
 "format": "compliancetf.verdict/v1", "org_id": "bobthecorp", "workspace": "prod", "environment": "production", "run_id": "run-1",
 "caller": {"account_id": "111122223333", "role_arn": "arn:aws:iam::111122223333:role/bobthecorp-ci", "region": "us-east-1"},
 "plan_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
 "provenance": {"tool": "ctfkit gate plan", "refresh": "true", "targeted": "false", "workspace": "prod"},
 "plan_format_version": "1.2",
 "profile_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
 "bundle_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
 "content_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
 "floor_epoch": "3", "provider_versions": {"compliancetf/aws": "2.0.0", "hashicorp/aws": "6.20.0"},
 "terraform_version": "1.14.0", "nonce": "AAECAwQFBgcICQoLDA0ODw",
 "issued_at": "2026-10-19T10:00:00Z", "expires_at": "2026-10-19T22:00:00Z",
 "instance_key_check": "5555555555555555555555555555555555555555555555555555555555555555",
 "instances": [
  {"address": "aws_s3_bucket.logs[\"eu-ü\\t\"]", "type": "aws_s3_bucket", "action": "create",
   "instance_key": "sha256:6666666666666666666666666666666666666666666666666666666666666666", "prior_identity_kind": "none",
   "refreshed": "true", "unknown_paths": [["arn"], ["tags_all", "*"]],
   "decisions": [{"control": "CTF.S3.1", "version": "1", "result": "pass", "action": "deny"},
                 {"control": "CTF.S3.2", "version": "2", "result": "provisional", "action": "deny"}],
   "not_evaluable": [], "exceptions": ["sha256:9999999999999999999999999999999999999999999999999999999999999999"], "baselines": [], "break_glass": []},
  {"address": "aws_db_instance.main", "type": "aws_db_instance", "action": "replace", "previous_address": "aws_db_instance.old",
   "instance_key": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
   "delete_key": "sha256:8888888888888888888888888888888888888888888888888888888888888888", "prior_identity_kind": "id",
   "refreshed": "true", "unknown_paths": [],
   "decisions": [{"control": "CTF.RDS.1", "version": "1", "result": "not_evaluable", "action": "warn"}],
   "delete_decisions": [{"control": "CTF.RDS.9", "version": "1", "result": "pending", "action": "deny"}],
   "not_evaluable": [{"control": "CTF.RDS.1", "reason": "unknown_value"}], "exceptions": [], "baselines": [], "break_glass": []},
  {"address": "aws_instance.web", "deposed": "a1b2c3d4", "type": "aws_instance", "action": "delete",
   "delete_key": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "prior_identity_kind": "identity",
   "refreshed": "false", "unknown_paths": [], "decisions": [], "delete_decisions": [],
   "not_evaluable": [], "exceptions": [], "baselines": [], "break_glass": []}
 ],
 "exceptions": [{"digest": "sha256:9999999999999999999999999999999999999999999999999999999999999999", "source": "grant", "expires": "2026-11-01T00:00:00Z"}],
 "baselines": [{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
 "break_glass_receipts": []
}`

const (
	vNow      = "2026-10-19T12:00:00Z"
	vEarly    = "2026-09-30T23:54:59Z" // not_before - 5m - 1s
	vEdgeNB   = "2026-09-30T23:55:00Z" // not_before - 5m
	vEdgeNA   = "2026-12-31T00:05:00Z" // not_after + 5m
	vLate     = "2026-12-31T00:05:01Z" // not_after + 5m + 1s
	parseFail = "not a compliancetf.verdict/v1 document"
)

// generate rewrites testdata/sig from fresh in-memory keys; no private key is
// ever written.
func generate(t *testing.T) {
	t.Helper()
	priv, key := keyFor(t, elliptic.P256(), "verdict")
	otherPriv, other := keyFor(t, elliptic.P256(), "verdict")
	p384, p384Key := keyFor(t, elliptic.P384(), "verdict")

	signed, err := SignedBytes([]byte(baseDoc))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(k *ecdsa.PrivateKey) string {
		d := sha256.Sum256(signed)
		der, serr := ecdsa.SignASN1(rand.Reader, k, d[:])
		if serr != nil {
			t.Fatal(serr)
		}
		return base64.RawURLEncoding.EncodeToString(der)
	}
	good := sign(priv)
	withSig := func(doc string, s Signature) []byte {
		var m map[string]json.RawMessage
		if uerr := json.Unmarshal([]byte(doc), &m); uerr != nil {
			t.Fatal(uerr)
		}
		m["signature"], _ = json.Marshal(s) //nolint:errcheck // a struct of strings always marshals
		b, merr := json.MarshalIndent(m, "", " ")
		if merr != nil {
			t.Fatal(merr)
		}
		return append(b, '\n')
	}
	ok := Signature{Kid: key.Kid, Alg: AlgES256, Value: good}
	exp := func(now string, keys []vectorKey, revoked []string, err string) expected {
		return expected{Now: now, Use: "verdict", Revoked: revoked, Keys: keys, SignedSHA256: sha256Hex(signed), Error: err}
	}
	baseline := key
	baseline.Use = "baseline"
	mismatch := key
	mismatch.SPKIB64 = other.SPKIB64
	tampered := strings.Replace(baseDoc, `"run_id": "run-1"`, `"run_id": "run-2"`, 1)
	tamperedSigned, err := SignedBytes([]byte(tampered))
	if err != nil {
		t.Fatal(err)
	}

	type sigCase struct {
		doc []byte
		exp expected
	}
	cases := map[string]sigCase{
		"valid":                {withSig(baseDoc, ok), exp(vNow, []vectorKey{key}, nil, "")},
		"skew_edge_before":     {withSig(baseDoc, ok), exp(vEdgeNB, []vectorKey{key}, nil, "")},
		"skew_edge_after":      {withSig(baseDoc, ok), exp(vEdgeNA, []vectorKey{key}, nil, "")},
		"not_yet_valid":        {withSig(baseDoc, ok), exp(vEarly, []vectorKey{key}, nil, ErrKeyTime.Error())},
		"key_expired":          {withSig(baseDoc, ok), exp(vLate, []vectorKey{key}, nil, ErrKeyTime.Error())},
		"unknown_kid":          {withSig(baseDoc, Signature{Kid: other.Kid, Alg: AlgES256, Value: good}), exp(vNow, []vectorKey{key}, nil, ErrKidUnknown.Error())},
		"revoked":              {withSig(baseDoc, ok), exp(vNow, []vectorKey{key}, []string{key.Kid}, ErrKidRevoked.Error())},
		"wrong_use":            {withSig(baseDoc, ok), exp(vNow, []vectorKey{baseline}, nil, "key use is not verdict")},
		"alg_ed25519":          {withSig(baseDoc, Signature{Kid: key.Kid, Alg: "Ed25519", Value: good}), exp(vNow, []vectorKey{key}, nil, ErrAlgorithm.Error())},
		"p384_key":             {withSig(baseDoc, Signature{Kid: p384Key.Kid, Alg: AlgES256, Value: sign(p384)}), exp(vNow, []vectorKey{p384Key}, nil, ErrAlgorithm.Error())},
		"spki_kid_mismatch":    {withSig(baseDoc, ok), exp(vNow, []vectorKey{mismatch}, nil, ErrKidUnknown.Error())},
		"p384_malformed_value": {withSig(baseDoc, Signature{Kid: p384Key.Kid, Alg: AlgES256, Value: "A"}), exp(vNow, []vectorKey{p384Key}, nil, ErrMalformedValue.Error())},
		"malformed_value":      {withSig(baseDoc, Signature{Kid: key.Kid, Alg: AlgES256, Value: "A"}), exp(vNow, []vectorKey{key}, nil, ErrMalformedValue.Error())},
		"bad_der":              {withSig(baseDoc, Signature{Kid: key.Kid, Alg: AlgES256, Value: base64.RawURLEncoding.EncodeToString([]byte("not der"))}), exp(vNow, []vectorKey{key}, nil, ErrBadSignature.Error())},
		"other_key_sig":        {withSig(baseDoc, Signature{Kid: key.Kid, Alg: AlgES256, Value: sign(otherPriv)}), exp(vNow, []vectorKey{key}, nil, ErrBadSignature.Error())},
		"overlap_revoked":      {withSig(baseDoc, Signature{Kid: key.Kid, Alg: "Ed25519", Value: "A"}), exp(vLate, []vectorKey{baseline}, []string{key.Kid}, ErrKidRevoked.Error())},
		"overlap_use":          {withSig(baseDoc, Signature{Kid: key.Kid, Alg: "Ed25519", Value: "A"}), exp(vLate, []vectorKey{baseline}, nil, "key use is not verdict")},
		"tampered":             {withSig(tampered, ok), expected{Now: vNow, Use: "verdict", Keys: []vectorKey{key}, SignedSHA256: sha256Hex(tamperedSigned), Error: ErrBadSignature.Error()}},
	}
	valid := withSig(baseDoc, ok)
	edit := func(old, repl string) []byte {
		if !bytes.Contains(valid, []byte(old)) {
			t.Fatalf("vector edit: %q not found", old)
		}
		return bytes.Replace(valid, []byte(old), []byte(repl), 1)
	}
	parseCases := map[string][]byte{
		"duplicate_member":    edit(`"org_id": "bobthecorp",`, `"org_id": "bobthecorp", "org_id": "bobthecorp",`),
		"nested_duplicate":    edit(`"region": "us-east-1"`, `"region": "us-east-1", "region": "us-east-1"`),
		"number_value":        edit(`"floor_epoch": "3"`, `"floor_epoch": 3`),
		"bool_value":          edit(`"refreshed": "false"`, `"refreshed": false`),
		"null_value":          edit(`"run_id": "run-1"`, `"run_id": null`),
		"unknown_member":      edit(`"run_id": "run-1",`, `"run_id": "run-1", "run_note": "x",`),
		"case_variant_member": edit(`"run_id": "run-1"`, `"Run_ID": "run-1"`),
		"missing_member":      edit(`"nonce": "AAECAwQFBgcICQoLDA0ODw",`, ``),
		"empty_optional":      edit(`"deposed": "a1b2c3d4"`, `"deposed": ""`),
		"lone_surrogate":      edit(`"workspace": "prod"`, `"workspace": "\ud800"`),
		"lone_low_surrogate":  edit(`"workspace": "prod"`, `"workspace": "\udc00x"`),
		"noncharacter":        edit(`"workspace": "prod"`, `"workspace": "\ufdd0"`),
		"invalid_utf8":        edit(`"workspace": "prod"`, "\"workspace\": \"pr\xffd\""),
		"baseline_digest":     edit(`"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`, `"digest": "sha256:BBBB"`),
		"wrong_format":        edit(`"format": "compliancetf.verdict/v1"`, `"format": "compliancetf.verdict/v2"`),
		"trailing_data":       append(append([]byte(nil), valid...), []byte("{}")...),
		"top_level_array":     append(append([]byte("["), valid...), ']'),
	}

	old, err := os.ReadDir(sigDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range old { // case dirs only: bundle_set_digest.json is hand-recorded
		if d.IsDir() {
			if err := os.RemoveAll(filepath.Join(sigDir, d.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, c := range cases {
		writeCase(t, name, "verdict.json", c.doc, c.exp)
	}
	for name, raw := range parseCases {
		writeCase(t, name, "input.json", raw, expected{Error: parseFail})
	}
	kids := []map[string]string{}
	for _, k := range []vectorKey{key, other, p384Key} {
		kids = append(kids, map[string]string{"spki_b64": k.SPKIB64, "kid": k.Kid})
	}
	writeJSON(t, filepath.Join(sigDir, "kid.json"), kids)
}

func writeCase(t *testing.T, name, file string, doc []byte, e expected) {
	t.Helper()
	dir := filepath.Join(sigDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, file), doc)
	writeJSON(t, filepath.Join(dir, "expected.json"), e)
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(b, '\n'))
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil { // #nosec G306 -- public test vectors
		t.Fatal(err)
	}
}
