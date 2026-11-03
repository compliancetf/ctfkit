package verdict

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate testdata/sig with a fresh in-memory key")

const sigDir = "testdata/sig"

// vectorKey is a trusted key of a vector, as a signed profile lists it.
type vectorKey struct {
	Kid       string `json:"kid"`
	SPKIB64   string `json:"spki_b64"`
	Use       string `json:"use"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// expected is a case's inputs and outcome. A verdict.json case parses and
// verifies to error ("" is success); an input.json case fails Parse with error.
type expected struct {
	Now          string      `json:"now,omitempty"`
	Use          string      `json:"use,omitempty"`
	Revoked      []string    `json:"revoked,omitempty"`
	Keys         []vectorKey `json:"keys,omitempty"`
	SignedSHA256 string      `json:"signed_sha256,omitempty"`
	Error        string      `json:"error"`
}

// TestSigVectors runs testdata/sig. The terraform provider must reach the same
// result on every case: its strict parse accepts exactly the verdict.json
// cases and refuses every input.json case, its signed bytes hash to
// signed_sha256, and its signature check returns error for the given now,
// keys (a profile's verdict.public_keys) and revoked (revoked_kids).
// Regenerate with: go test ./pkg/verdict -run TestSigVectors -update
func TestSigVectors(t *testing.T) {
	if *update {
		generate(t)
	}
	dirs, err := os.ReadDir(sigDir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		n++
		t.Run(d.Name(), func(t *testing.T) {
			dir := filepath.Join(sigDir, d.Name())
			var want expected
			readJSON(t, filepath.Join(dir, "expected.json"), &want)
			if raw, err := os.ReadFile(filepath.Join(dir, "input.json")); err == nil {
				if _, err := Parse(raw); err == nil || err.Error() != want.Error {
					t.Fatalf("Parse = %v, want %q", err, want.Error)
				}
				return
			}
			raw, err := os.ReadFile(filepath.Join(dir, "verdict.json"))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			signed, err := SignedBytes(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256Hex(signed); got != want.SignedSHA256 {
				t.Fatalf("signed bytes sha256 = %s, want %s", got, want.SignedSHA256)
			}
			now, err := time.Parse(time.RFC3339, want.Now)
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if err := Verify(raw, doc.Signature, publicKeys(t, want.Keys), want.Revoked, want.Use, now); err != nil {
				got = err.Error()
			}
			if got != want.Error {
				t.Fatalf("Verify = %q, want %q", got, want.Error)
			}
		})
	}
	if n < 20 {
		t.Fatalf("only %d vector cases under %s", n, sigDir)
	}
}

// TestKeyIDVectors pins KeyID to sha256 over the SPKI DER, computed outside
// this package (shasum) when the vectors were recorded.
func TestKeyIDVectors(t *testing.T) {
	var vs []struct {
		SPKIB64 string `json:"spki_b64"`
		Kid     string `json:"kid"`
	}
	readJSON(t, filepath.Join(sigDir, "kid.json"), &vs)
	for _, v := range vs {
		der, err := base64.StdEncoding.DecodeString(v.SPKIB64)
		if err != nil {
			t.Fatal(err)
		}
		if got := KeyID(der); got != v.Kid {
			t.Errorf("KeyID = %s, want %s", got, v.Kid)
		}
	}
	if len(vs) == 0 {
		t.Fatal("no kid vectors")
	}
}

// TestBundleSetDigestVectors: expected digests were computed with shasum over
// the sorted digests joined by "\n" (no trailing newline).
func TestBundleSetDigestVectors(t *testing.T) {
	var vs []struct {
		ManifestDigests []string `json:"manifest_digests"`
		Digest          string   `json:"digest"`
	}
	readJSON(t, filepath.Join(sigDir, "bundle_set_digest.json"), &vs)
	for _, v := range vs {
		in := append([]string(nil), v.ManifestDigests...)
		if got := BundleSetDigest(v.ManifestDigests); got != v.Digest {
			t.Errorf("BundleSetDigest(%v) = %s, want %s", v.ManifestDigests, got, v.Digest)
		}
		if !slices.Equal(in, v.ManifestDigests) {
			t.Error("BundleSetDigest reordered its input")
		}
	}
	if len(vs) == 0 {
		t.Fatal("no bundle set digest vectors")
	}
}

func TestSignedBytes(t *testing.T) {
	got, err := SignedBytes([]byte(`{"b":{"signature":"kept"},"signature":{"kid":"x"},"a":"1"}`))
	if err != nil || string(got) != `{"a":"1","b":{"signature":"kept"}}` {
		t.Fatalf("SignedBytes = %s, %v", got, err)
	}
	if got, err := SignedBytes([]byte(`{"a":"1"}`)); err != nil || string(got) != `{"a":"1"}` {
		t.Fatalf("unsigned document: %s, %v", got, err)
	}
	for _, bad := range []string{`["a"]`, `{"a":1}`, `{"a":"1"}{}`, `{"a":"1","a":"2"}`, "{\"a\":\"\xff\"}"} {
		if _, err := SignedBytes([]byte(bad)); err == nil {
			t.Errorf("SignedBytes(%q) accepted", bad)
		}
	}
}

func TestVerifyNilKey(t *testing.T) {
	keys := []PublicKey{{Kid: "sha256:00", Use: "verdict"}}
	err := Verify([]byte(`{}`), Signature{Kid: "sha256:00", Alg: AlgES256, Value: "AA"}, keys, nil, "verdict", time.Now())
	if !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("nil key: %v", err)
	}
}

func publicKeys(t *testing.T, vks []vectorKey) []PublicKey {
	t.Helper()
	var out []PublicKey
	for _, vk := range vks {
		der, err := base64.StdEncoding.DecodeString(vk.SPKIB64)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatal(err)
		}
		nb, err1 := time.Parse(time.RFC3339, vk.NotBefore)
		na, err2 := time.Parse(time.RFC3339, vk.NotAfter)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		out = append(out, PublicKey{Kid: vk.Kid, Key: pub.(*ecdsa.PublicKey), Use: vk.Use, NotBefore: nb, NotAfter: na})
	}
	return out
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// keyFor returns a fresh key of curve c and its vector entry; the private key
// lives only in memory.
func keyFor(t *testing.T, c elliptic.Curve, use string) (*ecdsa.PrivateKey, vectorKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, vectorKey{Kid: KeyID(der), SPKIB64: base64.StdEncoding.EncodeToString(der), Use: use,
		NotBefore: "2026-10-01T00:00:00Z", NotAfter: "2026-12-31T00:00:00Z"}
}
