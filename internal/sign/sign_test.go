package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

type memSigner struct {
	key   *ecdsa.PrivateKey
	bad   bool // return a signature over another digest
	calls *int // counts Sign calls when set
}

func (m memSigner) Public() *ecdsa.PublicKey { return &m.key.PublicKey }

func (m memSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	if m.calls != nil {
		*m.calls++
	}
	if m.bad {
		other := sha256.Sum256(digest)
		digest = other[:]
	}
	return ecdsa.SignASN1(rand.Reader, m.key, digest)
}

func trusted(t *testing.T, k *ecdsa.PrivateKey) verdict.PublicKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return verdict.PublicKey{Kid: verdict.KeyID(der), Key: &k.PublicKey, Use: "verdict",
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func doc() *verdict.Document {
	return &verdict.Document{Format: verdict.Format, OrgID: "bobthecorp", Caller: []byte(`{}`), Provenance: []byte(`{}`),
		ProviderVersions: map[string]string{}, Instances: []verdict.Instance{}, Exceptions: []verdict.ExceptionRef{},
		Baselines: []verdict.BaselineRef{}, BreakGlassReceipts: []json.RawMessage{}}
}

// TestVerdict: a trusted key signs a document that Parse and Verify accept;
// an untrusted key, a revoked kid and a signer returning a wrong signature
// never yield a signed verdict, and an untrusted or revoked key is never
// asked to sign.
func TestVerdict(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	keys := []verdict.PublicKey{trusted(t, key)}

	raw, err := Verdict(context.Background(), memSigner{key: key}, doc(), keys, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	d, err := verdict.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = verdict.Verify(raw, d.Signature, keys, nil, "verdict", now); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		s         memSigner
		revoked   []string
		want      error
		wantCalls int
	}{
		"untrusted": {memSigner{key: other}, nil, verdict.ErrKidUnknown, 0},
		"revoked":   {memSigner{key: key}, []string{keys[0].Kid}, verdict.ErrKidRevoked, 0},
		"bad-sig":   {memSigner{key: key, bad: true}, nil, verdict.ErrBadSignature, 1},
	} {
		calls := 0
		tc.s.calls = &calls
		if _, err := Verdict(context.Background(), tc.s, doc(), keys, tc.revoked, now); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
		if calls != tc.wantCalls {
			t.Errorf("%s: %d Sign calls, want %d", name, calls, tc.wantCalls)
		}
	}
}
