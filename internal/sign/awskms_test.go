package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

const testKeyARN = "arn:aws:kms:eu-west-1:111111111111:key/00000000-0000-0000-0000-000000000000"

// fakeKMS answers GetPublicKey and Sign of the AWS KMS JSON protocol with an
// in-memory key and records every Sign request.
type fakeKMS struct {
	key     *ecdsa.PrivateKey
	spki    []byte // GetPublicKey PublicKey; default the key's SPKI
	keySpec string // default ECC_NIST_P256
	sig     []byte // Sign Signature; default a DER signature over the message

	mu    sync.Mutex
	signs []kms.SignInput
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in["KeyId"] != testKeyARN {
		http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
		return
	}
	var out any
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.GetPublicKey":
		spki, spec := f.spki, f.keySpec
		if spki == nil {
			spki, _ = x509.MarshalPKIXPublicKey(&f.key.PublicKey)
		}
		if spec == "" {
			spec = "ECC_NIST_P256"
		}
		out = map[string]any{"KeyId": testKeyARN, "KeySpec": spec, "KeyUsage": "SIGN_VERIFY",
			"SigningAlgorithms": []string{"ECDSA_SHA_256"}, "PublicKey": spki}
	case "TrentService.Sign":
		var s kms.SignInput
		raw, _ := json.Marshal(in)
		_ = json.Unmarshal(raw, &s)
		f.mu.Lock()
		f.signs = append(f.signs, s)
		f.mu.Unlock()
		sig := f.sig
		if sig == nil {
			sig, _ = ecdsa.SignASN1(rand.Reader, f.key, s.Message)
		}
		out = map[string]any{"KeyId": testKeyARN, "SigningAlgorithm": "ECDSA_SHA_256", "Signature": sig}
	default:
		http.Error(w, `{"__type":"UnknownOperationException"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(out)
}

// kmsClient is a real SDK client pointed at f; it never reaches AWS.
func kmsClient(t *testing.T, f *fakeKMS) *kms.Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return kms.New(kms.Options{
		Region:       "eu-west-1",
		BaseEndpoint: aws.String(srv.URL),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "test"}, nil
		}),
		RetryMaxAttempts: 1,
	})
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestAWSKMSVerdict: a KMS key the profile trusts signs the digest of the
// signed bytes (MessageType DIGEST, ECDSA_SHA_256) and its DER signature
// verifies; a KMS key the profile does not list is never asked to sign.
func TestAWSKMSVerdict(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	f := &fakeKMS{key: newKey(t)}
	s, err := NewAWSKMS(ctx, kmsClient(t, f), testKeyARN)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if kid, _ := KeyID(s); kid != verdict.KeyID(spki) {
		t.Fatalf("kid %s is not sha256 of the KMS SPKI", kid)
	}
	keys := []verdict.PublicKey{trusted(t, f.key)}
	raw, err := Verdict(ctx, s, doc(), keys, nil, now)
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
	if len(f.signs) != 1 || f.signs[0].MessageType != "DIGEST" || f.signs[0].SigningAlgorithm != "ECDSA_SHA_256" || len(f.signs[0].Message) != 32 {
		t.Fatalf("Sign requests %+v, want one DIGEST ECDSA_SHA_256 of 32 bytes", f.signs)
	}

	other := &fakeKMS{key: newKey(t)}
	s, err = NewAWSKMS(ctx, kmsClient(t, other), testKeyARN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verdict(ctx, s, doc(), keys, nil, now); !errors.Is(err, verdict.ErrKidUnknown) {
		t.Fatalf("untrusted KMS key: %v, want ErrKidUnknown", err)
	}
	if len(other.signs) != 0 {
		t.Fatal("untrusted KMS key was asked to sign")
	}

	// A signature that is not a DER signature over the digest is refused.
	f.sig = []byte("not der")
	s, _ = NewAWSKMS(ctx, kmsClient(t, f), testKeyARN)
	if _, err = Verdict(ctx, s, doc(), keys, nil, now); !errors.Is(err, verdict.ErrBadSignature) {
		t.Fatalf("bad KMS signature: %v, want ErrBadSignature", err)
	}
}

// TestNewAWSKMSRefuses: keys of another spec or with a non-P-256 SPKI, and
// an unknown key, do not open.
func TestNewAWSKMSRefuses(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSPKI, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384SPKI, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	for name, f := range map[string]*fakeKMS{
		"spec": {key: newKey(t), keySpec: "ECC_SECG_P256K1"},
		"rsa":  {key: newKey(t), spki: rsaSPKI},
		"p384": {key: newKey(t), spki: p384SPKI},
		"junk": {key: newKey(t), spki: []byte("junk")},
	} {
		if _, err := NewAWSKMS(context.Background(), kmsClient(t, f), testKeyARN); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := NewAWSKMS(context.Background(), kmsClient(t, &fakeKMS{key: newKey(t)}), testKeyARN+"x"); err == nil {
		t.Error("unknown key opened")
	}
}
