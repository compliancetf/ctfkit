//go:build ctftest

package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"
)

// TestOpenCtftest: a ctftest build opens test:<label> as the label key and
// refuses every other scheme.
func TestOpenCtftest(t *testing.T) {
	s, err := Open("test:bobthecorp")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Public().Equal(&LabelKey("bobthecorp").PublicKey) {
		t.Fatal("test signer is not the label key")
	}
	d := sha256.Sum256([]byte("x"))
	sig, err := s.Sign(context.Background(), d[:])
	if err != nil || !ecdsa.VerifyASN1(s.Public(), d[:], sig) {
		t.Fatalf("test signer signature: %v", err)
	}
	for _, uri := range []string{"test:", "awskms:k", "file:/tmp/k"} {
		if _, err := Open(uri); err == nil {
			t.Errorf("Open(%q) opened a signer", uri)
		}
	}
}
