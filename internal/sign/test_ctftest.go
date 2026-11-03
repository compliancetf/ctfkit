//go:build ctftest

package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// A ctftest build opens test:<label>: the P-256 key whose scalar is sha256
// of the label. The label is public, so the key is too; a release build has
// no such scheme and a production profile never lists such a key.
func init() {
	schemes["test"] = func(label string) (Signer, error) {
		if label == "" {
			return nil, errors.New("--signer test: needs a label")
		}
		return NewKeySigner(LabelKey(label)), nil
	}
}

// LabelKey is the test key of a public label.
func LabelKey(label string) *ecdsa.PrivateKey {
	d := sha256.Sum256([]byte(label))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		panic(err) // a sha256 is a valid P-256 scalar but for negligible odds
	}
	return k
}

// KeySigner signs with an in-memory key.
type KeySigner struct{ key *ecdsa.PrivateKey }

// NewKeySigner wraps key.
func NewKeySigner(key *ecdsa.PrivateKey) KeySigner { return KeySigner{key} }

// Public returns the public key.
func (k KeySigner) Public() *ecdsa.PublicKey { return &k.key.PublicKey }

// Sign signs digest.
func (k KeySigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, k.key, digest)
}
