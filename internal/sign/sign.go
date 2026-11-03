// Package sign signs verdicts for ctfkit gate sign: a Signer holds one ES256
// key (ECDSA P-256), and Verdict signs a verdict document with it and checks
// the result against the keys the signed org profile trusts before the
// signature is used.
//
// Signers are opened by URI (--signer). Every build opens awskms:KEY_ARN,
// an AWS KMS ECC_NIST_P256 key; a ctftest build adds test:<label>, a key
// derived from a public label.
package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

// Signer signs a SHA-256 digest with an ECDSA P-256 key and returns the
// ASN.1 DER signature.
type Signer interface {
	Public() *ecdsa.PublicKey
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// schemes are the URI schemes this build can open.
var schemes = map[string]func(rest string) (Signer, error){}

// Open opens a signer URI, scheme:rest.
func Open(uri string) (Signer, error) {
	scheme, rest, ok := strings.Cut(uri, ":")
	if open := schemes[scheme]; ok && open != nil {
		return open(rest)
	}
	return nil, fmt.Errorf("--signer scheme %q is not supported; use awskms:KEY_ARN", scheme)
}

// KeyID is the kid of the signer's key: sha256 of its SPKI DER.
func KeyID(s Signer) (string, error) {
	pub := s.Public()
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errors.New("signer key is not ECDSA P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return verdict.KeyID(der), nil
}

// Verdict signs doc with s: it sets doc.Signature from the ES256 signature
// over verdict.SignedBytes, then verifies it with verdict.Verify against
// keys (the profile's verdict keys) at now, so a key the profile does not
// trust, or a signer that returned a bad signature, never yields a signed
// verdict. It returns the signed document bytes.
func Verdict(ctx context.Context, s Signer, doc *verdict.Document, keys []verdict.PublicKey, revoked []string, now time.Time) ([]byte, error) {
	return Document(ctx, s, doc, &doc.Signature, keys, revoked, now)
}

// Document signs doc, whose top-level signature member is *sig, the way
// Verdict signs a verdict: with a key of keys only, checked with
// verdict.Verify for use verdict before it is returned. ctfkit evidence ship
// signs the run manifest with it.
func Document(ctx context.Context, s Signer, doc any, sig *verdict.Signature, keys []verdict.PublicKey, revoked []string, now time.Time) ([]byte, error) {
	kid, err := KeyID(s)
	if err != nil {
		return nil, err
	}
	// The signer is asked to sign only with a key the profile trusts.
	switch {
	case slices.Contains(revoked, kid):
		return nil, fmt.Errorf("signer key: %w", verdict.ErrKidRevoked)
	case !slices.ContainsFunc(keys, func(k verdict.PublicKey) bool { return k.Kid == kid }):
		return nil, fmt.Errorf("signer key: %w", verdict.ErrKidUnknown)
	}
	*sig = verdict.Signature{Kid: kid, Alg: verdict.AlgES256}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	signed, err := verdict.SignedBytes(raw)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(signed)
	value, err := s.Sign(ctx, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	sig.Value = base64.RawURLEncoding.EncodeToString(value)
	if raw, err = json.Marshal(doc); err == nil {
		err = verdict.Verify(raw, *sig, keys, revoked, "verdict", now)
	}
	if err != nil {
		return nil, fmt.Errorf("signed document does not verify against the profile's verdict keys: %w", err)
	}
	return raw, nil
}
