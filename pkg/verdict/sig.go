package verdict

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// AlgES256 is the only signature algorithm Verify accepts: ECDSA P-256 over
// SHA-256 of the signed bytes.
const AlgES256 = "ES256"

// Skew is the clock skew allowed on a key's not_before and not_after.
const Skew = 5 * time.Minute

// PublicKey is a trusted signing key. Kid must be KeyID of the key's SPKI DER;
// Use names what it may sign (verdict, baseline, receipt).
type PublicKey struct {
	Kid                 string
	Key                 *ecdsa.PublicKey
	Use                 string
	NotBefore, NotAfter time.Time
}

// Verify errors. Their texts are the reasons the provider reports, in the
// order Verify checks them.
var (
	ErrKidRevoked     = errors.New("kid revoked")
	ErrKidUnknown     = errors.New("kid unknown")
	ErrKeyUse         = errors.New("key use is not")
	ErrAlgorithm      = errors.New("algorithm not allowed")
	ErrKeyTime        = errors.New("key not valid at this time")
	ErrMalformedValue = errors.New("malformed signature value")
	ErrBadSignature   = errors.New("signature does not verify")
)

// SignedBytes returns the bytes a signature covers: the JCS (RFC 8785) form of
// doc with its top-level "signature" member removed (absent is fine, so a
// signer calls it on the unsigned document). doc must be a strict JSON object
// of strings, arrays and objects: valid UTF-8, paired surrogate escapes, no
// noncharacter and no duplicate member name.
func SignedBytes(doc []byte) ([]byte, error) {
	canon, err := canonical(doc)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err = json.Unmarshal(canon, &top); err != nil {
		return nil, err
	}
	delete(top, "signature")
	b, err := json.Marshal(top)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// Verify checks sig over SignedBytes(doc) against keys, the keys trusted for
// use. It checks, in this order: sig.Kid not in revoked, sig.Kid in keys, the
// key's Use, sig.Alg ES256, now within the key's validity widened by Skew at
// both ends, Kid equal to KeyID of the key, the value encoding, the key on
// P-256, then the signature itself. It checks the signature only:
// callers Parse a verdict first.
func Verify(doc []byte, sig Signature, keys []PublicKey, revoked []string, use string, now time.Time) error {
	if slices.Contains(revoked, sig.Kid) {
		return ErrKidRevoked
	}
	i := slices.IndexFunc(keys, func(k PublicKey) bool { return k.Kid == sig.Kid })
	if i < 0 {
		return ErrKidUnknown
	}
	key := keys[i]
	switch {
	case key.Use != use:
		return fmt.Errorf("%w %s", ErrKeyUse, use)
	case sig.Alg != AlgES256 || key.Key == nil:
		return ErrAlgorithm
	case now.Before(key.NotBefore.Add(-Skew)) || now.After(key.NotAfter.Add(Skew)):
		return ErrKeyTime
	}
	der, err := x509.MarshalPKIXPublicKey(key.Key)
	if err != nil || KeyID(der) != key.Kid {
		return ErrKidUnknown
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(sig.Value)
	if err != nil {
		return ErrMalformedValue
	}
	if key.Key.Curve != elliptic.P256() { // after the value decode, as the provider orders it
		return ErrAlgorithm
	}
	signed, err := SignedBytes(doc)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(key.Key, digest[:], value) {
		return ErrBadSignature
	}
	return nil
}

// KeyID is the key id of a public key: "sha256:" + hex of sha256 over its
// SPKI DER (x509.MarshalPKIXPublicKey).
func KeyID(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BundleSetDigest is the digest of a loaded bundle set: "sha256:" + hex of
// sha256 over the manifest digests (each "sha256:<hex>" of the raw
// manifest.dsse.json bytes), sorted and joined by "\n". It equals the
// provider's ControlSet.Digest.
func BundleSetDigest(manifestDigests []string) string {
	sorted := slices.Clone(manifestDigests)
	slices.Sort(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
