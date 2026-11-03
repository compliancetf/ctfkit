package instancekey

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

// HKDF info strings (spec B3).
const (
	infoLeaf  = "compliancetf.verdict/v1 leaf"
	infoCheck = "compliancetf.verdict/v1 key-check"
)

// testSecret is the public secret every golden is computed with (FORMAT.md
// Test secret); keys derived from it are forgeable.
const testSecret = "INSECURE-TEST-SECRET-instancekey"

var (
	// ErrSecretFormat: the key file is not exactly 64 lowercase hex characters.
	ErrSecretFormat = errors.New("run key is not 64 lowercase hex characters")
	// ErrTestSecret: the key is the public golden test secret, refused
	// outside ctftest builds.
	ErrTestSecret = errors.New("run key is the public instance_key test secret")
	// ErrNoSecret: a Secret that did not come from the constructor.
	ErrNoSecret = errors.New("run key not constructed")
)

// Secret is a per-run secret. Only ParseSecret and NewSecret make a usable
// one; the zero value is refused.
type Secret struct {
	b  [32]byte
	ok bool
}

// ParseSecret is the one constructor every run secret goes through: exactly
// 64 lowercase hex characters, decoded into a fixed 32-byte buffer (no trim,
// no truncation), refused when it is the public test secret unless this is a
// ctftest build.
func ParseSecret(text []byte) (Secret, error) {
	var s Secret
	if len(text) != 64 {
		return s, ErrSecretFormat
	}
	for _, c := range text {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return s, ErrSecretFormat
		}
	}
	if _, err := hex.Decode(s.b[:], text); err != nil {
		return s, ErrSecretFormat
	}
	if subtle.ConstantTimeCompare(s.b[:], []byte(testSecret)) == 1 && !allowTestSecret {
		return Secret{}, ErrTestSecret
	}
	s.ok = true
	return s, nil
}

// NewSecret is a fresh run secret from crypto/rand.
func NewSecret() (Secret, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Secret{}, err
	}
	return ParseSecret([]byte(hex.EncodeToString(b[:])))
}

// Hex is the key file content: 64 lowercase hex characters, no newline.
func (s Secret) Hex() (string, error) {
	if !s.ok {
		return "", ErrNoSecret
	}
	return hex.EncodeToString(s.b[:]), nil
}

// Keys derives the leaf and check keys of s (HKDF-SHA256, empty salt).
func Keys(s Secret) (leaf, check [32]byte, err error) {
	if !s.ok {
		return leaf, check, ErrNoSecret
	}
	leaf, check = derive(s.b)
	return leaf, check, nil
}

func derive(secret [32]byte) (leaf, check [32]byte) {
	l, err := hkdf.Key(sha256.New, secret[:], nil, infoLeaf, 32)
	if err != nil {
		panic(err) // unreachable: 32 bytes is far below the HKDF-SHA256 limit
	}
	c, err := hkdf.Key(sha256.New, secret[:], nil, infoCheck, 32)
	if err != nil {
		panic(err)
	}
	copy(leaf[:], l)
	copy(check[:], c)
	return leaf, check
}

// KeyCheck is instance_key_check: hex(HMAC-SHA256(k_check, info)).
func KeyCheck(check [32]byte) string {
	m := hmac.New(sha256.New, check[:])
	m.Write([]byte(infoCheck))
	return hex.EncodeToString(m.Sum(nil))
}
