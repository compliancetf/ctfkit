package instancekey

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// TestTestSecret: only a ctftest build accepts the public golden secret
// (FORMAT.md Test secret). make test runs this file with and without the tag.
func TestTestSecret(t *testing.T) {
	s, err := ParseSecret([]byte(hex.EncodeToString([]byte(testSecret))))
	if allowTestSecret {
		if err != nil {
			t.Fatalf("ctftest build refused the test secret: %v", err)
		}
		leaf, check, kerr := Keys(s)
		wantLeaf, wantCheck := derive([32]byte([]byte(testSecret)))
		if kerr != nil || leaf != wantLeaf || check != wantCheck {
			t.Fatalf("keys of the test secret differ: %v", kerr)
		}
		return
	}
	if !errors.Is(err, ErrTestSecret) {
		t.Fatalf("release build: %v, want ErrTestSecret", err)
	}
	if _, _, err := Keys(s); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("refused secret still derives keys: %v", err)
	}
}

func TestParseSecret(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	s, err := ParseSecret([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if h, err := s.Hex(); err != nil || h != good {
		t.Fatalf("Hex %q, %v", h, err)
	}
	for name, in := range map[string]string{
		"short":            good[:63],
		"long":             good + "0",
		"newline":          good[:63] + "\n",
		"newline after 64": good + "\n",
		"uppercase":        strings.ToUpper(good),
		"not hex":          good[:63] + "g",
		"space":            " " + good[:63],
	} {
		if _, err := ParseSecret([]byte(in)); !errors.Is(err, ErrSecretFormat) {
			t.Errorf("%s: %v, want ErrSecretFormat", name, err)
		}
	}
}

func TestZeroSecret(t *testing.T) {
	var s Secret
	if _, _, err := Keys(s); !errors.Is(err, ErrNoSecret) {
		t.Errorf("Keys: %v", err)
	}
	if _, err := s.Hex(); !errors.Is(err, ErrNoSecret) {
		t.Errorf("Hex: %v", err)
	}
}

func TestNewSecret(t *testing.T) {
	a, errA := NewSecret()
	b, errB := NewSecret()
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	ha, _ := a.Hex()
	hb, _ := b.Hex()
	if ha == hb {
		t.Fatal("two run secrets are equal")
	}
	back, err := ParseSecret([]byte(ha))
	if err != nil || back != a {
		t.Fatalf("round trip: %v", err)
	}
}
