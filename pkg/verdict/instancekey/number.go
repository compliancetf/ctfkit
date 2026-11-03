package instancekey

import (
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxNumberText = 1200 // bytes; holds every in-bound value as cty writes it
	maxExponent   = 1000 // |floor(log10(|x|))|
)

// numberText is the canonical text of a decimal literal (FORMAT.md Numbers):
// length and exponent bounds, zero as "0", then the 512-bit rounding as an
// exact integer or the shortest round-trip 'g' text.
func numberText(s string) (string, error) {
	if len(s) > maxNumberText {
		return "", errors.New("number text longer than 1200 bytes")
	}
	e, zero, err := literalExp(s)
	switch {
	case err != nil:
		return "", err
	case zero:
		return "0", nil
	case e > maxExponent || e < -maxExponent:
		return "", errors.New("number exponent out of range")
	}
	f, _, err := big.ParseFloat(s, 10, 512, big.ToNearestEven)
	if err != nil {
		return "", err
	}
	if f.IsInt() {
		return f.Text('f', 0), nil
	}
	return f.Text('g', -1), nil
}

// jsonNumber is the RFC 8259 number grammar; plan JSON numbers arrive in it.
var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// literalExp is floor(log10(|x|)) of the decimal literal s, from its
// coefficient digits and exponent without expanding the value.
func literalExp(s string) (int64, bool, error) {
	if !jsonNumber.MatchString(s) {
		return 0, false, errors.New("malformed number")
	}
	coef, expText := strings.TrimPrefix(s, "-"), "0"
	if i := strings.IndexAny(coef, "eE"); i >= 0 {
		coef, expText = coef[:i], coef[i+1:]
	}
	intPart, frac, _ := strings.Cut(coef, ".")
	digits := intPart + frac
	first := strings.IndexFunc(digits, func(r rune) bool { return r != '0' })
	if first < 0 {
		return 0, true, nil // zero, whatever its exponent
	}
	exp, err := strconv.ParseInt(expText, 10, 64)
	if err != nil { // the grammar leaves only ErrRange
		return 1 << 62, false, nil // beyond any bound
	}
	return int64(len(intPart)-1-first) + exp, false, nil
}

// NumberText is the canonical number text of a decimal literal (FORMAT.md
// Numbers); readdigest hashes number leaves with it.
func NumberText(s string) (string, error) { return numberText(s) }
