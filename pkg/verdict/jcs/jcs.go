// Package jcs is the JSON Canonicalization Scheme of RFC 8785: object members
// sorted by UTF-16 code units, no insignificant whitespace, the minimal string
// escaping JSON requires and nothing more, numbers in ECMAScript form, and no
// trailing newline.
//
// It exists because a signature covers bytes. A signed document (a receipt
// statement, a verdict minus its signature) has to reserialize to exactly the
// signed bytes on any machine and from any JSON library that also
// canonicalizes; the terraform provider verifies those bytes with its own
// RFC 8785 implementation, and testdata/ holds the vectors both agree on.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrNotIJSON is every refusal of TransformIJSON, the provider's
// digest_not_json class. It never quotes the input.
var ErrNotIJSON = errors.New("jcs: not one I-JSON value")

// maxDepth bounds nesting so a deep document cannot exhaust the stack.
const maxDepth = 10000

// Transform rewrites one JSON document in its RFC 8785 form.
//
// Input that is not I-JSON (invalid UTF-8, an unpaired surrogate escape, a
// duplicate member name) is decoded the way encoding/json decodes it rather
// than refused. That is right for this project's own json.Marshal output,
// whose strings may hold noncharacters a plan value carries; a document from
// anywhere else goes through TransformIJSON.
func Transform(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	// One document, not the first of several. Bytes trailing the closing brace
	// would be dropped rather than refused, and two readers would then
	// disagree about what was signed. More() would miss a stray } or ], so
	// the next token has to be the end of input.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("jcs: trailing data after the JSON document")
	}

	var out bytes.Buffer
	if err := write(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// TransformIJSON is Transform for a document this project did not produce,
// with the checks of the provider's bundle.CanonicalJSON: input that is not
// one I-JSON value (RFC 7493) is ErrNotIJSON. That is invalid UTF-8, an
// unpaired surrogate escape, a noncharacter in a string or member name, a
// duplicate member name at any depth, nesting deeper than maxDepth, a number
// outside float64 or trailing data. Input that passes gets exactly the bytes
// Transform writes.
func TransformIJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) || !SurrogatesPaired(raw) {
		return nil, ErrNotIJSON
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || checkValue(dec, tok, 0) != nil {
		return nil, ErrNotIJSON
	}
	out, err := Transform(raw) // refuses trailing data and numbers outside float64
	if err != nil {
		return nil, ErrNotIJSON
	}
	return out, nil
}

// checkValue checks the value that starts with tok for duplicate member
// names, noncharacters and depth.
func checkValue(dec *json.Decoder, tok json.Token, depth int) error {
	if depth > maxDepth {
		return ErrNotIJSON
	}
	switch tok {
	case json.Delim('['):
		for dec.More() {
			t, err := dec.Token()
			if err != nil {
				return err
			}
			if err = checkValue(dec, t, depth+1); err != nil {
				return err
			}
		}
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			name, ok := k.(string)
			if err != nil || !ok || seen[name] || hasNoncharacter(name) {
				return ErrNotIJSON
			}
			seen[name] = true
			t, err := dec.Token()
			if err != nil {
				return err
			}
			if err = checkValue(dec, t, depth+1); err != nil {
				return err
			}
		}
	default:
		if s, ok := tok.(string); ok && hasNoncharacter(s) {
			return ErrNotIJSON
		}
		return nil
	}
	_, err := dec.Token() // the closing delimiter
	return err
}

// SurrogatesPaired reports whether every high surrogate escape (\uD800 to
// \uDBFF) inside a string is followed at once by a low surrogate escape and no
// low surrogate escape stands alone. encoding/json would read an unpaired one
// as U+FFFD, so two readers could disagree about the signed text. raw is valid
// UTF-8, so a '"' or '\\' byte never sits inside a multi-byte sequence.
func SurrogatesPaired(raw []byte) bool {
	in := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case !in:
			in = c == '"'
		case c == '"':
			in = false
		case c != '\\':
		case i+1 < len(raw) && raw[i+1] != 'u':
			i++ // a one-character escape
		default:
			hi, ok := escape(raw, i)
			switch {
			case !ok || 0xDC00 <= hi && hi <= 0xDFFF:
				return false
			case 0xD800 <= hi && hi <= 0xDBFF:
				lo, ok := escape(raw, i+6)
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return false
				}
				i += 11
			default:
				i += 5
			}
		}
	}
	return true
}

// escape decodes the \uXXXX escape at raw[i:i+6].
func escape(raw []byte, i int) (int, bool) {
	if i+6 > len(raw) || raw[i] != '\\' || raw[i+1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
	return int(v), err == nil
}

// hasNoncharacter reports a Unicode noncharacter: U+FDD0 to U+FDEF, or a code
// point ending in FFFE or FFFF (RFC 7493 section 2.1).
func hasNoncharacter(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return 0xFDD0 <= r && r <= 0xFDEF || r&0xFFFE == 0xFFFE
	}) >= 0
}

func write(out *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sortUTF16(keys)

		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(out, key)
			out.WriteByte(':')
			if err := write(out, typed[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, element := range typed {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := write(out, element); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case string:
		writeString(out, typed)
	case json.Number:
		number, err := formatNumber(typed)
		if err != nil {
			return err
		}
		out.WriteString(number)
	case bool:
		out.WriteString(strconv.FormatBool(typed))
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("jcs: unexpected %T in the document", value)
	}
	return nil
}

// sortUTF16 orders keys by their UTF-16 code units, as RFC 8785 section 3.2.3
// requires. Byte order agrees below U+10000 and differs above it: a key
// starting with U+1F600 (surrogates D83D DE00) sorts before one starting with
// U+FB33, the reverse of their UTF-8 bytes.
func sortUTF16(keys []string) {
	units := make(map[string][]uint16, len(keys))
	for _, key := range keys {
		units[key] = utf16.Encode([]rune(key))
	}
	sort.Slice(keys, func(i, j int) bool {
		return slices.Compare(units[keys[i]], units[keys[j]]) < 0
	})
}

// writeString escapes only what JSON requires: the quote, the backslash and
// the control characters below U+0020. Go's encoder also escapes <, > and &
// for HTML safety and the two line separators for old JavaScript parsers;
// RFC 8785 forbids both, so the escaping is written here rather than
// delegated.
func writeString(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
				continue
			}
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
}

// formatNumber writes a JSON number as ECMAScript Number.prototype.toString
// writes the nearest float64 (RFC 8785 section 3.2.2.3). Go's shortest
// round-trip digits are the digits ECMAScript picks; only the layout differs.
func formatNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsInf(f, 0) {
		return "", fmt.Errorf("jcs: number %s is outside the float64 range", n)
	}
	if f == 0 {
		return "0", nil // and -0
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	e, err := strconv.Atoi(exponent)
	if err != nil {
		return "", fmt.Errorf("jcs: number %s: %w", n, err)
	}
	// value = 0.digits * 10^point, the k and n of ECMA-262 Number::toString.
	k, point := len(digits), e+1
	switch {
	case k <= point && point <= 21:
		return sign + digits + strings.Repeat("0", point-k), nil
	case 0 < point && point <= 21:
		return sign + digits[:point] + "." + digits[point:], nil
	case -6 < point && point <= 0:
		return sign + "0." + strings.Repeat("0", -point) + digits, nil
	}
	exp := strconv.Itoa(point - 1)
	if point-1 >= 0 {
		exp = "+" + exp
	}
	if k == 1 {
		return sign + digits + "e" + exp, nil
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + exp, nil
}
