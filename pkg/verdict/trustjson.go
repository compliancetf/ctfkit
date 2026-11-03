package verdict

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The strict JSON rules of the trust files (DSSE envelopes, keyring,
// revocations, manifest, floor, profile), ported from the provider's
// internal/trust/jsonstrict.go so both sides accept the same bytes.

const maxTrustDepth = 32

var (
	errInvalidJSON = errors.New("invalid JSON")
	errWrongShape  = errors.New("JSON value has the wrong shape")
	errUnknownName = errors.New("unknown member name")
	errTrailing    = errors.New("trailing data after JSON value")
)

// foldName maps every rune to the smallest rune of its Unicode simple-fold
// orbit: two names collide exactly when encoding/json would match them to
// the same field.
func foldName(s string) string {
	var b strings.Builder
	for _, r := range s {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			m = min(m, f)
		}
		b.WriteRune(m)
	}
	return b.String()
}

type jsonFrame struct {
	obj, wantKey bool
	seen         map[string]bool
}

// checkJSON rejects invalid UTF-8, more than one top-level value, nesting
// deeper than maxTrustDepth, member names duplicated under case folding and,
// when allowed is non-nil, member names not in allowed and null values.
// Errors never quote the input.
func checkJSON(data []byte, allowed map[string]bool) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*jsonFrame
	values := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errInvalidJSON
		}
		var top *jsonFrame
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			continue
		}
		if top != nil && top.obj && top.wantKey {
			name, ok := tok.(string)
			if !ok {
				return errors.New("non-string member name")
			}
			folded := foldName(name)
			if top.seen[folded] {
				return errors.New("duplicate member name")
			}
			top.seen[folded] = true
			if allowed != nil && !allowed[name] {
				return errUnknownName
			}
			top.wantKey = false
			continue
		}
		if top == nil {
			if values++; values > 1 {
				return errTrailing
			}
		} else if top.obj {
			top.wantKey = true
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) >= maxTrustDepth {
				return errors.New("JSON nested too deep")
			}
			obj := tok == json.Delim('{')
			stack = append(stack, &jsonFrame{obj: obj, wantKey: obj, seen: map[string]bool{}})
		case nil:
			if allowed != nil {
				return errors.New("null value")
			}
		}
	}
	if values != 1 {
		return errors.New("empty JSON")
	}
	return nil
}

// strictUnmarshal is checkJSON with allowed, then a decode with unknown
// fields rejected. A decode error is errWrongShape alone: the decoder's text
// quotes names and values.
func strictUnmarshal(data []byte, allowed map[string]bool, v any) error {
	if err := checkJSON(data, allowed); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errWrongShape
	}
	return nil
}

func names(n ...string) map[string]bool {
	m := make(map[string]bool, len(n))
	for _, s := range n {
		m[s] = true
	}
	return m
}
