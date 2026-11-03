package tfjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// maxDepth bounds nesting so a deep document cannot exhaust the stack.
const maxDepth = 10000

// decodeStrict decodes one JSON document into a value tree with numbers as
// json.Number. It refuses what encoding/json would read silently (FORMAT.md
// Value tree errors): invalid UTF-8, a lone surrogate escape and a duplicate
// object key at any depth.
func decodeStrict(raw []byte) (any, error) {
	if !utf8.Valid(raw) || !jcs.SurrogatesPaired(raw) {
		return nil, errors.New("not valid UTF-8 (or a lone surrogate escape)")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	v, err := strictValue(dec, tok, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON document")
	}
	return v, nil
}

func strictValue(dec *json.Decoder, tok json.Token, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("JSON nested too deep")
	}
	switch tok {
	case json.Delim('['):
		out := []any{}
		for dec.More() {
			t, err := dec.Token()
			if err != nil {
				return nil, err
			}
			v, err := strictValue(dec, t, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		_, err := dec.Token()
		return out, err
	case json.Delim('{'):
		out := map[string]any{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, err
			}
			name, ok := k.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			if _, dup := out[name]; dup {
				return nil, fmt.Errorf("duplicate object key %q", name)
			}
			t, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if out[name], err = strictValue(dec, t, depth+1); err != nil {
				return nil, err
			}
		}
		_, err := dec.Token()
		return out, err
	}
	return tok, nil // string, json.Number, bool or nil
}
