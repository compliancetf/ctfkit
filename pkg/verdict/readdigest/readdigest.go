// Package readdigest computes read_digest (spec B4): the digest a baseline
// entry binds of the values its control reads, keyed by the org-held
// baseline key so the plaintext values never appear in a baseline or an
// evidence record. The terraform provider computes it from prior state
// (internal/baseline ReadDigest); testdata/readdigest holds its vectors.
//
// read_digest = "sha256:" + hex(sha256(JCS(o))), where o maps each read path,
// as the control writes it, to H_b of the value at that path. H_b is the
// keyed value tree of the instance_key format v1 (instancekey) with the
// leaf key HKDF-SHA256(baseline key, salt "", info
// "compliancetf.read-digest/v1"), except that JSON null is kept wherever it
// occurs (an object member, map value or list element), and every declared
// object attribute appears, absent ones as null.
package readdigest

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

const info = "compliancetf.read-digest/v1"

// ErrKeyFormat: the baseline key file is not 64 lowercase hex characters
// with at most one final newline.
var ErrKeyFormat = errors.New("baseline key is not 64 lowercase hex characters")

// ParseKey decodes the content of COMPLIANCETF_BASELINE_KEY_FILE as the
// provider does: exactly 64 lowercase hex characters and an optional final
// "\n". The file's ownership and mode checks are the caller's.
func ParseKey(text []byte) ([32]byte, error) {
	var k [32]byte
	s := strings.TrimSuffix(string(text), "\n")
	if len(s) != 64 || strings.Trim(s, "0123456789abcdef") != "" {
		return k, ErrKeyFormat
	}
	if _, err := hex.Decode(k[:], []byte(s)); err != nil {
		return k, ErrKeyFormat
	}
	return k, nil
}

// Digest is the read_digest of value, typed by schema (an object type), for
// reads, dot-separated attribute paths. Value trees hold what instancekey
// trees hold: nil, string, json.Number, bool, []any, map[string]any and
// instancekey.Unknown.
//
// A path step goes into an object attribute only; a null on the way ends
// the path at null. It is an error, and the instance is never
// grandfathered, when a read value is wholly or partly unknown, a step
// meets a value that is not an object or an attribute the schema does not
// declare, or a read value holds a dynamic type. The provider hashes a
// dynamic value by its runtime type, which plan JSON does not carry, so
// ctfkit refuses it.
func Digest(key [32]byte, reads []string, schema *instancekey.Type, value any) (string, error) {
	k, err := hkdf.Key(sha256.New, key[:], nil, info, 32)
	if err != nil {
		return "", err
	}
	leaf := [32]byte(k)
	o := make(map[string]any, len(reads))
	for _, r := range reads {
		v, t, werr := walk(value, schema, strings.Split(r, "."))
		if werr == nil {
			o[r], werr = hashTree(leaf, v, t)
		}
		if werr != nil {
			return "", fmt.Errorf("read %s: %w", r, werr)
		}
	}
	b, err := canonical(o)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// walk follows attribute steps: unknown is an error, null ends the path,
// anything but an object is an error.
func walk(v any, t *instancekey.Type, steps []string) (any, *instancekey.Type, error) {
	for _, s := range steps {
		if _, ok := v.(instancekey.Unknown); ok {
			return nil, nil, errors.New("unknown value")
		}
		if v == nil {
			return nil, nil, nil
		}
		m, ok := v.(map[string]any)
		if t == nil || t.Kind != instancekey.Object || !ok {
			return nil, nil, fmt.Errorf("step %q into a value that is not an object", s)
		}
		at, ok := t.Attrs[s]
		if !ok {
			return nil, nil, fmt.Errorf("attribute %q not in schema", s)
		}
		v, t = m[s], at
	}
	return v, t, nil
}

// hashTree is H_b(v) under type t.
func hashTree(leaf [32]byte, v any, t *instancekey.Type) (any, error) {
	if _, ok := v.(instancekey.Unknown); ok {
		return nil, errors.New("unknown value")
	}
	if v == nil {
		return nil, nil
	}
	switch t.Kind {
	case instancekey.String:
		if s, ok := v.(string); ok && utf8.ValidString(s) {
			return instancekey.LeafHash(leaf, 's', s), nil
		}
	case instancekey.Bool:
		if b, ok := v.(bool); ok {
			return instancekey.LeafHash(leaf, 'b', strconv.FormatBool(b)), nil
		}
	case instancekey.Number:
		if n, ok := v.(json.Number); ok {
			text, err := instancekey.NumberText(n.String())
			if err != nil {
				return nil, err
			}
			return instancekey.LeafHash(leaf, 'n', text), nil
		}
	case instancekey.Object, instancekey.Map:
		return objectTree(leaf, v, t)
	case instancekey.List, instancekey.Set, instancekey.Tuple:
		return seqTree(leaf, v, t)
	case instancekey.Dynamic:
		return nil, errors.New("dynamic value")
	}
	return nil, fmt.Errorf("value %T does not match its type", v)
}

func objectTree(leaf [32]byte, v any, t *instancekey.Type) (any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("expected an object or map")
	}
	out := make(map[string]any, len(m))
	for name, e := range m {
		et := t.Elem
		if t.Kind == instancekey.Object {
			if et, ok = t.Attrs[name]; !ok {
				return nil, fmt.Errorf("attribute %q not in schema", name)
			}
		}
		h, err := hashTree(leaf, e, et)
		if err != nil {
			return nil, err
		}
		out[name] = h
	}
	if t.Kind == instancekey.Object {
		for name := range t.Attrs {
			if _, ok := m[name]; !ok {
				out[name] = nil // a tftypes object carries every attribute
			}
		}
	}
	return out, nil
}

func seqTree(leaf [32]byte, v any, t *instancekey.Type) (any, error) {
	elems, ok := v.([]any)
	if !ok || t.Kind == instancekey.Tuple && len(elems) != len(t.Elems) {
		return nil, errors.New("expected an array of the type's shape")
	}
	out := make([]any, len(elems))
	keys := make([][]byte, len(elems))
	for i, e := range elems {
		et := t.Elem
		if t.Kind == instancekey.Tuple {
			et = t.Elems[i]
		}
		h, err := hashTree(leaf, e, et)
		if err != nil {
			return nil, err
		}
		if out[i] = h; t.Kind == instancekey.Set {
			if keys[i], err = canonical(h); err != nil {
				return nil, err
			}
		}
	}
	if t.Kind != instancekey.Set {
		return out, nil
	}
	idx := make([]int, len(out))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int { return bytes.Compare(keys[a], keys[b]) })
	sorted := make([]any, len(out))
	for i, j := range idx {
		sorted[i] = out[j]
	}
	return sorted, nil
}

// canonical is the RFC 8785 form of a hashed tree.
func canonical(tree any) ([]byte, error) {
	b, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}
