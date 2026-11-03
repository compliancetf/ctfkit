// Package instancekey computes the instance_key of format version 1
// (testdata/instancekey/FORMAT.md, spec B2 and B3): the one canonicalizer
// that ctfkit gate (plan JSON) and the terraform provider (apply
// PlannedState) share. An adapter builds a schema-typed value tree; Compute
// validates it, masks the unknown paths, hashes every leaf with the per-run
// leaf key and returns the key.
package instancekey

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// Form is the key form, chosen from the plan action (FORMAT.md Forms).
type Form string

const (
	FormCreate Form = "create"
	FormUpdate Form = "update"
	FormDelete Form = "delete"
)

// Kind is the kind of a schema type node.
type Kind uint8

const (
	String Kind = iota + 1
	Number
	Bool
	Dynamic // DynamicPseudoType
	List
	Set
	Map
	Object // object types and single or group nesting
	Tuple
)

// Type is a schema type: Elem for List, Set and Map, Attrs for Object, Elems
// for Tuple.
type Type struct {
	Kind  Kind
	Elem  *Type
	Attrs map[string]*Type
	Elems []*Type
}

// Unknown marks a value that is unknown in the tree an adapter passes in. An
// unknown must lie under one of the unknown paths; an unknown inside a set
// makes the whole set unknown.
type Unknown struct{}

const keyDomain = "compliancetf.instance_key/v1"

var reIndex = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)

// Compute is the instance key of resource type typ under form.
//
// after is the planned value typed by schema (an object; nil for delete).
// Value trees hold nil (JSON null), string, json.Number (decimal text), bool,
// []any (list, set, tuple), map[string]any (object, map) and Unknown.
// unknown is the entry's normalized unknown_paths (empty for delete). prior is
// nil for create, else the prior identity object: the identity for kind
// identity, {"id": id} for kind id.
func Compute(leaf [32]byte, typ string, form Form, schema *Type, after any, unknown [][]string, prior any) (string, error) {
	var afterJCS, priorJCS []byte
	var err error
	switch form {
	case FormCreate, FormUpdate:
		if afterJCS, err = afterTree(leaf, schema, after, unknown); err != nil {
			return "", err
		}
	case FormDelete:
		if after != nil || len(unknown) != 0 {
			return "", errors.New("a delete key has no planned value and no unknown paths")
		}
		afterJCS = []byte("null")
	default:
		return "", fmt.Errorf("unknown form %q", form)
	}
	if form == FormCreate {
		if prior != nil {
			return "", errors.New("a create key has no prior identity")
		}
		priorJCS = []byte("null")
	} else if priorJCS, err = priorTree(leaf, prior); err != nil {
		return "", err
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte(keyDomain), []byte(typ), []byte(form), afterJCS} {
		h.Write(part)
		h.Write([]byte{0})
	}
	h.Write(priorJCS)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// afterTree is JCS(H(after_masked)): the whole value is validated before the
// paths, and each path against the schema alone, before any masking.
func afterTree(leaf [32]byte, schema *Type, after any, unknown [][]string) ([]byte, error) {
	if schema == nil || schema.Kind != Object {
		return nil, errors.New("schema is not an object type")
	}
	if _, ok := after.(Unknown); ok {
		return nil, errors.New("whole planned value unknown")
	}
	if _, ok := after.(map[string]any); !ok {
		return nil, errors.New("planned value is not an object")
	}
	tree, err := valueTree(leaf, after, schema)
	if err != nil {
		return nil, err
	}
	for _, p := range unknown {
		if err := checkPath(schema, p); err != nil {
			return nil, err
		}
	}
	for _, p := range unknown {
		tree = mask(tree, p)
	}
	if hasUnknown(tree) {
		return nil, errors.New("an unknown value lies outside the unknown paths")
	}
	return canonical(tree)
}

// dynamicBearing reports whether t is dynamic, or a list, set, map or tuple
// holding a dynamic-bearing type; an object type never is.
func dynamicBearing(t *Type) bool {
	switch t.Kind {
	case Dynamic:
		return true
	case List, Set, Map:
		return dynamicBearing(t.Elem)
	case Tuple:
		return slices.ContainsFunc(t.Elems, dynamicBearing)
	}
	return false
}

// valueTree is v hashed: leaves become leaf hashes, nil stays nil, Unknown
// stays Unknown, set elements are sorted by the JCS of their hashed form.
func valueTree(leaf [32]byte, v any, t *Type) (any, error) {
	switch v.(type) {
	case nil, Unknown:
		return v, nil
	}
	switch t.Kind {
	case Object:
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("expected an object")
		}
		out := make(map[string]any, len(m))
		for name, e := range m {
			at, ok := t.Attrs[name]
			if !ok {
				return nil, fmt.Errorf("attribute %q not in schema", name)
			}
			if dynamicBearing(at) {
				continue
			}
			n, err := valueTree(leaf, e, at)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if n != nil {
				out[name] = n
			}
		}
		return out, nil
	case Map:
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("expected a map")
		}
		out := make(map[string]any, len(m))
		for k, e := range m {
			if !utf8.ValidString(k) {
				return nil, errors.New("map key is not valid UTF-8")
			}
			n, err := valueTree(leaf, e, t.Elem)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			if n != nil {
				out[k] = n
			}
		}
		return out, nil
	case List, Set, Tuple:
		return seqTree(leaf, v, t)
	}
	return leafOf(leaf, v, t.Kind)
}

func seqTree(leaf [32]byte, v any, t *Type) (any, error) {
	elems, ok := v.([]any)
	if !ok {
		return nil, errors.New("expected an array")
	}
	if t.Kind == Tuple && len(t.Elems) != len(elems) {
		return nil, errors.New("tuple arity differs from its type")
	}
	out := make([]any, len(elems))
	for i, e := range elems {
		et := t.Elem
		if t.Kind == Tuple {
			et = t.Elems[i]
		}
		n, err := valueTree(leaf, e, et)
		if err != nil {
			return nil, fmt.Errorf("%d: %w", i, err)
		}
		out[i] = n
	}
	if t.Kind != Set {
		return out, nil
	}
	if hasUnknown(out) {
		return Unknown{}, nil // an unknown inside a set masks the whole set
	}
	keys := make(map[int][]byte, len(out))
	idx := make([]int, len(out))
	for i, e := range out {
		b, err := canonical(e)
		if err != nil {
			return nil, err
		}
		keys[i], idx[i] = b, i
	}
	slices.SortStableFunc(idx, func(a, b int) int { return bytes.Compare(keys[a], keys[b]) })
	sorted := make([]any, len(out))
	for i, j := range idx {
		sorted[i] = out[j]
	}
	return sorted, nil
}

func leafOf(leaf [32]byte, v any, kind Kind) (any, error) {
	switch kind {
	case String:
		if s, ok := v.(string); ok {
			if !utf8.ValidString(s) {
				return nil, errors.New("string is not valid UTF-8")
			}
			return leafHash(leaf, 's', s), nil
		}
		return nil, errors.New("expected string")
	case Bool:
		if b, ok := v.(bool); ok {
			return leafHash(leaf, 'b', strconv.FormatBool(b)), nil
		}
		return nil, errors.New("expected bool")
	case Number:
		if n, ok := v.(json.Number); ok {
			text, err := numberText(n.String())
			if err != nil {
				return nil, err
			}
			return leafHash(leaf, 'n', text), nil
		}
		return nil, errors.New("expected number")
	}
	return nil, fmt.Errorf("unsupported schema kind %d", kind)
}

func leafHash(leaf [32]byte, tag byte, text string) string {
	m := hmac.New(sha256.New, leaf[:])
	m.Write([]byte{tag, 0})
	m.Write([]byte(text))
	return hex.EncodeToString(m.Sum(nil))
}

// checkPath validates one unknown path against the schema alone: attribute
// and map-key steps, list and tuple indices; a step into a set or a path
// into a dynamic-bearing value is an error.
func checkPath(t *Type, path []string) error {
	if len(path) == 0 {
		return errors.New("empty unknown path")
	}
	for _, step := range path {
		switch t.Kind {
		case Object:
			at, ok := t.Attrs[step]
			if !ok {
				return fmt.Errorf("unknown path step %q is not a declared attribute", step)
			}
			t = at
		case Map:
			t = t.Elem
		case List:
			if !reIndex.MatchString(step) {
				return fmt.Errorf("unknown path step %q is not a list index", step)
			}
			t = t.Elem
		case Tuple:
			i, err := strconv.Atoi(step)
			if !reIndex.MatchString(step) || err != nil || i >= len(t.Elems) {
				return fmt.Errorf("unknown path step %q is not a tuple index", step)
			}
			t = t.Elems[i]
		default:
			return fmt.Errorf("unknown path step %q cannot be read", step)
		}
		if dynamicBearing(t) {
			return errors.New("unknown path into a dynamic value")
		}
	}
	return nil
}

// mask applies one validated path: the last step removes an attribute or map
// key, or nulls a list element; a path that does not resolve is a no-op.
func mask(tree any, path []string) any {
	switch n := tree.(type) {
	case map[string]any:
		c, ok := n[path[0]]
		switch {
		case !ok:
		case len(path) == 1:
			delete(n, path[0])
		default:
			n[path[0]] = mask(c, path[1:])
		}
	case []any:
		i, err := strconv.Atoi(path[0])
		switch {
		case err != nil || i < 0 || i >= len(n):
		case len(path) == 1:
			n[i] = nil
		default:
			n[i] = mask(n[i], path[1:])
		}
	}
	return tree
}

func hasUnknown(tree any) bool {
	switch n := tree.(type) {
	case Unknown:
		return true
	case map[string]any:
		for _, c := range n {
			if hasUnknown(c) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(n, hasUnknown)
	}
	return false
}

// priorTree is JCS(H(prior)) of the prior identity object: arrays are lists
// (an identity schema has no sets), null object members are omitted, and
// the object must keep at least one leaf.
func priorTree(leaf [32]byte, prior any) ([]byte, error) {
	if _, ok := prior.(map[string]any); !ok {
		return nil, errors.New("prior identity is not an object")
	}
	tree, err := jsonTree(leaf, prior)
	if err != nil {
		return nil, err
	}
	if !hasLeaf(tree) {
		return nil, errors.New("prior identity has no leaf")
	}
	return canonical(tree)
}

func jsonTree(leaf [32]byte, v any) (any, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case string:
		return leafOf(leaf, v, String)
	case bool:
		return leafOf(leaf, v, Bool)
	case json.Number:
		return leafOf(leaf, v, Number)
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			n, err := jsonTree(leaf, e)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			if !utf8.ValidString(k) {
				return nil, errors.New("prior identity key is not valid UTF-8")
			}
			n, err := jsonTree(leaf, e)
			if err != nil {
				return nil, err
			}
			if n != nil {
				out[k] = n
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("prior identity holds %T", v) // Unknown included
}

func hasLeaf(tree any) bool {
	switch n := tree.(type) {
	case string:
		return true
	case map[string]any:
		for _, c := range n {
			if hasLeaf(c) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(n, hasLeaf)
	}
	return false
}

// canonical is the RFC 8785 form of a hashed tree (strings, null, arrays and
// objects only); jcs.Transform undoes the HTML escaping of encoding/json.
func canonical(tree any) ([]byte, error) {
	b, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// LeafHash is a leaf of the keyed value tree: hex(HMAC-SHA256(key, tag ||
// 0x00 || text)), tag 's', 'n' or 'b'; readdigest shares it.
func LeafHash(key [32]byte, tag byte, text string) string { return leafHash(key, tag, text) }
