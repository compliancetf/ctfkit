// Package tfvalue is the provider-side adapter of the instance key
// (../testdata/instancekey/FORMAT.md): it turns an apply PlannedState
// (tftypes.Value) and the plan envelope's prior identity into the schema
// type, value tree and prior identity that instancekey.Compute hashes. The
// tfjson adapter builds the same trees from plan JSON.
package tfvalue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
)

// Prior identity kinds, as the envelope's prior_identity_kind names them.
const (
	KindIdentity = "identity"
	KindID       = "id"
	KindNone     = "none"
)

// Key is the instance key of typ under form: planned is the apply
// PlannedState (ignored for delete), unknown the verdict entry's
// unknown_paths and prior the tree Prior returns.
func Key(leaf [32]byte, typ string, form instancekey.Form, planned tftypes.Value, unknown [][]string, prior any) (string, error) {
	if form == instancekey.FormDelete {
		return instancekey.Compute(leaf, typ, form, nil, nil, unknown, prior)
	}
	schema, after, err := Planned(planned)
	if err != nil {
		return "", err
	}
	return instancekey.Compute(leaf, typ, form, schema, after, unknown, prior)
}

// Planned is the schema type and value tree of v. The schema is v's declared
// type, whose dynamic positions keep DynamicPseudoType; the tree holds nil
// for null, instancekey.Unknown for unknown and numbers as decimal text.
func Planned(v tftypes.Value) (*instancekey.Type, any, error) {
	schema, err := typeOf(v.Type())
	if err != nil {
		return nil, nil, err
	}
	tree, err := valueOf(v)
	if err != nil {
		return nil, nil, err
	}
	return schema, tree, nil
}

// Prior is the prior identity tree of the envelope's prior_identity_kind:
// nil for none (create), the envelope's prior_identity object for identity,
// {"id": <prior state id>} for id. prior is the request's PriorState.
func Prior(kind string, identity json.RawMessage, prior tftypes.Value) (any, error) {
	switch kind {
	case KindNone:
		return nil, nil
	case KindIdentity:
		return decodeObject(identity)
	case KindID:
		var attrs map[string]tftypes.Value
		var id string
		if !prior.IsKnown() || prior.IsNull() || prior.As(&attrs) != nil {
			return nil, errors.New("prior state is not a known object")
		}
		if a, ok := attrs["id"]; !ok || !a.IsKnown() || a.IsNull() || a.As(&id) != nil || id == "" {
			return nil, errors.New("prior state has no non-empty string id")
		}
		return map[string]any{"id": id}, nil
	}
	return nil, fmt.Errorf("unknown prior_identity_kind %q", kind)
}

func typeOf(t tftypes.Type) (*instancekey.Type, error) {
	var err error
	elem := func(e tftypes.Type, k instancekey.Kind) (*instancekey.Type, error) {
		out := &instancekey.Type{Kind: k}
		out.Elem, err = typeOf(e)
		return out, err
	}
	switch t := t.(type) {
	case tftypes.Object:
		out := &instancekey.Type{Kind: instancekey.Object, Attrs: make(map[string]*instancekey.Type, len(t.AttributeTypes))}
		for name, at := range t.AttributeTypes {
			if out.Attrs[name], err = typeOf(at); err != nil {
				return nil, err
			}
		}
		return out, nil
	case tftypes.List:
		return elem(t.ElementType, instancekey.List)
	case tftypes.Set:
		return elem(t.ElementType, instancekey.Set)
	case tftypes.Map:
		return elem(t.ElementType, instancekey.Map)
	case tftypes.Tuple:
		out := &instancekey.Type{Kind: instancekey.Tuple, Elems: make([]*instancekey.Type, len(t.ElementTypes))}
		for i, et := range t.ElementTypes {
			if out.Elems[i], err = typeOf(et); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	for _, p := range []struct {
		t tftypes.Type
		k instancekey.Kind
	}{{tftypes.String, instancekey.String}, {tftypes.Number, instancekey.Number}, {tftypes.Bool, instancekey.Bool}, {tftypes.DynamicPseudoType, instancekey.Dynamic}} {
		if t != nil && t.Is(p.t) {
			return &instancekey.Type{Kind: p.k}, nil
		}
	}
	return nil, fmt.Errorf("unsupported type %v", t)
}

// valueOf walks v by its own type: at a dynamic position that is the
// concrete type, which Compute omits by the declared one.
func valueOf(v tftypes.Value) (any, error) {
	if !v.IsKnown() {
		return instancekey.Unknown{}, nil
	}
	if v.IsNull() {
		return nil, nil
	}
	switch v.Type().(type) {
	case tftypes.Object, tftypes.Map:
		var m map[string]tftypes.Value
		if err := v.As(&m); err != nil {
			return nil, err
		}
		out := make(map[string]any, len(m))
		for k, e := range m {
			n, err := valueOf(e)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = n
		}
		return out, nil
	case tftypes.List, tftypes.Set, tftypes.Tuple:
		var elems []tftypes.Value
		if err := v.As(&elems); err != nil {
			return nil, err
		}
		out := make([]any, len(elems))
		for i, e := range elems {
			n, err := valueOf(e)
			if err != nil {
				return nil, fmt.Errorf("%d: %w", i, err)
			}
			out[i] = n
		}
		return out, nil
	}
	switch t := v.Type(); {
	case t.Is(tftypes.String):
		var s string
		err := v.As(&s)
		return s, err
	case t.Is(tftypes.Bool):
		var b bool
		err := v.As(&b)
		return b, err
	case t.Is(tftypes.Number):
		f := new(big.Float)
		if err := v.As(&f); err != nil {
			return nil, err
		}
		// The 512-bit value as shortest decimal text, which Compute canonicalizes
		// (FORMAT.md Numbers); the provider writes the same text. An infinity
		// becomes "+Inf", which Compute refuses unless the declared type omits
		// it at a dynamic position, as the provider does.
		return json.Number(new(big.Float).SetPrec(512).SetMode(big.ToNearestEven).Set(f).Text('e', -1)), nil
	}
	return nil, fmt.Errorf("unsupported value type %v", v.Type())
}

// decodeObject reads the envelope's prior_identity: one JSON object of valid
// UTF-8 with no duplicate member name at any depth, numbers as decimal text.
// shortcut: an unpaired surrogate escape decodes as U+FFFD; the envelope is
// written by json.Marshal, which never emits one. Check it if another writer
// appears.
func decodeObject(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("prior identity is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, fmt.Errorf("prior identity: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("prior identity has trailing data")
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("prior identity is not an object")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('['):
		list := []any{}
		for dec.More() {
			var e any
			if e, err = decodeValue(dec); err != nil {
				return nil, err
			}
			list = append(list, e)
		}
		_, err = dec.Token()
		return list, err
	case json.Delim('{'):
		obj := map[string]any{}
		for dec.More() {
			var kt json.Token
			if kt, err = dec.Token(); err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok {
				return nil, errors.New("member name is not a string")
			}
			if _, dup := obj[k]; dup {
				return nil, fmt.Errorf("duplicate member %q", k)
			}
			if obj[k], err = decodeValue(dec); err != nil {
				return nil, err
			}
		}
		_, err = dec.Token()
		return obj, err
	}
	return tok, nil
}
