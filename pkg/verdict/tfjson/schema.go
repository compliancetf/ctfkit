package tfjson

import (
	"errors"
	"fmt"

	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
)

// Schemas is the output of terraform providers schema -json, read strictly.
// A resource type is lowered to an instancekey.Type when an instance needs
// it, so a schema the format cannot read refuses only that type's instances.
type Schemas struct {
	providers map[string]any
}

// ParseSchemas reads terraform providers schema -json bytes.
func ParseSchemas(raw []byte) (*Schemas, error) {
	doc, err := decodeStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("provider schema: %w", err)
	}
	m, _ := doc.(map[string]any)
	ps, ok := m["provider_schemas"].(map[string]any)
	if !ok {
		return nil, errors.New("provider schema: no provider_schemas object")
	}
	return &Schemas{providers: ps}, nil
}

// resource is the type of a resource and of its identity (nil when the type
// has no identity schema).
func (s *Schemas) resource(provider, typ string) (res, ident *instancekey.Type, err error) {
	p, _ := s.providers[provider].(map[string]any)
	rs, _ := p["resource_schemas"].(map[string]any)
	r, ok := rs[typ].(map[string]any)
	if !ok {
		return nil, nil, errors.New("schema has no entry for this provider and type")
	}
	if res, err = blockType(r["block"]); err != nil {
		return nil, nil, err
	}
	ids, _ := p["resource_identity_schemas"].(map[string]any)
	if id, ok := ids[typ]; ok && id != nil {
		im, ok := id.(map[string]any)
		if !ok {
			return nil, nil, errors.New("identity schema is not an object")
		}
		if ident, err = attrsType(im["attributes"]); err != nil {
			return nil, nil, fmt.Errorf("identity schema: %w", err)
		}
	}
	return res, ident, nil
}

// blockType lowers a schema block: attributes by their type or nested_type,
// block_types by nesting_mode.
func blockType(b any) (*instancekey.Type, error) {
	bm, ok := b.(map[string]any)
	if !ok {
		return nil, errors.New("schema block is not an object")
	}
	obj, err := attrsType(bm["attributes"])
	if err != nil {
		return nil, err
	}
	bts, _ := bm["block_types"].(map[string]any)
	for name, bt := range bts {
		btm, _ := bt.(map[string]any)
		inner, err := blockType(btm["block"])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if obj.Attrs[name], err = nest(btm["nesting_mode"], inner); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return obj, nil
}

// attrsType is the object type of an attributes map (absent: no attributes).
func attrsType(attrs any) (*instancekey.Type, error) {
	obj := &instancekey.Type{Kind: instancekey.Object, Attrs: map[string]*instancekey.Type{}}
	am, ok := attrs.(map[string]any)
	if attrs != nil && !ok {
		return nil, errors.New("schema attributes is not an object")
	}
	for name, a := range am {
		t, err := attrType(a)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		obj.Attrs[name] = t
	}
	return obj, nil
}

func attrType(a any) (*instancekey.Type, error) {
	m, ok := a.(map[string]any)
	if !ok {
		return nil, errors.New("schema attribute is not an object")
	}
	nt, ok := m["nested_type"].(map[string]any)
	if !ok {
		return ctyType(m["type"])
	}
	inner, err := attrsType(nt["attributes"])
	if err != nil {
		return nil, err
	}
	mode, ok := nt["nesting_mode"]
	if !ok {
		mode = "single"
	}
	return nest(mode, inner)
}

func nest(mode any, o *instancekey.Type) (*instancekey.Type, error) {
	switch mode {
	case "single", "group":
		return o, nil
	case "list":
		return &instancekey.Type{Kind: instancekey.List, Elem: o}, nil
	case "set":
		return &instancekey.Type{Kind: instancekey.Set, Elem: o}, nil
	case "map":
		return &instancekey.Type{Kind: instancekey.Map, Elem: o}, nil
	}
	return nil, fmt.Errorf("unknown nesting_mode %v", mode)
}

var primitives = map[string]instancekey.Kind{
	"string": instancekey.String, "number": instancekey.Number,
	"bool": instancekey.Bool, "dynamic": instancekey.Dynamic,
}

// ctyType reads the cty JSON type syntax.
func ctyType(j any) (*instancekey.Type, error) {
	if s, ok := j.(string); ok {
		if k := primitives[s]; k != 0 {
			return &instancekey.Type{Kind: k}, nil
		}
		return nil, fmt.Errorf("unknown schema type %q", s)
	}
	a, ok := j.([]any)
	if !ok || len(a) != 2 {
		return nil, fmt.Errorf("unknown schema type %v", j)
	}
	switch a[0] {
	case "list", "set", "map":
		elem, err := ctyType(a[1])
		if err != nil {
			return nil, err
		}
		kind := map[any]instancekey.Kind{"list": instancekey.List, "set": instancekey.Set, "map": instancekey.Map}[a[0]]
		return &instancekey.Type{Kind: kind, Elem: elem}, nil
	case "object":
		attrs, ok := a[1].(map[string]any)
		if !ok {
			return nil, errors.New("object type without attributes")
		}
		o := &instancekey.Type{Kind: instancekey.Object, Attrs: map[string]*instancekey.Type{}}
		for n, at := range attrs {
			t, err := ctyType(at)
			if err != nil {
				return nil, err
			}
			o.Attrs[n] = t
		}
		return o, nil
	case "tuple":
		elems, ok := a[1].([]any)
		if !ok {
			return nil, errors.New("tuple type without elements")
		}
		tu := &instancekey.Type{Kind: instancekey.Tuple, Elems: []*instancekey.Type{}}
		for _, e := range elems {
			t, err := ctyType(e)
			if err != nil {
				return nil, err
			}
			tu.Elems = append(tu.Elems, t)
		}
		return tu, nil
	}
	return nil, fmt.Errorf("unknown schema type %v", j)
}
