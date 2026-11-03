package tfvalue

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
)

// The frozen goldens (../testdata/instancekey) from the msgpack side: each
// planned value is built from plan.json "after" and "after_unknown" with the
// schema.json type and sent through msgpack like Core's PlannedState; the
// prior state likewise from "before". The envelope carries the golden
// prior_identity_kind and, for kind identity, "before_identity". Deriving
// unknown_paths and the kind from plan JSON is the tfjson adapter's job.

const goldenDir = "../testdata/instancekey"

type golden struct {
	Error   string `json:"error"`
	Entries []struct {
		Address string `json:"address"`
		Deposed string `json:"deposed"`
		Error   string `json:"error"`
		Keys    []struct {
			Form              instancekey.Form `json:"form"`
			Key               string           `json:"key"`
			PriorIdentityKind string           `json:"prior_identity_kind"`
			UnknownPaths      [][]string       `json:"unknown_paths"`
		} `json:"keys"`
	} `json:"entries"`
	KLeafHex string `json:"k_leaf_hex"`
}

type planChange struct {
	Address string `json:"address"`
	Deposed string `json:"deposed"`
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Change  struct {
		Actions        []string `json:"actions"`
		After          any      `json:"after"`
		AfterUnknown   any      `json:"after_unknown"`
		Before         any      `json:"before"`
		BeforeIdentity any      `json:"before_identity"`
	} `json:"change"`
}

// msgpackRefusals are the _edge refusals that have a tftypes form; the
// others (wrong JSON kinds, malformed after_unknown, plan action rules,
// missing schema) cannot reach the provider as a PlannedState.
var msgpackRefusals = map[string]bool{
	"edge_thing.allunknown": true, "edge_thing.bigexp": true, "edge_thing.smallexp": true,
	"edge_thing.longnum": true, "edge_thing.noid": true, "edge_thing.emptyid": true,
}

func decodeFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func testLeaf(t *testing.T) [32]byte {
	t.Helper()
	l, err := hkdf.Key(sha256.New, []byte("INSECURE-TEST-SECRET-instancekey"), nil, "compliancetf.verdict/v1 leaf", 32)
	if err != nil {
		t.Fatal(err)
	}
	return [32]byte(l)
}

func TestGoldens(t *testing.T) {
	leaf := testLeaf(t)
	dirs, err := filepath.Glob(filepath.Join(goldenDir, "*", "expected.json"))
	if err != nil || len(dirs) != 23 {
		t.Fatalf("goldens: %d dirs, %v", len(dirs), err)
	}
	keys, refused := 0, 0
	for _, exp := range dirs {
		dir := filepath.Dir(exp)
		var g golden
		decodeFile(t, exp, &g)
		if g.Error != "" {
			continue // plan JSON parsing cases (_edge_dupkey, _edge_surrogate)
		}
		if g.KLeafHex != hex.EncodeToString(leaf[:]) {
			t.Fatalf("%s: k_leaf differs", dir)
		}
		var plan struct {
			ResourceChanges []planChange `json:"resource_changes"`
		}
		decodeFile(t, filepath.Join(dir, "plan.json"), &plan)
		types := schemaTypes(t, filepath.Join(dir, "schema.json"))
		var changes []planChange
		for _, rc := range plan.ResourceChanges {
			a := rc.Change.Actions
			noop := len(a) == 1 && (a[0] == "no-op" || a[0] == "read")
			if rc.Mode == "managed" && (!noop || rc.Deposed != "") {
				changes = append(changes, rc)
			}
		}
		if len(changes) != len(g.Entries) {
			t.Fatalf("%s: %d managed changes, %d entries", dir, len(changes), len(g.Entries))
		}
		for i, e := range g.Entries {
			rc := changes[i]
			typ := types[rc.Type]
			if e.Error != "" {
				if !msgpackRefusals[e.Address] {
					continue
				}
				form, kind := instancekey.Form(rc.Change.Actions[0]), KindID
				if form == instancekey.FormCreate {
					kind = KindNone
				}
				if _, err := key(t, leaf, rc, typ, form, kind, nil); err == nil {
					t.Errorf("%s: key computed, want refusal (%s)", e.Address, e.Error)
				}
				refused++
				continue
			}
			for _, k := range e.Keys {
				got, err := key(t, leaf, rc, typ, k.Form, k.PriorIdentityKind, k.UnknownPaths)
				if err != nil {
					t.Errorf("%s %s %s: %v", e.Address, e.Deposed, k.Form, err)
				} else if got != k.Key {
					t.Errorf("%s %s %s: key %s, want %s", e.Address, e.Deposed, k.Form, got, k.Key)
				}
				keys++
			}
		}
	}
	t.Logf("%d keys, %d refusals", keys, refused)
	if keys < 40 || refused != len(msgpackRefusals) {
		t.Fatalf("checked %d keys and %d refusals", keys, refused)
	}
}

// key builds the PlannedState, the prior state and the envelope of rc and
// computes the key the way the provider does at apply.
func key(t *testing.T, leaf [32]byte, rc planChange, typ tftypes.Type, form instancekey.Form, kind string, unknown [][]string) (string, error) {
	planned := tftypes.NewValue(typ, nil)
	if form != instancekey.FormDelete {
		planned = roundTrip(t, typ, build(t, typ, rc.Change.After, rc.Change.AfterUnknown))
	}
	var identity json.RawMessage
	if kind == KindIdentity {
		identity, _ = json.Marshal(rc.Change.BeforeIdentity)
	}
	priorState := tftypes.NewValue(typ, nil)
	if rc.Change.Before != nil {
		priorState = roundTrip(t, typ, build(t, typ, rc.Change.Before, nil))
	}
	prior, err := Prior(kind, identity, priorState)
	if err != nil {
		return "", err
	}
	return Key(leaf, rc.Type, form, planned, unknown, prior)
}

// schemaTypes are the resource types of a terraform providers schema -json file.
func schemaTypes(t *testing.T, path string) map[string]tftypes.Type {
	var schema struct {
		ProviderSchemas map[string]struct {
			Resources map[string]struct {
				Block json.RawMessage `json:"block"`
			} `json:"resource_schemas"`
		} `json:"provider_schemas"`
	}
	decodeFile(t, path, &schema)
	out := map[string]tftypes.Type{}
	for _, ps := range schema.ProviderSchemas {
		for name, r := range ps.Resources {
			out[name] = blockType(t, r.Block)
		}
	}
	return out
}

func blockType(t *testing.T, raw json.RawMessage) tftypes.Type {
	t.Helper()
	var b struct {
		Attributes map[string]struct {
			Type   json.RawMessage `json:"type"`
			Nested *struct {
				Attributes  json.RawMessage `json:"attributes"`
				NestingMode string          `json:"nesting_mode"`
			} `json:"nested_type"`
		} `json:"attributes"`
		BlockTypes map[string]struct {
			Block       json.RawMessage `json:"block"`
			NestingMode string          `json:"nesting_mode"`
		} `json:"block_types"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]tftypes.Type{}
	for n, a := range b.Attributes {
		if a.Nested != nil {
			inner, _ := json.Marshal(map[string]json.RawMessage{"attributes": a.Nested.Attributes})
			attrs[n] = nest(a.Nested.NestingMode, blockType(t, inner))
			continue
		}
		at, err := tftypes.ParseJSONType(a.Type) //nolint:staticcheck // the cty JSON type syntax of the schema file
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		attrs[n] = at
	}
	for n, bt := range b.BlockTypes {
		attrs[n] = nest(bt.NestingMode, blockType(t, bt.Block))
	}
	return tftypes.Object{AttributeTypes: attrs}
}

func nest(mode string, o tftypes.Type) tftypes.Type {
	switch mode {
	case "list":
		return tftypes.List{ElementType: o}
	case "set":
		return tftypes.Set{ElementType: o}
	case "map":
		return tftypes.Map{ElementType: o}
	}
	return o // single, group
}

func dynamicBearing(t tftypes.Type) bool {
	switch t := t.(type) {
	case tftypes.List:
		return dynamicBearing(t.ElementType)
	case tftypes.Set:
		return dynamicBearing(t.ElementType)
	case tftypes.Map:
		return dynamicBearing(t.ElementType)
	case tftypes.Tuple:
		for _, e := range t.ElementTypes {
			if dynamicBearing(e) {
				return true
			}
		}
		return false
	}
	return t.Is(tftypes.DynamicPseudoType)
}

// build is the tftypes value of plan JSON j with after_unknown u.
func build(t *testing.T, typ tftypes.Type, j, u any) tftypes.Value {
	t.Helper()
	if u == true {
		return tftypes.NewValue(typ, tftypes.UnknownValue)
	}
	if j == nil || dynamicBearing(typ) && !typ.Is(tftypes.DynamicPseudoType) {
		// The key omits a dynamic-bearing value, and a mixed list of dynamic
		// has no tftypes form.
		return tftypes.NewValue(typ, nil)
	}
	um, _ := u.(map[string]any)
	ul, _ := u.([]any)
	switch tt := typ.(type) {
	case tftypes.Object:
		jm := j.(map[string]any)
		vals := map[string]tftypes.Value{}
		for n, a := range tt.AttributeTypes {
			vals[n] = build(t, a, jm[n], um[n])
		}
		return tftypes.NewValue(tt, vals)
	case tftypes.Map:
		vals := map[string]tftypes.Value{}
		for k, e := range j.(map[string]any) {
			vals[k] = build(t, tt.ElementType, e, um[k])
		}
		return tftypes.NewValue(tt, vals)
	case tftypes.List, tftypes.Set, tftypes.Tuple:
		var vals []tftypes.Value
		for i, e := range j.([]any) {
			var et tftypes.Type
			switch tt := tt.(type) {
			case tftypes.List:
				et = tt.ElementType
			case tftypes.Set:
				et = tt.ElementType
			case tftypes.Tuple:
				et = tt.ElementTypes[i]
			}
			var eu any
			if i < len(ul) {
				eu = ul[i]
			}
			vals = append(vals, build(t, et, e, eu))
		}
		return tftypes.NewValue(tt, vals)
	}
	if typ.Is(tftypes.DynamicPseudoType) {
		return build(t, implied(j), j, u)
	}
	if n, ok := j.(json.Number); ok {
		f, _, err := big.ParseFloat(n.String(), 10, 512, big.ToNearestEven)
		if err != nil {
			f = new(big.Float) // a zero spelling with an exponent beyond big.ParseFloat
		}
		return tftypes.NewValue(typ, f)
	}
	return tftypes.NewValue(typ, j)
}

// implied is the concrete type of a dynamic JSON value (the key omits it).
func implied(j any) tftypes.Type {
	switch j := j.(type) {
	case bool:
		return tftypes.Bool
	case json.Number:
		return tftypes.Number
	case []any:
		var ets []tftypes.Type
		for _, e := range j {
			ets = append(ets, implied(e))
		}
		return tftypes.Tuple{ElementTypes: ets}
	case map[string]any:
		ats := map[string]tftypes.Type{}
		for k, e := range j {
			ats[k] = implied(e)
		}
		return tftypes.Object{AttributeTypes: ats}
	}
	return tftypes.String
}

// roundTrip sends v through msgpack like Core's PlannedState and PriorState.
func roundTrip(t *testing.T, typ tftypes.Type, v tftypes.Value) tftypes.Value {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(typ, v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := dv.Unmarshal(typ)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRefusals: inputs with a tftypes form that get no key, so nothing
// matches and a required change blocks.
func TestRefusals(t *testing.T) {
	var leaf [32]byte
	setT := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"st": tftypes.Set{ElementType: tftypes.String}, "n": tftypes.Number, "id": tftypes.String}}
	val := func(st, n tftypes.Value) tftypes.Value {
		return tftypes.NewValue(setT, map[string]tftypes.Value{"st": st, "n": n, "id": tftypes.NewValue(tftypes.String, "i-1")})
	}
	strs := tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{tftypes.NewValue(tftypes.String, "a")})
	num := func(f *big.Float) tftypes.Value { return tftypes.NewValue(tftypes.Number, f) }
	one := big.NewFloat(1)
	unknownSet := tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{tftypes.NewValue(tftypes.String, tftypes.UnknownValue)})
	for name, tc := range map[string]struct {
		v       tftypes.Value
		unknown [][]string
	}{
		"unknown outside paths": {val(unknownSet, num(one)), nil},
		"step into a set":       {val(unknownSet, num(one)), [][]string{{"st", "0"}}},
		"undeclared path":       {val(strs, num(one)), [][]string{{"bogus"}}},
		"infinite number":       {val(strs, num(new(big.Float).SetInf(false))), nil},
		"whole value unknown":   {tftypes.NewValue(setT, tftypes.UnknownValue), nil},
		"null planned value":    {tftypes.NewValue(setT, nil), nil},
		"not an object":         {strs, nil},
	} {
		if _, err := Key(leaf, "edge_thing", instancekey.FormCreate, tc.v, tc.unknown, nil); err == nil {
			t.Errorf("%s: key computed", name)
		}
	}
	if _, err := Key(leaf, "edge_thing", instancekey.FormCreate, val(unknownSet, num(one)), [][]string{{"st"}}, nil); err != nil {
		t.Errorf("masked set: %v", err)
	}
	// The key omits a dynamic attribute, so an infinity there keys like its
	// absence, as in the provider, which never visits it.
	dynT := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"s": tftypes.String, "d": tftypes.DynamicPseudoType}}
	s := tftypes.NewValue(tftypes.String, "x")
	inf, err := Key(leaf, "edge_thing", instancekey.FormCreate, tftypes.NewValue(dynT, map[string]tftypes.Value{"s": s, "d": num(new(big.Float).SetInf(false))}), nil, nil)
	if want, _ := Key(leaf, "edge_thing", instancekey.FormCreate, tftypes.NewValue(dynT, map[string]tftypes.Value{"s": s, "d": tftypes.NewValue(tftypes.DynamicPseudoType, nil)}), nil, nil); err != nil || inf != want {
		t.Errorf("infinity at a dynamic position: key %q, %v; want %q", inf, err, want)
	}
	for name, identity := range map[string]string{
		"no leaf": `{"arn":null}`, "not object": `"x"`, "duplicate": `{"id":"a","id":"b"}`,
		"nested duplicate": `{"a":{"b":"1","b":"2"}}`, "trailing": `{"id":"a"} {}`, "invalid UTF-8": "{\"id\":\"\xff\"}", "empty": ``,
	} {
		prior, err := Prior(KindIdentity, json.RawMessage(identity), tftypes.Value{})
		if err == nil {
			_, err = Key(leaf, "edge_thing", instancekey.FormDelete, tftypes.Value{}, nil, prior)
		}
		if err == nil {
			t.Errorf("identity %s: key computed", name)
		}
	}
	idT := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"id": tftypes.String}}
	for name, state := range map[string]tftypes.Value{
		"null state":   tftypes.NewValue(idT, nil),
		"null id":      tftypes.NewValue(idT, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, nil)}),
		"empty id":     tftypes.NewValue(idT, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "")}),
		"unknown id":   tftypes.NewValue(idT, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}),
		"no id":        tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}, map[string]tftypes.Value{}),
		"number id":    tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"id": tftypes.Number}}, map[string]tftypes.Value{"id": num(one)}),
		"not a object": tftypes.NewValue(tftypes.String, "x"),
	} {
		if _, err := Prior(KindID, nil, state); err == nil {
			t.Errorf("prior state %s: id accepted", name)
		}
	}
	if _, err := Prior("other", nil, tftypes.Value{}); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := Key(leaf, "edge_thing", instancekey.FormUpdate, val(strs, num(one)), nil, nil); err == nil {
		t.Error("update without a prior identity: key computed")
	}
}

// TestNumberText: values that reach the provider by msgpack as int64,
// float64 or decimal text keep the canonical text of their plan JSON form.
func TestNumberText(t *testing.T) {
	for in, want := range map[string]string{
		"0.1": "0.1", "1e21": "1000000000000000000000", "9223372036854775808": "9223372036854775808",
		"9007199254740993": "9007199254740993", "1234567.5": "1.2345675e+06", "0.00001": "1e-05",
		"-0": "0", "-7": "-7", "1e-1000": "1e-1000",
	} {
		f, _, err := big.ParseFloat(in, 10, 512, big.ToNearestEven)
		if err != nil {
			t.Fatal(err)
		}
		typ := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"n": tftypes.Number}}
		v := roundTrip(t, typ, tftypes.NewValue(typ, map[string]tftypes.Value{"n": tftypes.NewValue(tftypes.Number, f)}))
		_, tree, err := Planned(v)
		if err != nil {
			t.Fatal(err)
		}
		// Compute canonicalizes the text; both spellings must hash alike.
		var leaf [32]byte
		got, err1 := instancekey.Compute(leaf, "t", instancekey.FormCreate, &instancekey.Type{Kind: instancekey.Object, Attrs: map[string]*instancekey.Type{"n": {Kind: instancekey.Number}}}, tree, nil, nil)
		exp, err2 := instancekey.Compute(leaf, "t", instancekey.FormCreate, &instancekey.Type{Kind: instancekey.Object, Attrs: map[string]*instancekey.Type{"n": {Kind: instancekey.Number}}}, map[string]any{"n": json.Number(want)}, nil, nil)
		if err1 != nil || err2 != nil || got != exp {
			t.Errorf("%s: tree %v, want text %s (%v, %v)", in, tree, want, err1, err2)
		}
	}
}
