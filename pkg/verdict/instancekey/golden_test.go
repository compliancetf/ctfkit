package instancekey

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The instance_key goldens (../testdata/instancekey, frozen). This file holds a
// test-only plan adapter: it types plan.json "after" with schema.json, takes
// the golden unknown_paths and prior identity kind, and checks that Compute
// reproduces every key and both hashed JCS strings. Deriving unknown_paths
// and the prior kind from the plan is the tfjson adapter's job.

const goldenDir = "../testdata/instancekey"

type goldenKey struct {
	Field             string     `json:"field"`
	Form              Form       `json:"form"`
	Key               string     `json:"key"`
	PriorIdentityKind string     `json:"prior_identity_kind"`
	UnknownPaths      [][]string `json:"unknown_paths"`
	AfterJCS          string     `json:"after_hashed_jcs"`
	PriorJCS          string     `json:"prior_identity_hashed_jcs"`
}

type golden struct {
	Error   string `json:"error"`
	Entries []struct {
		Address string      `json:"address"`
		Deposed string      `json:"deposed"`
		Error   string      `json:"error"`
		Keys    []goldenKey `json:"keys"`
	} `json:"entries"`
	KLeafHex      string `json:"k_leaf_hex"`
	KeyCheck      string `json:"key_check"`
	TestSecretHex string `json:"test_secret_hex"`
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

// Refusals of the canonicalizer itself; every other _edge refusal belongs to
// the plan adapter (pkg/verdict/tfjson TestGoldens refuses each): prior kind
// choice, before and before_identity shape, after_unknown shape, deposed and
// action rules, missing schema.
var (
	canonRefusals = map[string]bool{
		"edge_thing.allunknown": true, "edge_thing.bigexp": true, "edge_thing.smallexp": true,
		"edge_thing.afterfalse": true, "edge_thing.maskedbad": true, "edge_thing.longnum": true,
		"edge_thing.extra": true,
	}
	adapterRefusals = map[string]bool{
		"edge_thing.noid": true, "edge_thing.emptyid": true, "edge_thing.numid": true,
		"edge_thing.identstr": true, "edge_thing.beforestridentity": true, "edge_thing.beforestr": true,
		"edge_thing.depnoop": true, "edge_thing.noschema": true, "edge_thing.setscalar": true,
		"edge_thing.setmixed": true, "edge_thing.setshape": true, "edge_thing.depbad": true,
	}
)

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

func testKeys(t *testing.T) (leaf, check [32]byte) {
	t.Helper()
	var secret [32]byte
	copy(secret[:], testSecret)
	return derive(secret)
}

func TestGoldens(t *testing.T) {
	leaf, check := testKeys(t)
	dirs, err := filepath.Glob(filepath.Join(goldenDir, "*", "expected.json"))
	if err != nil || len(dirs) != 23 {
		t.Fatalf("goldens: %d dirs, %v", len(dirs), err)
	}
	keys, refused := 0, 0
	for _, exp := range dirs {
		dir := filepath.Dir(exp)
		var g, cg golden
		decodeFile(t, exp, &g)
		decodeFile(t, filepath.Join(dir, "canonical.json"), &cg)
		if g.Error != "" {
			continue // whole-file JSON refusals (_edge_dupkey, _edge_surrogate): the plan adapter's
		}
		if g.TestSecretHex != hex.EncodeToString([]byte(testSecret)) || g.KLeafHex != hex.EncodeToString(leaf[:]) || g.KeyCheck != KeyCheck(check) {
			t.Fatalf("%s: secret, k_leaf or key_check differs", dir)
		}
		var plan struct {
			ResourceChanges []planChange `json:"resource_changes"`
		}
		decodeFile(t, filepath.Join(dir, "plan.json"), &plan)
		schemas := schemaTypes(t, filepath.Join(dir, "schema.json"))
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
			if rc.Address != e.Address || rc.Deposed != e.Deposed {
				t.Fatalf("%s: entry %d is %s, change is %s", dir, i, e.Address, rc.Address)
			}
			schema := schemas[rc.Type]
			if e.Error != "" {
				switch {
				case canonRefusals[e.Address]:
					after := rc.Change.After
					if rc.Change.AfterUnknown == true {
						after = Unknown{}
					}
					if _, cerr := Compute(leaf, rc.Type, FormCreate, schema, after, unknownLeaves(rc.Change.AfterUnknown, nil), nil); cerr == nil {
						t.Errorf("%s: key computed, want refusal (%s)", e.Address, e.Error)
					}
					refused++
				case !adapterRefusals[e.Address]:
					t.Errorf("%s: refusal %q not assigned to the canonicalizer or the adapter", e.Address, e.Error)
				}
				continue
			}
			for j, k := range e.Keys {
				name := e.Address + "/" + e.Deposed + "/" + string(k.Form)
				var err error // per key, so one failure does not mask the next
				var after, prior any
				if k.Form != FormDelete {
					after = rc.Change.After
				}
				switch k.PriorIdentityKind {
				case "identity":
					prior = rc.Change.BeforeIdentity
				case "id":
					prior = map[string]any{"id": rc.Change.Before.(map[string]any)["id"]}
				}
				ck := cg.Entries[i].Keys[j]
				afterJCS, priorJCS := []byte("null"), []byte("null")
				if after != nil {
					afterJCS, err = afterTree(leaf, schema, after, k.UnknownPaths)
				}
				if err == nil && prior != nil {
					priorJCS, err = priorTree(leaf, prior)
				}
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				if string(afterJCS) != ck.AfterJCS || string(priorJCS) != ck.PriorJCS {
					t.Errorf("%s: hashed JCS differs\n after %s\n want  %s\n prior %s\n want  %s", name, afterJCS, ck.AfterJCS, priorJCS, ck.PriorJCS)
				}
				got, err := Compute(leaf, rc.Type, k.Form, schema, after, k.UnknownPaths, prior)
				if err != nil || got != k.Key {
					t.Errorf("%s: key %s (%v), want %s", name, got, err, k.Key)
				}
				keys++
			}
		}
	}
	if keys < 40 || refused != len(canonRefusals) {
		t.Fatalf("checked %d keys and %d canonicalizer refusals", keys, refused)
	}
}

// unknownLeaves is every path where after_unknown is true, unnormalized.
func unknownLeaves(u any, path []string) [][]string {
	var out [][]string
	switch u := u.(type) {
	case bool:
		if u && len(path) > 0 {
			out = append(out, append([]string(nil), path...))
		}
	case map[string]any:
		for k, e := range u {
			out = append(out, unknownLeaves(e, append(path, k))...)
		}
	case []any:
		for i, e := range u {
			out = append(out, unknownLeaves(e, append(path, strconv.Itoa(i)))...)
		}
	}
	return out
}

// schemaTypes is the resource Type per type name of a terraform providers
// schema -json file.
func schemaTypes(t *testing.T, path string) map[string]*Type {
	t.Helper()
	var s struct {
		ProviderSchemas map[string]struct {
			Resources map[string]struct {
				Block json.RawMessage `json:"block"`
			} `json:"resource_schemas"`
		} `json:"provider_schemas"`
	}
	decodeFile(t, path, &s)
	out := map[string]*Type{}
	for _, ps := range s.ProviderSchemas {
		for name, r := range ps.Resources {
			out[name] = blockType(t, r.Block)
		}
	}
	return out
}

func blockType(t *testing.T, raw json.RawMessage) *Type {
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
	obj := &Type{Kind: Object, Attrs: map[string]*Type{}}
	for n, a := range b.Attributes {
		if a.Nested != nil {
			inner, _ := json.Marshal(map[string]json.RawMessage{"attributes": a.Nested.Attributes})
			obj.Attrs[n] = nest(a.Nested.NestingMode, blockType(t, inner))
			continue
		}
		var j any
		if err := json.Unmarshal(a.Type, &j); err != nil {
			t.Fatal(err)
		}
		obj.Attrs[n] = ctyType(t, j)
	}
	for n, bt := range b.BlockTypes {
		obj.Attrs[n] = nest(bt.NestingMode, blockType(t, bt.Block))
	}
	return obj
}

func nest(mode string, o *Type) *Type {
	switch mode {
	case "list":
		return &Type{Kind: List, Elem: o}
	case "set":
		return &Type{Kind: Set, Elem: o}
	case "map":
		return &Type{Kind: Map, Elem: o}
	}
	return o // single, group
}

// ctyType reads the cty JSON type syntax of a schema attribute.
func ctyType(t *testing.T, j any) *Type {
	t.Helper()
	switch j := j.(type) {
	case string:
		k := map[string]Kind{"string": String, "number": Number, "bool": Bool, "dynamic": Dynamic}[j]
		if k == 0 {
			t.Fatalf("type %q", j)
		}
		return &Type{Kind: k}
	case []any:
		switch j[0] {
		case "list":
			return &Type{Kind: List, Elem: ctyType(t, j[1])}
		case "set":
			return &Type{Kind: Set, Elem: ctyType(t, j[1])}
		case "map":
			return &Type{Kind: Map, Elem: ctyType(t, j[1])}
		case "object":
			o := &Type{Kind: Object, Attrs: map[string]*Type{}}
			for n, a := range j[1].(map[string]any) {
				o.Attrs[n] = ctyType(t, a)
			}
			return o
		case "tuple":
			tu := &Type{Kind: Tuple}
			for _, e := range j[1].([]any) {
				tu.Elems = append(tu.Elems, ctyType(t, e))
			}
			return tu
		}
	}
	t.Fatalf("type %v", j)
	return nil
}
