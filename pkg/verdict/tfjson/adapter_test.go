package tfjson

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
)

const goldenDir = "../testdata/instancekey"

type goldenKey struct {
	Field             string     `json:"field"`
	Form              string     `json:"form"`
	Key               string     `json:"key"`
	PriorIdentityKind string     `json:"prior_identity_kind"`
	UnknownPaths      [][]string `json:"unknown_paths"`
}

type goldenEntry struct {
	Address      string      `json:"address"`
	Deposed      string      `json:"deposed"`
	Actions      []string    `json:"actions"`
	ActionReason string      `json:"action_reason"`
	Error        string      `json:"error"`
	Keys         []goldenKey `json:"keys"`
}

// adapterRefusals are the _edge instances the canonicalizer cannot refuse on
// its own (instancekey golden_test.go): prior kind choice, before and
// before_identity shape, after_unknown shape, deposed and action rules,
// missing schema. The plan adapter refuses each of them.
var adapterRefusals = []string{
	"edge_thing.noid", "edge_thing.emptyid", "edge_thing.numid",
	"edge_thing.identstr", "edge_thing.beforestridentity", "edge_thing.beforestr",
	"edge_thing.depnoop", "edge_thing.noschema", "edge_thing.setscalar",
	"edge_thing.setmixed", "edge_thing.setshape", "edge_thing.depbad",
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T, leaf [32]byte, dir string) ([]Instance, error) {
	t.Helper()
	s, err := ParseSchemas(readFile(t, filepath.Join(dir, "schema.json")))
	if err != nil {
		return nil, err
	}
	return Instances(leaf, readFile(t, filepath.Join(dir, "plan.json")), s)
}

// TestGoldens: the plan side of every frozen golden, keys, kinds, unknown
// paths and refusals included, from plan.json and schema.json alone.
func TestGoldens(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(goldenDir, "*", "expected.json"))
	if err != nil || len(dirs) != 23 {
		t.Fatalf("goldens: %d dirs, %v", len(dirs), err)
	}
	keys, refused := 0, map[string]bool{}
	for _, exp := range dirs {
		dir := filepath.Dir(exp)
		var g struct {
			Error    string        `json:"error"`
			KLeafHex string        `json:"k_leaf_hex"`
			Entries  []goldenEntry `json:"entries"`
		}
		if err := json.Unmarshal(readFile(t, exp), &g); err != nil {
			t.Fatal(err)
		}
		var leaf [32]byte
		if g.Error == "" {
			b, err := hex.DecodeString(g.KLeafHex)
			if err != nil || len(b) != len(leaf) {
				t.Fatalf("%s: k_leaf_hex: %v", dir, err)
			}
			copy(leaf[:], b)
		}
		insts, err := load(t, leaf, dir)
		if g.Error != "" {
			if err == nil {
				t.Errorf("%s: file accepted, want refusal (%s)", dir, g.Error)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if len(insts) != len(g.Entries) {
			t.Fatalf("%s: %d instances, %d entries", dir, len(insts), len(g.Entries))
		}
		for i, e := range g.Entries {
			in := insts[i]
			name := e.Address + "/" + e.Deposed
			if in.Address != e.Address || in.Deposed != e.Deposed || !slices.Equal(in.Actions, e.Actions) || in.ActionReason != e.ActionReason {
				t.Errorf("%s: instance %+v", name, in)
				continue
			}
			if e.Error != "" {
				if in.Err == nil || len(in.Keys) != 0 {
					t.Errorf("%s: keys %v, want refusal (%s)", name, in.Keys, e.Error)
				}
				refused[e.Address] = true
				continue
			}
			if in.Err != nil {
				t.Errorf("%s: %v", name, in.Err)
				continue
			}
			got := make([]goldenKey, len(in.Keys))
			for j, k := range in.Keys {
				got[j] = goldenKey{k.Field, string(k.Form), k.Key, k.PriorIdentityKind, k.UnknownPaths}
			}
			if !reflect.DeepEqual(got, e.Keys) {
				t.Errorf("%s:\n got  %+v\n want %+v", name, got, e.Keys)
			}
			keys += len(got)
		}
	}
	for _, a := range adapterRefusals {
		if !refused[a] {
			t.Errorf("%s: not refused", a)
		}
	}
	if keys < 40 {
		t.Fatalf("checked %d keys", keys)
	}
}

const edgeSchema = `{"format_version":"1.0","provider_schemas":{"p":{
 "resource_identity_schemas":{"t":{"attributes":{"name":{"type":"string"}},"version":0}},
 "resource_schemas":{"t":{"block":{"attributes":{
  "id":{"type":"string","computed":true},
  "st":{"type":["set",["object",{"d":"dynamic","s":"string"}]]}}}}}}}}`

func plan(change string) []byte {
	return []byte(`{"format_version":"1.2","resource_changes":[{"address":"t.x","mode":"managed","type":"t","provider_name":"p",` + change + `}]}`)
}

func one(t *testing.T, change string) Instance {
	t.Helper()
	s, err := ParseSchemas([]byte(edgeSchema))
	if err != nil {
		t.Fatal(err)
	}
	insts, err := Instances([32]byte{1}, plan(change), s)
	if err != nil || len(insts) != 1 {
		t.Fatalf("%v %v", insts, err)
	}
	return insts[0]
}

// An unknown inside a dynamic member of a set element records the set path
// (FORMAT.md normalization rule 1), so the key masks the whole set.
func TestUnknownInDynamicMemberOfSetElement(t *testing.T) {
	in := one(t, `"change":{"actions":["create"],"after":{"st":[{"s":"a","d":null}]},"after_unknown":{"id":true,"st":[{"d":true}]}}`)
	if in.Err != nil {
		t.Fatal(in.Err)
	}
	k := in.Keys[0]
	if want := [][]string{{"id"}, {"st"}}; !reflect.DeepEqual(k.UnknownPaths, want) {
		t.Fatalf("unknown paths %v, want %v", k.UnknownPaths, want)
	}
	noSet := one(t, `"change":{"actions":["create"],"after":{},"after_unknown":{"id":true}}`)
	if k.Key != noSet.Keys[0].Key {
		t.Fatal("the set is not masked as a whole")
	}
}

// The destroy half of a tainted replace keys with kind id even when
// before_identity is usable (OpenTofu emits it). An untainted
// replace keys the same object with kind identity.
func TestTaintedReplaceDeleteKindID(t *testing.T) {
	change := `"change":{"actions":["delete","create"],"before":{"id":"i-1"},"before_identity":{"name":"bob"},"after":{},"after_unknown":{"id":true}}`
	tainted := one(t, `"action_reason":"replace_because_tainted",`+change)
	plain := one(t, `"action_reason":"replace_because_cannot_update",`+change)
	if tainted.Err != nil || plain.Err != nil {
		t.Fatal(tainted.Err, plain.Err)
	}
	if k := tainted.Keys[0]; k.Form != instancekey.FormDelete || k.PriorIdentityKind != KindID || !reflect.DeepEqual(k.Prior, map[string]any{"id": "i-1"}) {
		t.Fatalf("tainted delete half %+v", k)
	}
	if k := plain.Keys[0]; k.PriorIdentityKind != KindIdentity {
		t.Fatalf("replace delete half %+v", k)
	}
	if tainted.Keys[1].PriorIdentityKind != KindNone || tainted.Keys[1].Key != plain.Keys[1].Key {
		t.Fatal("create half differs")
	}
}

// A bad marker under a dynamic member of a set element is refused whatever
// order the element's members are read in.
func TestSetMarkerRefusalDeterministic(t *testing.T) {
	for range 50 {
		in := one(t, `"change":{"actions":["create"],"after":{"st":[{"s":"a","d":null}]},"after_unknown":{"st":[{"d":"bad","s":true}]}}`)
		if in.Err == nil || len(in.Keys) != 0 {
			t.Fatalf("accepted: %+v", in.Keys)
		}
	}
}

func TestPlanShape(t *testing.T) {
	s, err := ParseSchemas([]byte(edgeSchema))
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range []string{`[]`, `null`, `"x"`, `{"resource_changes":{}}`} {
		if _, perr := Instances([32]byte{1}, []byte(doc), s); perr == nil {
			t.Errorf("%s: accepted", doc)
		}
	}
	for _, doc := range []string{`{"format_version":"1.2"}`, `{"resource_changes":null}`} {
		if insts, perr := Instances([32]byte{1}, []byte(doc), s); perr != nil || len(insts) != 0 {
			t.Errorf("%s: %v %v", doc, insts, perr)
		}
	}
	bad := strings.Replace(edgeSchema, `"t":{"attributes":{"name":{"type":"string"}},"version":0}`, `"t":42`, 1)
	if s, err = ParseSchemas([]byte(bad)); err != nil {
		t.Fatal(err)
	}
	if in, _ := Instances([32]byte{1}, plan(`"change":{"actions":["create"],"after":{}}`), s); len(in) != 1 || in[0].Err == nil {
		t.Errorf("non-object identity schema accepted: %+v", in)
	}
}

func TestStrictJSON(t *testing.T) {
	for name, doc := range map[string]string{
		"dup key":        `{"a":1,"a":2}`,
		"nested dup key": `{"a":[{"b":1,"b":1}]}`,
		"lone surrogate": `{"a":"\ud800"}`,
		"lone low":       `{"a":"\udc00x"}`,
		"invalid utf-8":  "{\"a\":\"\xff\"}",
		"trailing":       `{} {}`,
	} {
		if _, err := decodeStrict([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	v, err := decodeStrict([]byte(`{"n":18446744073709551617,"s":"\ud83d\ude00"}`))
	if err != nil {
		t.Fatal(err)
	}
	if m := v.(map[string]any); m["n"] != json.Number("18446744073709551617") || m["s"] != "\U0001F600" {
		t.Fatalf("%v", m)
	}
}
