package instancekey

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRefusals: inputs that give no key, ported from the provider's
// TestKeyRefusals (terraform-provider-aws internal/verdict) so both sides
// refuse the same trees, plus the tree shapes only the canonicalizer checks.
func TestRefusals(t *testing.T) {
	var leaf [32]byte
	str, num := &Type{Kind: String}, &Type{Kind: Number}
	setT := &Type{Kind: Object, Attrs: map[string]*Type{"st": {Kind: Set, Elem: str}, "n": num, "tu": {Kind: Tuple, Elems: []*Type{str}}}}
	val := func(st any, n string) map[string]any { return map[string]any{"st": st, "n": json.Number(n)} }
	unknownSet := []any{Unknown{}}
	for name, tc := range map[string]struct {
		after   any
		unknown [][]string
	}{
		"unknown outside paths": {val(unknownSet, "1"), nil},
		"step into a set":       {val(unknownSet, "1"), [][]string{{"st", "0"}}},
		"undeclared path":       {val([]any{"a"}, "1"), [][]string{{"bogus"}}},
		"empty path":            {val([]any{"a"}, "1"), [][]string{{}}},
		"exponent too large":    {val([]any{"a"}, "10e1000"), nil},
		"exponent too small":    {val([]any{"a"}, "1e-1001"), nil},
		"number text too long":  {val([]any{"a"}, "1"+strings.Repeat("0", 1200)), nil},
		"infinity":              {val([]any{"a"}, "Inf"), nil},
		"whole value unknown":   {Unknown{}, nil},
		"not an object":         {false, nil},
		"wrong kind":            {map[string]any{"n": "1"}, nil},
		"wrong kind masked":     {map[string]any{"n": "1"}, [][]string{{"n"}}},
		"undeclared attribute":  {map[string]any{"bogus": "x"}, nil},
		"invalid UTF-8":         {val([]any{"\xff"}, "1"), nil},
		"tuple arity":           {map[string]any{"tu": []any{"a", "b"}}, nil},
		"tuple index":           {map[string]any{"tu": []any{"a"}}, [][]string{{"tu", "1"}}},
		"index syntax":          {map[string]any{"tu": []any{"a"}}, [][]string{{"tu", "00"}}},
	} {
		if _, err := Compute(leaf, "edge_thing", FormCreate, setT, tc.after, tc.unknown, nil); err == nil {
			t.Errorf("%s: key computed", name)
		}
	}
	if _, err := Compute(leaf, "edge_thing", FormCreate, setT, val(unknownSet, "1"), [][]string{{"st"}}, nil); err != nil {
		t.Errorf("masked set: %v", err)
	}
	mapT := &Type{Kind: Object, Attrs: map[string]*Type{"tags": {Kind: Map, Elem: str}}}
	tags := func() any { return map[string]any{"tags": map[string]any{"": Unknown{}, "a": "b"}} }
	if _, err := Compute(leaf, "edge_thing", FormCreate, mapT, tags(), [][]string{{"tags", ""}}, nil); err != nil {
		t.Errorf("empty map key path: %v", err)
	}
	if _, err := Compute(leaf, "edge_thing", FormCreate, mapT, tags(), [][]string{{""}}, nil); err == nil {
		t.Error("empty attribute step accepted")
	}
	for name, prior := range map[string]any{
		"no leaf": map[string]any{"arn": nil}, "not object": "x", "nil": nil, "unknown": map[string]any{"id": Unknown{}},
	} {
		if _, err := Compute(leaf, "edge_thing", FormDelete, setT, nil, nil, prior); err == nil {
			t.Errorf("prior %s: key computed", name)
		}
	}
	id := map[string]any{"id": "x"}
	if _, err := Compute(leaf, "edge_thing", FormDelete, setT, val(nil, "1"), nil, id); err == nil {
		t.Error("delete with a planned value: key computed")
	}
	if _, err := Compute(leaf, "edge_thing", FormCreate, setT, val(nil, "1"), nil, id); err == nil {
		t.Error("create with a prior identity: key computed")
	}
	if _, err := Compute(leaf, "edge_thing", "replace", setT, val(nil, "1"), nil, id); err == nil {
		t.Error("unknown form: key computed")
	}
}

// TestMask: masking nulls a list element in place and never shifts or
// extends a list; an unresolved path is a no-op.
func TestMask(t *testing.T) {
	var leaf [32]byte
	ty := &Type{Kind: Object, Attrs: map[string]*Type{"l": {Kind: List, Elem: &Type{Kind: String}}}}
	key := func(l []any, paths ...[]string) string {
		k, err := Compute(leaf, "t", FormCreate, ty, map[string]any{"l": l}, paths, nil)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	if key([]any{"a", Unknown{}}, []string{"l", "1"}) != key([]any{"a", nil}) {
		t.Error("masked element is not null")
	}
	if key([]any{"a"}, []string{"l", "5"}) != key([]any{"a"}) {
		t.Error("index past the end changed the list")
	}
	if key([]any{"a"}, []string{"l"}) == key([]any{"a"}) {
		t.Error("whole-list path did not remove the list")
	}
}

func TestNumberText(t *testing.T) {
	for in, want := range map[string]string{
		"0.1":                           "0.1",
		"1e21":                          "1000000000000000000000",
		"9223372036854775808":           "9223372036854775808",
		"9007199254740993":              "9007199254740993",
		"18446744073709551617":          "18446744073709551617",
		"18446744073709552000":          "18446744073709552000",
		"1234567.5":                     "1.2345675e+06",
		"0.00001":                       "1e-05",
		"0.0001":                        "0.0001",
		"-0":                            "0",
		"0e" + strings.Repeat("9", 100): "0",
		"1e-1000":                       "1e-1000",
	} {
		if got, err := numberText(in); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", in, got, err, want)
		}
	}
	a, errA := numberText("1e1000")
	b, errB := numberText("0.1e1001")
	if errA != nil || errB != nil || a != b || len(a) != 1000 || !strings.HasPrefix(a, "99999") {
		t.Errorf("1e1000: %q %v, 0.1e1001: %q %v", a[:min(len(a), 10)], errA, b[:min(len(b), 10)], errB)
	}
	for _, in := range []string{"10e1000", "1e-1001", strings.Repeat("1", 1201), "", "1e", "0e", "0eNaN", "0e+", "0e+-1", "0e1.5", "-+0", "+1", "-", ".5", "1.", "01", "0x10", "1e99999999999999999999"} {
		if got, err := numberText(in); err == nil {
			t.Errorf("%q: %q accepted", in, got)
		}
	}
}
