package readdigest

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
)

type goldenCase struct {
	Name    string          `json:"name"`
	Reads   []string        `json:"reads"`
	Value   json.RawMessage `json:"value"`
	Unknown [][]string      `json:"unknown"`
	KeyHex  string          `json:"key_hex"`
	Digest  string          `json:"digest"`
}

type goldenFile struct {
	KeyHex   string          `json:"key_hex"`
	KReadHex string          `json:"k_read_hex"`
	Type     json.RawMessage `json:"type"`
	Cases    []goldenCase    `json:"cases"`
}

// TestGoldens recomputes every digest the provider computed for
// ../testdata/readdigest/cases.json (SOURCE.json in ../testdata/baseline); an
// empty digest is a case the provider refuses, so Digest must refuse it too.
func TestGoldens(t *testing.T) {
	raw, err := os.ReadFile("../testdata/readdigest/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var f goldenFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var typ any
	if err := json.Unmarshal(f.Type, &typ); err != nil {
		t.Fatal(err)
	}
	schema := ctyType(t, typ)
	k := mustKey(t, f.KeyHex)
	if kr, _ := hkdf.Key(sha256.New, k[:], nil, info, 32); hex.EncodeToString(kr) != f.KReadHex {
		t.Fatalf("k_read %x, want %s", kr, f.KReadHex)
	}
	digests := map[string]string{}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			dec := json.NewDecoder(bytes.NewReader(c.Value))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err != nil {
				t.Fatal(err)
			}
			for _, p := range c.Unknown {
				v = markUnknown(v, p)
			}
			key := k
			if c.KeyHex != "" {
				key = mustKey(t, c.KeyHex)
			}
			got, err := Digest(key, c.Reads, schema, v)
			if c.Digest == "" {
				if err == nil {
					t.Fatalf("digest %s, the provider refuses", got)
				}
				return
			}
			if err != nil || got != c.Digest {
				t.Fatalf("got %s %v, want %s", got, err, c.Digest)
			}
		})
		digests[c.Name] = c.Digest
	}
	// The properties the vectors exist for (spec "Golden").
	for _, pair := range [][2]string{{"base", "unrelated attribute changed"}, {"base", "unknown unrelated attribute"},
		{"set order a", "set order b"}, {"set of objects a", "set of objects b"}, {"null read", "absent attribute is null"},
		{"single read", "duplicate reads"}} {
		if digests[pair[0]] != digests[pair[1]] {
			t.Errorf("%s and %s differ", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{"base", "read attribute changed"}, {"base", "other baseline key"},
		{"list order a", "list order b"}, {"map with a null value", "map without the null key"}} {
		if digests[pair[0]] == digests[pair[1]] {
			t.Errorf("%s and %s are equal", pair[0], pair[1])
		}
	}
}

// TestDynamicRefused: ctfkit refuses a dynamic value under a read (the
// provider would hash its runtime type); a dynamic attribute nobody reads
// does not matter.
func TestDynamicRefused(t *testing.T) {
	schema := &instancekey.Type{Kind: instancekey.Object, Attrs: map[string]*instancekey.Type{
		"acl": {Kind: instancekey.String}, "any": {Kind: instancekey.Dynamic}}}
	v := map[string]any{"acl": "private", "any": "x"}
	if _, err := Digest([32]byte{}, []string{"any"}, schema, v); err == nil {
		t.Fatal("dynamic read digested")
	}
	if _, err := Digest([32]byte{}, []string{"acl"}, schema, v); err != nil {
		t.Fatalf("dynamic sibling: %v", err)
	}
	if _, err := Digest([32]byte{}, []string{"acl"}, schema, map[string]any{"acl": 1.5}); err == nil {
		t.Fatal("wrong value kind digested")
	}
}

func TestParseKey(t *testing.T) {
	hexKey := strings.Repeat("ab", 32)
	for text, ok := range map[string]bool{hexKey: true, hexKey + "\n": true, hexKey + "\r\n": false, hexKey + "\n\n": false,
		" " + hexKey: false, strings.ToUpper(hexKey): false, hexKey[:62]: false, hexKey + "ab": false, "": false} {
		k, err := ParseKey([]byte(text))
		if (err == nil) != ok || ok && hex.EncodeToString(k[:]) != hexKey {
			t.Errorf("%q: %x %v", text, k, err)
		}
	}
}

func mustKey(t *testing.T, s string) [32]byte {
	t.Helper()
	k, err := ParseKey([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// markUnknown replaces the value at path with an Unknown; "*" is every
// element of an array.
func markUnknown(v any, path []string) any {
	if len(path) == 0 {
		return instancekey.Unknown{}
	}
	switch n := v.(type) {
	case map[string]any:
		if c, ok := n[path[0]]; ok {
			n[path[0]] = markUnknown(c, path[1:])
		}
	case []any:
		for i := range n {
			if path[0] == "*" || path[0] == strconv.Itoa(i) {
				n[i] = markUnknown(n[i], path[1:])
			}
		}
	}
	return v
}

// ctyType reads the cty JSON type syntax.
func ctyType(t *testing.T, j any) *instancekey.Type {
	t.Helper()
	switch j := j.(type) {
	case string:
		k := map[string]instancekey.Kind{"string": instancekey.String, "number": instancekey.Number, "bool": instancekey.Bool, "dynamic": instancekey.Dynamic}[j]
		if k != 0 {
			return &instancekey.Type{Kind: k}
		}
	case []any:
		switch j[0] {
		case "list", "set", "map":
			k := map[any]instancekey.Kind{"list": instancekey.List, "set": instancekey.Set, "map": instancekey.Map}[j[0]]
			return &instancekey.Type{Kind: k, Elem: ctyType(t, j[1])}
		case "object":
			o := &instancekey.Type{Kind: instancekey.Object, Attrs: map[string]*instancekey.Type{}}
			for n, a := range j[1].(map[string]any) {
				o.Attrs[n] = ctyType(t, a)
			}
			return o
		case "tuple":
			tu := &instancekey.Type{Kind: instancekey.Tuple}
			for _, e := range j[1].([]any) {
				tu.Elems = append(tu.Elems, ctyType(t, e))
			}
			return tu
		}
	}
	t.Fatalf("type %v", j)
	return nil
}
