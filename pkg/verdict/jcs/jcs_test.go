package jcs_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// TestTransformVectors runs the RFC 8785 examples under testdata: section
// 3.2.2 (literals, numbers, string escapes) and 3.2.3 (UTF-16 member order).
// The terraform provider verifies signatures with its own RFC 8785
// implementation; rfc8785-input.json and rfc8785-output.json are the bytes of
// its internal/bundle/testdata/contentdigest vector, so a change that breaks
// agreement between the two sides fails here.
func TestTransformVectors(t *testing.T) {
	for _, name := range []string{"rfc8785", "rfc8785-sort"} {
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join("testdata", name+"-input.json"))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", name+"-output.json"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := jcs.Transform(in)
			if err != nil {
				t.Fatalf("Transform returned error: %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("Transform() =\n%s\nwant\n%s", got, want)
			}
		})
	}
}

// TestTransformNumbers pins the ECMAScript layout at each of its boundaries
// (RFC 8785 appendix B and ECMA-262 Number::toString).
func TestTransformNumbers(t *testing.T) {
	cases := map[string]string{
		"0":                      "0",
		"-0":                     "0",
		"1":                      "1",
		"-1":                     "-1",
		"1.0":                    "1",
		"1e2":                    "100",
		"0.1":                    "0.1",
		"1e21":                   "1e+21",
		"999999999999999900000":  "999999999999999900000",
		"1e-6":                   "0.000001",
		"1e-7":                   "1e-7",
		"1.5e-7":                 "1.5e-7",
		"9007199254740993":       "9007199254740992",
		"5e-324":                 "5e-324",
		"1.7976931348623157e308": "1.7976931348623157e+308",
		"-1.25e25":               "-1.25e+25",
	}
	for in, want := range cases {
		got, err := jcs.Transform([]byte(in))
		if err != nil {
			t.Errorf("Transform(%s) returned error: %v", in, err)
			continue
		}
		if string(got) != want {
			t.Errorf("Transform(%s) = %s, want %s", in, got, want)
		}
	}
	if _, err := jcs.Transform([]byte("1e400")); err == nil {
		t.Error("Transform(1e400) returned no error, want one: it is outside float64")
	}
}

// TestTransformLeavesNonASCIIUnescaped pins the escaping rule. RFC 8785
// forbids the \uXXXX escaping Go's encoder applies to non-ASCII and to the
// HTML-significant characters, so a signature over a clause containing an
// accented word has to cover the UTF-8 bytes themselves.
func TestTransformLeavesNonASCIIUnescaped(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "non-ASCII", in: `{"k":"contrôlé Ω"}`, want: `{"k":"contrôlé Ω"}`},
		{name: "HTML significant", in: `{"k":"a <b> & c"}`, want: `{"k":"a <b> & c"}`},
		{name: "line separators", in: "{\"k\":\"a\u2028b\"}", want: "{\"k\":\"a\u2028b\"}"},
		{name: "required escapes kept", in: `{"k":"a\"b\\c"}`, want: `{"k":"a\"b\\c"}`},
		{name: "control characters escaped", in: `{"k":"a\u0001b\tc"}`, want: `{"k":"a\u0001b\tc"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jcs.Transform([]byte(tc.in))
			if err != nil {
				t.Fatalf("Transform returned error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("Transform(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestTransformRejectsTrailingData pins the one thing a decoder does quietly.
// Bytes after the closing brace that were dropped rather than
// refused would let two readers disagree about what the signature covered.
func TestTransformRejectsTrailingData(t *testing.T) {
	for _, bad := range []string{`{"a":1} {"b":2}`, `{"a":1}garbage`, `{"a":1}[]`, `{"a":1}}`, `{"a":1} ]`, `[1,2]]`} {
		if _, err := jcs.Transform([]byte(bad)); err == nil {
			t.Errorf("Transform(%s) returned no error, want one", bad)
		}
	}
}

// TestTransformSortsKeysAndDropsWhitespace is the rest of RFC 8785.
func TestTransformSortsKeysAndDropsWhitespace(t *testing.T) {
	in := `{ "z": 1, "a": [ true, null, 2 ], "m": { "b": "x", "a": "y" } }`
	want := `{"a":[true,null,2],"m":{"a":"y","b":"x"},"z":1}`

	got, err := jcs.Transform([]byte(in))
	if err != nil {
		t.Fatalf("Transform returned error: %v", err)
	}
	if string(got) != want {
		t.Errorf("Transform() = %s, want %s", got, want)
	}
}

// TestTransformIJSONRefuses pins the I-JSON refusals, with the vectors of the
// provider's internal/bundle DigestJSON test. Transform still reads each of
// these the way encoding/json does.
func TestTransformIJSONRefuses(t *testing.T) {
	cases := map[string]string{
		"truncated escape":         `["\ud800`,
		"short low escape":         `["\ud83d\u12"]`,
		"short escape":             `["\u12"]`,
		"non-hex escape":           `["\uzzzz"]`,
		"lone high surrogate":      `["\ud800"]`,
		"lone low surrogate":       `{"a":["\udfff"]}`,
		"reversed pair":            `["\udc00\ud800"]`,
		"surrogate in member name": `{"\ud800":1}`,
		"invalid UTF-8":            "[\"\xff\"]",
		"raw surrogate bytes":      "[\"\xed\xa0\x80\"]",
		"duplicate member":         `{"a":1,"a":2}`,
		"nested duplicate member":  `{"x":[{"b":"1","b":"1"}]}`,
		"noncharacter FDD0":        "[\"\ufdd0\"]",
		"noncharacter FFFE":        "{\"k\":\"a\ufffe\"}",
		"noncharacter U+10FFFF":    "[\"\U0010FFFF\"]",
		"noncharacter member name": "{\"\uffff\":1}",
		"noncharacter by escape":   `["\ufdef"]`,
		"too deep":                 strings.Repeat("[", 10002) + strings.Repeat("]", 10002),
		"trailing data":            `{"a":1} {}`,
		"number outside float64":   `[1e400]`,
		"not JSON":                 `{"a":}`,
		"empty":                    ``,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := jcs.TransformIJSON([]byte(in)); !errors.Is(err, jcs.ErrNotIJSON) || got != nil {
				t.Fatalf("TransformIJSON = %q, %v; want ErrNotIJSON", got, err)
			}
		})
	}
}

// TestTransformIJSONMatchesTransform: valid I-JSON gets exactly the bytes of
// Transform, so no digest of valid input moves. An escaped backslash before u
// is text, not an escape, and U+FFFD itself is an ordinary character.
func TestTransformIJSONMatchesTransform(t *testing.T) {
	inputs := []string{
		`{ "z": 1, "a": [ true, null, 2 ], "m": { "b": "x", "a": "y" } }`,
		`["\ud83d\ude00"]`,
		`["\\ud800"]`,
		`{"\\udc00":"\\\\ud800"}`,
		"[\"\u00e9\ufffd\"]",
		`{"k":"contrôlé Ω","h":"a <b> & c","c":"a\u0001b\tc"}`,
		`"text"`, `1.5e-7`, `null`,
	}
	for _, name := range []string{"rfc8785", "rfc8785-sort"} {
		in, err := os.ReadFile(filepath.Join("testdata", name+"-input.json"))
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, string(in))
	}
	for _, in := range inputs {
		want, err := jcs.Transform([]byte(in))
		if err != nil {
			t.Fatalf("Transform(%s): %v", in, err)
		}
		if got, err := jcs.TransformIJSON([]byte(in)); err != nil || !bytes.Equal(got, want) {
			t.Errorf("TransformIJSON(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
}

// TestTransformIJSONDepthBoundary pins the nesting bound the provider's
// CanonicalJSON has (encoding/json's decoder limit): 10000 nested arrays pass
// and 10001 do not.
func TestTransformIJSONDepthBoundary(t *testing.T) {
	ok := strings.Repeat("[", 10000) + strings.Repeat("]", 10000)
	if got, err := jcs.TransformIJSON([]byte(ok)); err != nil || string(got) != ok {
		t.Fatalf("10000 levels: err %v, same bytes %v", err, string(got) == ok)
	}
	deep := strings.Repeat("[", 10001) + strings.Repeat("]", 10001)
	if _, err := jcs.TransformIJSON([]byte(deep)); !errors.Is(err, jcs.ErrNotIJSON) {
		t.Fatalf("10001 levels: err %v, want ErrNotIJSON", err)
	}
}
