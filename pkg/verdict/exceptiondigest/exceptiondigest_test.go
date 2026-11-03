package exceptiondigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

const dir = "../testdata/exceptiondigest"

type vector struct {
	File  string `json:"file"`
	Entry struct {
		Label        string   `json:"label"`
		Workspace    string   `json:"workspace"`
		Controls     []string `json:"controls"`
		Selector     string   `json:"selector"`
		Environments []string `json:"environments"`
		Expires      string   `json:"expires"`
	} `json:"entry"`
	Canonical string `json:"canonical"`
	Digest    string `json:"digest"`
}

type expected struct {
	Grants      map[string]string `json:"grants"`
	SelfService []vector          `json:"self_service"`
}

func load(t *testing.T) expected {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var e expected
	if err := dec.Decode(&e); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestSource checks every vector file still has the sha256 SOURCE.json
// recorded when the provider generated expected.json.
func TestSource(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(dir, "SOURCE.json"))
	if err != nil {
		t.Fatal(err)
	}
	var src struct {
		Copied, Authored map[string]string
		Expected         string `json:"expected_json_sha256"`
	}
	if err = json.Unmarshal(b, &src); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"expected.json": src.Expected}
	for _, m := range []map[string]string{src.Copied, src.Authored} {
		for k, v := range m {
			want[k] = v
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(want)-1 {
		t.Fatalf("%d vector files, SOURCE.json lists %d", len(files), len(want)-1)
	}
	for name, h := range want {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != h {
			t.Errorf("%s: sha256 differs from SOURCE.json", name)
		}
	}
}

// TestGrantGoldens: the digest of each raw envelope file equals the one the
// provider's grant loader computed for it.
func TestGrantGoldens(t *testing.T) {
	e := load(t)
	if len(e.Grants) == 0 {
		t.Fatal("no grant vectors")
	}
	for name, want := range e.Grants {
		b, err := os.ReadFile(filepath.Join(dir, "grants", name))
		if err != nil {
			t.Fatal(err)
		}
		if got := Grant(b); got != want {
			t.Errorf("%s: got %s, want %s", name, got, want)
		}
		if Grant(append(b, '\n')) == want {
			t.Errorf("%s: a trailing newline must change the digest", name)
		}
	}
}

// TestSelfServiceGoldens: each entry, fed in its written order, has the
// provider-computed canonical form and digest; entries sharing a label are
// reorderings of one entry and share one digest.
func TestSelfServiceGoldens(t *testing.T) {
	byLabel := map[string]string{}
	entries := load(t).SelfService
	if len(entries) == 0 {
		t.Fatal("expected.json lists no self-service entries")
	}
	for _, v := range entries {
		en := Entry(v.Entry)
		got, err := SelfService(en)
		if err != nil {
			t.Fatalf("%s %s: %v", v.File, v.Entry.Label, err)
		}
		if got != v.Digest {
			t.Errorf("%s %s: got %s, want %s", v.File, v.Entry.Label, got, v.Digest)
		}
		// the committed canonical form is JCS and hashes to the digest
		if c, err := jcs.Transform([]byte(v.Canonical)); err != nil || string(c) != v.Canonical || sum(c) != v.Digest {
			t.Errorf("%s %s: canonical form is not the hashed JCS bytes", v.File, v.Entry.Label)
		}
		if d, ok := byLabel[v.Entry.Label]; ok && d != got {
			t.Errorf("%s: reordered entry %s changed the digest", v.File, v.Entry.Label)
		}
		byLabel[v.Entry.Label] = got
	}
}

func base() Entry {
	return Entry{Label: "multi-env", Workspace: "bobthecorp-reporting-prod",
		Controls: []string{"b", "a", "c"}, Selector: "type == 'aws_s3_bucket'",
		Environments: []string{"prod", "dev"}, Expires: "2027-06-30"}
}

func TestSelfServiceInvariants(t *testing.T) {
	// digest fails the test on an error, so a rejected entry never passes a
	// comparison with "".
	digest := func(e Entry) string {
		t.Helper()
		d, err := SelfService(e)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	want := digest(base())
	e := base()
	slices.Reverse(e.Controls)
	slices.Reverse(e.Environments)
	if digest(e) != want {
		t.Error("reordering controls or environments changed the digest")
	}
	if e.Controls[0] != "c" || e.Environments[0] != "dev" {
		t.Error("SelfService modified the caller's slices")
	}
	nilEnv, emptyEnv := base(), base()
	nilEnv.Environments, emptyEnv.Environments = nil, []string{}
	a, b := digest(nilEnv), digest(emptyEnv)
	if a != b || a == want {
		t.Error("nil and empty environments must agree and differ from a scoped entry")
	}
	for name, mut := range map[string]func(*Entry){
		"label":       func(e *Entry) { e.Label = "other" },
		"workspace":   func(e *Entry) { e.Workspace = "bobthecorp-dev" },
		"controls":    func(e *Entry) { e.Controls = append(e.Controls, "a") }, // a duplicate counts
		"selector":    func(e *Entry) { e.Selector += " " },
		"environment": func(e *Entry) { e.Environments = e.Environments[:1] },
		"expires":     func(e *Entry) { e.Expires = "2027-07-01" },
	} {
		e := base()
		mut(&e)
		if digest(e) == want {
			t.Errorf("changing %s left the digest unchanged", name)
		}
	}
}

func TestSelfServiceRejects(t *testing.T) {
	for name, mut := range map[string]func(*Entry){
		"no label":         func(e *Entry) { e.Label = "" },
		"no workspace":     func(e *Entry) { e.Workspace = "" },
		"no controls":      func(e *Entry) { e.Controls = nil },
		"no selector":      func(e *Entry) { e.Selector = "" },
		"no expires":       func(e *Entry) { e.Expires = "" },
		"bad utf-8":        func(e *Entry) { e.Selector = "a\xffb" },
		"bad utf-8 in env": func(e *Entry) { e.Environments = []string{"\xc3"} },
	} {
		e := base()
		mut(&e)
		if d, err := SelfService(e); err == nil || d != "" {
			t.Errorf("%s: want an error and no digest, got %q", name, d)
		}
	}
}
