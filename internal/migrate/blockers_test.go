package migrate

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

// floorFixtures name, per fixture, the signed inputs case under
// pkg/verdict/testdata/inputs its floor check verifies (VerifyInputs) and
// reads beside preflight.show.json, the show -json of its preflight plan.
var floorFixtures = map[string]string{"18-hard-fail-violations": "valid"}

// fixtureNow is the time the signed inputs cases verify at.
var fixtureNow = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// TestBlockersFixtures is the PM-T05 oracle: blocked[] of the expected plan
// of every filled fixture, and for 04, 14 and 18 the exit code 1 of
// expected/exit-code; the other fixtures block nothing and exit 0.
func TestBlockersFixtures(t *testing.T) {
	for _, name := range append([]string{"06-cli-workspaces"}, rewriteFixtures...) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("..", "..", "testdata", "fixtures", "migrate", name)
			raw, err := os.ReadFile(filepath.Join(dir, "expected", "migrate-plan.json"))
			if err != nil {
				t.Fatal(err)
			}
			var want struct {
				Providers []Provider `json:"providers"`
				Units     []Unit     `json:"units"`
				Blocked   []Blocked  `json:"blocked"`
			}
			if err = json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			got, err := Blockers(filepath.Join(dir, "input"), want.Units, want.Providers)
			if err != nil {
				t.Fatal(err)
			}
			if inputs, ok := floorFixtures[name]; ok {
				fv, err := FloorViolations(".", verifiedCase(t, inputs), readShow(t, filepath.Join(dir, "preflight.show.json")), nil)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, fv...)
				sortBlocked(got)
			}
			if got == nil {
				got = []Blocked{}
			}
			if !reflect.DeepEqual(got, want.Blocked) {
				g, _ := json.MarshalIndent(got, "", "  ")
				w, _ := json.MarshalIndent(want.Blocked, "", "  ")
				t.Errorf("blocked:\n%s\nwant:\n%s", g, w)
			}
			wantCode := 0
			if b, err := os.ReadFile(filepath.Join(dir, "expected", "exit-code")); err == nil {
				if wantCode, err = strconv.Atoi(strings.TrimSpace(string(b))); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(err)
			}
			if code := PlanExitCode(got); code != wantCode {
				t.Errorf("exit code %d, want %d", code, wantCode)
			}
		})
	}
}

func verifiedCase(t *testing.T, name string) *verdict.Verified {
	t.Helper()
	in, err := verdict.ReadInputs(os.DirFS(filepath.Join("..", "..", "pkg", "verdict", "testdata", "inputs", name)),
		"bobthecorp", "keyring.json", "profile.dsse.json", "floor.dsse.json", "bundles")
	if err != nil {
		t.Fatal(err)
	}
	v, err := verdict.VerifyInputs(in, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func readShow(t *testing.T, path string) *tfjson.Plan {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	var p tfjson.Plan
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// TestFloorViolationsModes: a violation blocks only under a blocking floor;
// a control floor raises an advisory default, grandfather blocks until M3.
func TestFloorViolationsModes(t *testing.T) {
	plan := readShow(t, filepath.Join("..", "..", "testdata", "fixtures", "migrate", "18-hard-fail-violations", "preflight.show.json"))
	for _, tc := range []struct {
		inputs, modeFloor string
		want              int
	}{
		{"valid", "", 1},
		{"valid", `{"default":"soft_fail"}`, 0},
		{"valid", `{"default":"advisory"}`, 0},
		{"valid", `{"default":"grandfather"}`, 1},
		{"valid", `{"default":"bogus"}`, 1}, // an unknown floor fails closed
		{"permissive", "", 1},               // advisory default, control floor hard_fail
	} {
		t.Run(tc.inputs+tc.modeFloor, func(t *testing.T) {
			v := verifiedCase(t, tc.inputs)
			if tc.modeFloor != "" {
				p := *v.Profile
				p.ModeFloor = json.RawMessage(tc.modeFloor)
				v.Profile = &p
			}
			got, err := FloorViolations("live/prod", v, plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %+v, want %d entries", got, tc.want)
			}
			for _, b := range got {
				if b.Kind != BlockedFloorViolations || b.Dir != "live/prod" {
					t.Errorf("entry %+v", b)
				}
			}
		})
	}
}

// TestBlockersJSON: a .tf.json file blocks only when it binds a wrapped type
// to hashicorp/<t> (explicitly, on either host, or by its local name), and
// a file that does not parse is an error, never a silent pass.
func TestBlockersJSON(t *testing.T) {
	aws := []Provider{{Type: "aws", To: "registry.compliance.tf/compliancetf/aws"}}
	units := []Unit{{Dir: "."}}
	for _, tc := range []struct {
		name, body string
		blocked    bool
	}{
		{"explicit", `{"terraform":{"required_providers":{"aws":{"source":"hashicorp/aws"}}}}`, true},
		{"opentofu host", `{"terraform":{"required_providers":{"cloud":{"source":"registry.opentofu.org/hashicorp/aws"}}}}`, true},
		{"implied by name", `{"terraform":{"required_providers":{"aws":{"version":"~> 6.0"}}}}`, true},
		{"terraform block list", `{"terraform":[{"required_providers":[{"aws":{"source":"hashicorp/aws"}}]}]}`, true},
		{"other provider", `{"terraform":{"required_providers":{"random":{"source":"hashicorp/random"}}}}`, false},
		{"already wrapped", `{"terraform":{"required_providers":{"aws":{"source":"registry.compliance.tf/compliancetf/aws"}}}}`, false},
		{"no terraform block", `{"resource":{"aws_s3_bucket":{"logs":{"bucket":"bobthecorp-logs"}}}}`, false},
		{"entry that does not evaluate", `{"terraform":{"required_providers":{"cloud":{"source":"${var.s}"}}}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "versions.tf.json"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Blockers(dir, units, aws)
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) == 1) != tc.blocked || len(got) > 1 {
				t.Fatalf("got %+v, want blocked %v", got, tc.blocked)
			}
		})
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "versions.tf.json"), []byte(`{"terraform":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Blockers(dir, units, aws); err == nil {
		t.Fatal("a .tf.json that does not parse passed")
	}

	// Terraform ignores hidden files, so does migrate
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".versions.tf.json"), []byte(`{"terraform":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Blockers(dir, units, aws); err != nil || len(got) != 0 {
		t.Fatalf("hidden .tf.json: got %+v, err %v", got, err)
	}
}

// TestBlockersRemoteModule: the detail of a remote module names the source
// only by its getter, scheme and sha256 (or its registry address), so no byte
// of a source after the scheme reaches blocked[]; a module block without a
// name is an error.
func TestBlockersRemoteModule(t *testing.T) {
	aws := []Provider{{Type: "aws", To: "registry.compliance.tf/compliancetf/aws"}}
	dir := t.TempDir()
	src := "module \"net\" {\n  source  = \"git::https://bob:s3?cret@git.example/infra/net.git//vpc?ref=v1.2.0&sshkey=c2VjcmV0\"\n  version = \"1.2.0\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Blockers(dir, []Unit{{Dir: "."}}, aws)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, err %v", got, err)
	}
	if d := got[0].Detail; !regexp.MustCompile(`^module\.net \(source: git::https sha256:[0-9a-f]{64}, version 1\.2\.0\) is a remote module`).MatchString(d) {
		t.Errorf("detail %q", d)
	}

	sum := regexp.MustCompile(` sha256:[0-9a-f]{64}$`)
	for in, class := range map[string]string{
		"git::https://bob:s3?cret@git.example/infra/net.git//vpc?ref=v1.2.0&sshkey=c2VjcmV0": "git::https",
		"git::https://git.example?token=alice@s3cret":                                        "git::https",
		"git::https://git.example?token=alice@s3cret/tail":                                   "git::https",
		"git@github.com:org/repo.git?token=s3cret&redirect=https://alice@example.com?x=1":    "remote",
		"git::https://bob:p/w@git.example/x.git?ref=v1":                                      "git::https",
		"git::https://bob:pw@git.example/x.git?ref=v1#frag":                                  "git::https",
		"s3::https://s3.amazonaws.com/b/m.zip?X-Amz-Signature=x":                             "s3::https",
		"git@github.com:bobthecorp/net.git?ref=v2":                                           "remote",
		"alice:pw@x://host/y?z@w":                                                            "remote",
		"alice:pw@x://bob@host/y":                                                            "remote",
		"git::alice:pw@x://host/y":                                                           "git",
		"https://alice:pw@host/m.zip":                                                        "https",
		"github.com/bobthecorp/net?ref=v1":                                                   "remote",
		"github.com/bobthecorp/private-net/modules":                                          "remote",
		"GitHub.com/bobthecorp/private-net/modules":                                          "remote",
		"bitbucket.org/bobthecorp/private-net/modules":                                       "remote",
		"example.com/bobthecorp/private-net/MODULES":                                         "remote",
	} {
		out := describeSource(in)
		if !sum.MatchString(out) || sum.ReplaceAllString(out, "") != "source: "+class {
			t.Errorf("describeSource(%q) = %q, want class %q and a sha256", in, out, class)
			continue
		}
		if !strings.HasSuffix(out, fmt.Sprintf("%x", sha256.Sum256([]byte(in)))) {
			t.Errorf("describeSource(%q) = %q: sha256 is not of the source", in, out)
		}
		// the only text besides the sha256 is the class, taken from the
		// source's prefix: no byte after the getter and scheme survives
		if class != "remote" && !strings.HasPrefix(in, class+"://") && !strings.HasPrefix(in, class+"::") {
			t.Errorf("describeSource(%q): class %q is not the source's prefix", in, class)
		}
	}
	for in, want := range map[string]string{
		"bobthecorp/net/aws":                       "registry: registry.terraform.io/bobthecorp/net/aws",
		"app.terraform.io/bobthecorp/net/aws":      "registry: app.terraform.io/bobthecorp/net/aws",
		"bob:pw@app.terraform.io/bobthecorp/n/aws": "",
	} {
		got := describeSource(in)
		if want == "" {
			want = fmt.Sprintf("source: remote sha256:%x", sha256.Sum256([]byte(in)))
		}
		if got != want {
			t.Errorf("describeSource(%q) = %q, want %q", in, got, want)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("module {\n  source = \"git::https://git.example/x.git\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Blockers(dir, []Unit{{Dir: "."}}, aws); err == nil {
		t.Fatal("an unnamed module block passed")
	}
}

// TestRewriteSkipsJSONDeclared: a provider a .tf.json file declares is not
// implied, so the rewrite adds no second required_providers entry for it.
func TestRewriteSkipsJSONDeclared(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"main.tf":          "resource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"bobthecorp-logs\"\n}\n",
		"versions.tf.json": `{"terraform":{"required_providers":{"aws":{"source":"hashicorp/aws"}}}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	edits, err := Rewrite(dir, []Unit{{Dir: "."}}, []Provider{{Type: "aws", To: "registry.compliance.tf/compliancetf/aws"}})
	if err != nil || len(edits) != 0 {
		t.Fatalf("edits %+v, err %v", edits, err)
	}

	// a hidden .tf.json declares nothing: Terraform does not load it
	if err = os.Rename(filepath.Join(dir, "versions.tf.json"), filepath.Join(dir, ".versions.tf.json")); err != nil {
		t.Fatal(err)
	}
	edits, err = Rewrite(dir, []Unit{{Dir: "."}}, []Provider{{Type: "aws", To: "registry.compliance.tf/compliancetf/aws"}})
	if err != nil || len(edits) != 1 || edits[0].File != "versions.tf" {
		t.Fatalf("edits %+v, err %v", edits, err)
	}
}
