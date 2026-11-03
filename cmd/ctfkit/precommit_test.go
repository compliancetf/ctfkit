package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// hook is the part of a .pre-commit-hooks.yaml entry these tests read.
type hook struct {
	ID            string `yaml:"id"`
	Entry         string `yaml:"entry"`
	Language      string `yaml:"language"`
	Files         string `yaml:"files"`
	Exclude       string `yaml:"exclude"`
	PassFilenames bool   `yaml:"pass_filenames"`
	RequireSerial bool   `yaml:"require_serial"`
}

// readHooks returns the hooks in file order.
func readHooks(t *testing.T) []hook {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatalf("read .pre-commit-hooks.yaml: %v", err)
	}
	var hooks []hook
	if unmarshalErr := yaml.Unmarshal(raw, &hooks); unmarshalErr != nil {
		t.Fatalf("parse .pre-commit-hooks.yaml: %v", unmarshalErr)
	}
	return hooks
}

// hookByID returns the one hook with id, failing the test when it is absent.
func hookByID(t *testing.T, hooks []hook, id string) hook {
	t.Helper()
	for _, h := range hooks {
		if h.ID == id {
			return h
		}
	}
	t.Fatalf("no %s hook in .pre-commit-hooks.yaml", id)
	return hook{}
}

// TestPreCommitHooks pins the two hook ids and how each passes its input: the
// file hook gets the staged file names, the directory hook scans the
// repository root once, which is the only mode in which reusable module
// directories are told from deployable roots.
func TestPreCommitHooks(t *testing.T) {
	hooks := readHooks(t)
	// Counted from the list, not a map, so a duplicated id fails here.
	var ids []string
	for _, h := range hooks {
		ids = append(ids, h.ID)
	}
	if want := []string{"ctfkit", "ctfkit-scan-dir"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("hook ids = %q, want %q", ids, want)
	}

	files := hookByID(t, hooks, "ctfkit")
	if !files.PassFilenames || files.Entry != "ctfkit scan --stage pre_plan" {
		t.Errorf("ctfkit hook = %+v, want pass_filenames true and entry %q", files, "ctfkit scan --stage pre_plan")
	}

	dir := hookByID(t, hooks, "ctfkit-scan-dir")
	if dir.PassFilenames || !dir.RequireSerial || dir.Entry != "ctfkit scan --stage pre_plan ." {
		t.Errorf("ctfkit-scan-dir hook = %+v, want pass_filenames false, require_serial true and entry %q",
			dir, "ctfkit scan --stage pre_plan .")
	}

	// Both hooks build the same binary and trigger on the same files; only how
	// they pass their input differs.
	if dir.Language != files.Language || dir.Files != files.Files || dir.Exclude != files.Exclude {
		t.Errorf("ctfkit-scan-dir language/files/exclude = %q/%q/%q, want the ctfkit hook's %q/%q/%q",
			dir.Language, dir.Files, dir.Exclude, files.Language, files.Files, files.Exclude)
	}
}

// TestPreCommitHookFileFilter checks the files and exclude patterns the way
// pre-commit applies them, a regular expression search on the repository
// relative path: every configuration suffix triggers the hooks, and nothing
// under .terraform/ does.
func TestPreCommitHookFileFilter(t *testing.T) {
	for _, h := range readHooks(t) {
		t.Run(h.ID, func(t *testing.T) {
			files, err := regexp.Compile(h.Files)
			if err != nil {
				t.Fatalf("files %q: %v", h.Files, err)
			}
			exclude, err := regexp.Compile(h.Exclude)
			if err != nil {
				t.Fatalf("exclude %q: %v", h.Exclude, err)
			}
			for _, name := range []string{"main.tf", "main.tofu", "modules/a/main.tf.json", "examples/b/main.tofu.json"} {
				if !files.MatchString(name) || exclude.MatchString(name) {
					t.Errorf("%s does not trigger the hook", name)
				}
			}
			for _, name := range []string{"README.md", "terraform.tfvars", "main.tf.bak"} {
				if files.MatchString(name) {
					t.Errorf("%s triggers the hook", name)
				}
			}
			if name := ".terraform/modules/vpc/main.tf"; !exclude.MatchString(name) {
				t.Errorf("exclude %q does not match %s", h.Exclude, name)
			}
		})
	}
}

// TestPreCommitHooksOnAModuleRepository runs each hook's entry the way
// pre-commit does, from the repository root, on the module-repository
// fixture: the file hook reports provider_unpinned in every directory, the
// directory hook only in the example that deploys.
func TestPreCommitHooksOnAModuleRepository(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", "..", "testdata", "origin", "provider_unpinned", "03-module-repo"))
	if err != nil {
		t.Fatal(err)
	}
	var staged []string
	walkErr := filepath.WalkDir(repo, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".tf" {
			return err
		}
		rel, relErr := filepath.Rel(repo, path)
		staged = append(staged, filepath.ToSlash(rel))
		return relErr
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}

	hooks := readHooks(t)
	for _, tc := range []struct {
		id   string
		want []string
	}{
		{"ctfkit", []string{"examples/complete/versions.tf", "modules/sub/versions.tf", "versions.tf", "wrappers/versions.tf"}},
		{"ctfkit-scan-dir", []string{"examples/complete/versions.tf"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			h := hookByID(t, hooks, tc.id)
			args := strings.Fields(h.Entry)[1:]
			args = append(args, "--format", "json", "--fail-on", "never")
			if h.PassFilenames {
				args = append(args, staged...)
			}
			cmd := exec.Command(binaryPath, args...)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
			out, runErr := cmd.Output()
			if runErr != nil {
				t.Fatalf("%v: %v", args, runErr)
			}
			if got := unpinnedURIs(t, out); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("provider_unpinned on %q, want %q", got, tc.want)
			}
		})
	}
}

func unpinnedURIs(t *testing.T, out []byte) []string {
	t.Helper()
	var doc struct {
		Findings []struct {
			RuleID    string `json:"ruleId"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, out)
	}
	got := []string{}
	for _, f := range doc.Findings {
		if f.RuleID != "ctf.origin.provider_unpinned" {
			continue
		}
		if len(f.Locations) == 0 {
			t.Fatalf("a provider_unpinned finding has no location:\n%s", out)
		}
		got = append(got, f.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	sort.Strings(got)
	return got
}
