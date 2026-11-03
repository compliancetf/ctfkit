package cli

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// unpinnedFixture is the absolute path of a provider_unpinned fixture tree, resolved
// before runScanIn changes the working directory.
func unpinnedFixture(t *testing.T, name string) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "origin", "provider_unpinned", name))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// unpinnedFiles runs scan from dir and returns the sorted files of its
// ctf.origin.provider_unpinned findings.
func unpinnedFiles(t *testing.T, dir string, args ...string) []string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	res := runScanIn(t, dir, append([]string{"scan", "--stage", "pre_plan", "--format", "json", "--fail-on", "never"}, args...)...)
	if res.code != 0 {
		t.Fatalf("scan %v exit = %d, stderr %q", args, res.code, res.stderr)
	}
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
	if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	out := []string{}
	for _, f := range doc.Findings {
		if f.RuleID == "ctf.origin.provider_unpinned" {
			out = append(out, f.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	}
	sort.Strings(out)
	return out
}

func wantFiles(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("provider_unpinned on %q\n                   want %q", got, want)
	}
}

// A directory scan does not report an unbounded requirement in a reusable
// module directory; an explicit file list reports every one.
func TestScanProviderUnpinnedDirectoryAndFileList(t *testing.T) {
	dir := unpinnedFixture(t, "03-module-repo")

	wantFiles(t, unpinnedFiles(t, dir, "."), "examples/complete/versions.tf")

	wantFiles(t, unpinnedFiles(t, dir,
		"main.tf", "versions.tf",
		"modules/sub/main.tf", "modules/sub/versions.tf",
		"wrappers/main.tf", "wrappers/versions.tf",
		"examples/complete/main.tf", "examples/complete/providers.tf", "examples/complete/versions.tf",
	),
		"examples/complete/versions.tf", "modules/sub/versions.tf", "versions.tf", "wrappers/versions.tf")
}

// The documented remedies for the two false negatives of the classification
// round-trip: a directory the tree scan treats as a module is reported when
// it is scanned on its own, or when its files are passed as a list.
func TestScanProviderUnpinnedFalseNegativeRemedies(t *testing.T) {
	// Both paths are resolved before the first scan changes directory.
	fn1 := unpinnedFixture(t, "09-fn-uncalled-deployable")
	fn2 := unpinnedFixture(t, "13-fn-called-deployable")

	// (i) nothing marks live/app as a root in the tree.
	wantFiles(t, unpinnedFiles(t, fn1, "."), "versions.tf")
	wantFiles(t, unpinnedFiles(t, filepath.Join(fn1, "live", "app"), "."), "versions.tf")

	// (ii) a root in the same tree calls app and the scan root.
	wantFiles(t, unpinnedFiles(t, fn2, "."), "examples/complete/versions.tf")
	wantFiles(t, unpinnedFiles(t, filepath.Join(fn2, "app"), "."), "versions.tf")
	// The scan root's caller sits below it, so scanning it on its own still
	// reads the caller; its own files as a list do not.
	wantFiles(t, unpinnedFiles(t, fn2, "main.tf", "providers.tf", "versions.tf"), "versions.tf")
}

// The SARIF rule entry of ctf.origin.provider_unpinned carries its help text,
// which names the known misses; a rule with no help text has no help member.
func TestScanProviderUnpinnedSARIFHelp(t *testing.T) {
	dir := unpinnedFixture(t, "02-bare-root")
	t.Setenv("HOME", t.TempDir())
	res := runScanIn(t, dir, "scan", "--stage", "pre_plan", ".", "--format", "sarif", "--fail-on", "never")
	if res.code != 0 {
		t.Fatalf("scan exit = %d, stderr %q", res.code, res.stderr)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID   string `json:"id"`
						Help *struct {
							Text string `json:"text"`
						} `json:"help"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	seen := false
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		switch {
		case r.ID == "ctf.origin.provider_unpinned":
			seen = true
			if r.Help == nil || !strings.Contains(r.Help.Text, "Known misses") {
				t.Errorf("provider_unpinned help = %+v, want the known misses", r.Help)
			}
		case r.Help != nil:
			t.Errorf("%s has a help member with no help text defined", r.ID)
		}
	}
	if !seen {
		t.Fatal("no provider_unpinned rule entry; the fixture no longer exercises it")
	}
}
