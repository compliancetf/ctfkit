package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// healthCheck is a module whose check block reads an external data source.
const healthCheck = "check \"health\" {\n  data \"external\" \"probe\" {\n    program = [\"CANARY-probe\"]\n  }\n\n" +
	"  assert {\n    condition     = true\n    error_message = \"x\"\n  }\n}\n"

// rootOnlyWaiver waives ctf.exec.external_data for the root-level subject
// check.health.data.external.probe, and nothing else.
const rootOnlyWaiver = `schema_version: "1.0"
exceptions:
  - rule: ctf.exec.external_data
    resource: check.health.data.external.probe
    justification: "Root-level health probe, reviewed by the platform team."
    approved_by: compliance@bobthecorp.example
    approval_ticket: SEC-1
    review_date: "2027-06-01"
`

// waivedScan runs a pre_plan SARIF scan of repo with the exception file
// registry, expects exit 1, fails on any suppressed ctf.exec.external_data
// result and returns the subjects of those results in output order.
func waivedScan(t *testing.T, repo, registry string) []string {
	t.Helper()
	got := runScanIn(t, repo, "scan", "--stage", "pre_plan", "--format", "sarif", "--catalog", "embedded",
		"--exceptions", registry, ".")
	if got.code != ExitFindings {
		t.Fatalf("exit = %d, want %d (%v):\n%s", got.code, ExitFindings, got.err, got.stdout)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					LogicalLocations []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
					} `json:"logicalLocations"`
				} `json:"locations"`
				Suppressions []json.RawMessage `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &doc); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}
	var subjects []string
	for _, r := range doc.Runs[0].Results {
		if r.RuleID != "ctf.exec.external_data" {
			continue
		}
		if len(r.Suppressions) != 0 {
			t.Errorf("a root-only waiver suppressed a module's finding: %s", got.stdout)
		}
		subjects = append(subjects, r.Locations[0].LogicalLocations[0].FullyQualifiedName)
	}
	return subjects
}

// A ../ source that is a symlink
// is followed to the directory init would install, so the module's finding
// carries its module address. A waiver written for the root-level subject
// check.health.data.external.probe does not cover it. The same directory,
// called a second time through ./wrap, is reported once more under that call
// path, and the two subjects come out sorted.
func TestPrePlanWaiverDoesNotCoverAModuleThroughASymlink(t *testing.T) {
	refuseSwitchesInCI(t)
	t.Setenv("HOME", t.TempDir())
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	writeTree(t, map[string]string{
		filepath.Join(repo, "main.tf"):                "module \"a\" {\n  source = \"../alias\"\n}\n\nmodule \"b\" {\n  source = \"./wrap\"\n}\n",
		filepath.Join(repo, "wrap", "main.tf"):        "module \"c\" {\n  source = \"../../libs/pkg\"\n}\n",
		filepath.Join(base, "libs", "pkg", "main.tf"): healthCheck,
		filepath.Join(base, "exceptions.yaml"):        rootOnlyWaiver,
	})
	if err := os.Symlink(filepath.Join("libs", "pkg"), filepath.Join(base, "alias")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	want := []string{
		"module.a.check.health.data.external.probe",
		"module.b.module.c.check.health.data.external.probe",
	}
	if got := waivedScan(t, repo, filepath.Join(base, "exceptions.yaml")); !slices.Equal(got, want) {
		t.Errorf("external_data subjects = %q, want %q", got, want)
	}
}

// A module block and its override
// name different ../ sources for one call. With the override file sorting
// first, both directories carry module.a, so the root-only waiver suppresses
// neither, the effective module's (../other) included.
func TestPrePlanWaiverDoesNotCoverAnOverriddenModule(t *testing.T) {
	refuseSwitchesInCI(t)
	t.Setenv("HOME", t.TempDir())
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	writeTree(t, map[string]string{
		filepath.Join(repo, "a_override.tf"):    "module \"a\" {\n  source = \"../other\"\n}\n",
		filepath.Join(repo, "main.tf"):          "module \"a\" {\n  source = \"../real\"\n}\n",
		filepath.Join(base, "other", "main.tf"): healthCheck,
		filepath.Join(base, "real", "main.tf"):  healthCheck,
		filepath.Join(base, "exceptions.yaml"):  rootOnlyWaiver,
	})
	want := []string{
		"module.a.check.health.data.external.probe",
		"module.a.check.health.data.external.probe",
	}
	if got := waivedScan(t, repo, filepath.Join(base, "exceptions.yaml")); !slices.Equal(got, want) {
		t.Errorf("external_data subjects = %q, want %q", got, want)
	}
}

// Whitespace in a directory name is not a credential, so
// a finding in "stacks/my module" keeps its path, whatever the rule.
func TestSpacedDirectoryKeepsItsPath(t *testing.T) {
	refuseSwitchesInCI(t)
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	writeTree(t, map[string]string{
		filepath.Join(root, "main.tf"):                        "locals {}\n",
		filepath.Join(root, "stacks", "my module", "main.tf"): originAndSource + provisionedResource("spaced"),
	})
	got := runScanIn(t, root, "scan", "--stage", "pre_plan", "--format", "json", "--catalog", "embedded", ".")
	if got.code != ExitFindings {
		t.Fatalf("exit = %d (%v)", got.code, got.err)
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
	if err := json.Unmarshal([]byte(got.stdout), &doc); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, got.stdout)
	}
	rules := map[string]bool{}
	for _, f := range doc.Findings {
		if uri := f.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "stacks/my module/main.tf" {
			t.Errorf("%s is located at %q, want stacks/my module/main.tf", f.RuleID, uri)
		}
		rules[f.RuleID] = true
	}
	for _, rule := range []string{"ctf.exec.provisioner", "ctf.coverage.module_source", "ctf.policy.floating_ref"} {
		if !rules[rule] {
			t.Errorf("no %s finding:\n%s", rule, got.stdout)
		}
	}
}

// A modules.json record that is not an explicit ../ source
// (here a registry module) and whose directory lies outside the root, named
// directly or through a symlink inside .terraform/modules, is exit 2 with the
// fixed reason and the directory named through the redaction. The directory
// is never opened: it cannot be listed, and the reason is not that.
func TestPlantedModulesJSONOutsideTheRootIsRefused(t *testing.T) {
	refuseSwitchesInCI(t)
	if os.Geteuid() == 0 {
		t.Skip("root lists a directory whatever its mode")
	}
	t.Setenv("HOME", t.TempDir())
	for _, tc := range []struct {
		name  string
		dir   func(input, evil string) string // the recorded Dir, after any setup
		named string
	}{
		{
			name:  "directly",
			dir:   func(string, string) string { return "../" + leakyDir },
			named: "../shared",
		},
		{
			name: "through a symlink",
			dir: func(input, evil string) string {
				if err := os.Symlink(evil, filepath.Join(input, ".terraform", "modules", leakyDir)); err != nil {
					t.Skipf("this filesystem does not support symlinks: %v", err)
				}
				return ".terraform/modules/" + leakyDir
			},
			named: ".terraform/modules/shared",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := copyLocalOutside(t)
			evil := filepath.Join(input, "..", leakyDir)
			writeTree(t, map[string]string{filepath.Join(evil, "main.tf"): provisionedResource("planted")})
			if err := os.Chmod(evil, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(evil, 0o750) }) //nolint:gosec // restores a test directory so TempDir can remove it

			manifest := filepath.Join(input, ".terraform", "modules", "modules.json")
			record := `{"Key":"planted","Source":"bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws","Version":"5.16.1","Dir":"` +
				tc.dir(input, evil) + `"}`
			body := strings.TrimSuffix(strings.TrimSpace(string(readFile(t, manifest))), "]}") + "," + record + "]}"
			if err := os.WriteFile(manifest, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}

			got := runScanIn(t, input, append([]string{"report", "--format", "sarif"}, fixtureContext...)...)
			if got.code != ExitEnvironment || got.err == nil {
				t.Fatalf("exit = %d (%v), want 2", got.code, got.err)
			}
			noCredential(t, map[string]string{"stdout": got.stdout, "stderr": got.stderr, "error": got.err.Error()})
			want := "module directory " + tc.named + " of planted leaves the configuration directory"
			if !strings.Contains(got.err.Error(), want) {
				t.Errorf("error = %v, want one containing %q", got.err, want)
			}
		})
	}
}
