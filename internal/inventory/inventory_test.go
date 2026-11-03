package inventory_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// fixtureRoot is where the recorded report cases live, relative to this
// package. They are the oracle: the expected receipt of each case was frozen
// from the specification, so a test that reproduces its blocks reproduces the
// specification rather than this implementation.
const fixtureRoot = "../../testdata/fixtures/report"

// receiptFile is the recorded projection whose statement blocks this package
// has to reproduce.
const receiptFile = "expected/receipt.json"

// recordedReceipt is the part of a recorded receipt this package answers for.
// Every other field of the statement belongs to another step and is ignored.
type recordedReceipt struct {
	Statement struct {
		Builds                   json.RawMessage `json:"builds"`
		InstancesWithoutManifest json.RawMessage `json:"instancesWithoutManifest"`
		RootResources            json.RawMessage `json:"rootResources"`
	} `json:"statement"`
}

func TestBuild(t *testing.T) {
	cases := []struct {
		name string
		// why names what the case is the oracle for, so a failure reads as a
		// broken rule rather than a broken directory.
		why string
	}{
		{name: "served-leaf", why: "one subtree instance; notApplicable is null, not 0"},
		{name: "example-multi-instance", why: "three instances of one build in one entry"},
		{name: "delegated-with-sibling", why: "a delegated control resolves to the sibling key"},
		{name: "delegated-without-sibling", why: "an unresolved delegated control keeps satisfiedIn []"},
		{name: "missing-manifest", why: "an instance with no manifest is listed, never omitted"},
		{name: "helper-module", why: "a resource-free helper with no manifest is still listed"},
		{name: "degraded-build", why: "posture.degraded is carried in manifest order"},
		{name: "blueprint-wrapper", why: "root resources declared and unattested, superseded pairs"},
		{name: "supporting-clauses", why: "schema 3.4 supporting clauses ride on each control"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(fixtureRoot, tc.name, "input")

			got, err := inventory.Build(loadInventory(t, root), loadConfig(t, root))
			if err != nil {
				t.Fatalf("Build(%s) returned error: %v", tc.name, err)
			}

			want := loadReceipt(t, filepath.Join(fixtureRoot, tc.name, receiptFile))

			assertJSONEqual(t, "builds", got.Builds, want.Statement.Builds, tc.why)
			assertJSONEqual(t, "instancesWithoutManifest", got.InstancesWithoutManifest,
				want.Statement.InstancesWithoutManifest, tc.why)
			assertJSONEqual(t, "rootResources", got.RootResources, want.Statement.RootResources, tc.why)
		})
	}
}

// TestBuildRejectsNilInventory checks the one error the function returns. A
// nil inventory means the caller ran before post_init, which is a caller bug
// and not a finding.
func TestBuildRejectsNilInventory(t *testing.T) {
	if _, err := inventory.Build(nil, nil); err == nil {
		t.Fatal("Build(nil, nil) returned no error, want one")
	}
}

// TestBuildGroupsByServedBuild checks that the grouping key is the manifest's
// own (registry_source, version) pair and not the modules.json source, which
// differs per submodule.
func TestBuildGroupsByServedBuild(t *testing.T) {
	inv := &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
		instanceWith("second", "bobthecorp.compliance.tf/s3-bucket/aws//modules/notification", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
			control("c_one", ctfkit.ManifestControlEnforced, nil))),
		instanceWith("first", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
			control("c_one", ctfkit.ManifestControlEnforced, nil))),
		instanceWith("other", "bobthecorp.compliance.tf/vpc/aws", manifest("bobthecorp.compliance.tf/vpc/aws", "2.0.0", ".",
			control("c_two", ctfkit.ManifestControlEnforced, nil))),
	}}

	got, err := inventory.Build(inv, nil)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if len(got.Builds) != 2 {
		t.Fatalf("Builds has %d entries, want 2", len(got.Builds))
	}
	if got.Builds[0].Source != "bobthecorp.compliance.tf/s3-bucket/aws" || got.Builds[1].Source != "bobthecorp.compliance.tf/vpc/aws" {
		t.Fatalf("builds are ordered %q, %q; want acme/s3 then acme/vpc",
			got.Builds[0].Source, got.Builds[1].Source)
	}
	if want := []string{"first", "second"}; !reflect.DeepEqual(got.Builds[0].Keys, want) {
		t.Errorf("Keys = %v, want %v (ascending byte order)", got.Builds[0].Keys, want)
	}
	if want := []string{"first", "second"}; !reflect.DeepEqual(got.Builds[0].Controls[0].SatisfiedIn, want) {
		t.Errorf("SatisfiedIn = %v, want %v", got.Builds[0].Controls[0].SatisfiedIn, want)
	}
}

// TestBuildControlVocabulary pins each status word to the manifest shape that
// produces it. The vocabulary is closed: nothing else may appear.
func TestBuildControlVocabulary(t *testing.T) {
	cases := []struct {
		name       string
		instances  []ctfkit.ModuleInstance
		wantStatus inventory.ControlStatus
		wantIn     []string
	}{
		{
			name: "enforced when a manifest holds the evidence",
			instances: []ctfkit.ModuleInstance{
				instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
					control("c_one", ctfkit.ManifestControlEnforced, nil))),
			},
			wantStatus: inventory.ControlEnforced,
			wantIn:     []string{"pkg"},
		},
		{
			name: "delegated resolves against an instantiated sibling scope",
			instances: []ctfkit.ModuleInstance{
				instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
					control("c_one", ctfkit.ManifestControlDelegated, []string{"modules/child"}))),
				instanceWith("child", "bobthecorp.compliance.tf/s3-bucket/aws//modules/child",
					manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", "modules/child",
						control("c_one", ctfkit.ManifestControlEnforced, []string{"modules/child"}))),
			},
			wantStatus: inventory.ControlEnforced,
			wantIn:     []string{"child"},
		},
		{
			name: "delegated stays unresolved when no sibling governs the scope",
			instances: []ctfkit.ModuleInstance{
				instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
					control("c_one", ctfkit.ManifestControlDelegated, []string{"modules/child"}))),
			},
			wantStatus: inventory.ControlDelegated,
			wantIn:     []string{},
		},
		{
			name: "delegated stays unresolved when the enforcing scope is not the delegated one",
			instances: []ctfkit.ModuleInstance{
				instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
					control("c_one", ctfkit.ManifestControlDelegated, []string{"modules/child"}))),
				instanceWith("other", "bobthecorp.compliance.tf/s3-bucket/aws//modules/other",
					manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", "modules/other",
						control("c_one", ctfkit.ManifestControlEnforced, []string{"modules/other"}))),
			},
			wantStatus: inventory.ControlDelegated,
			wantIn:     []string{},
		},
		{
			name: "not applicable when the build declares the control out of scope",
			instances: []ctfkit.ModuleInstance{
				withNotApplicable(
					instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
						control("c_one", ctfkit.ManifestControlDelegated, []string{"modules/child"}))),
					"c_one"),
			},
			wantStatus: inventory.ControlNotApplicable,
			wantIn:     []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inventory.Build(&ctfkit.ModuleInventory{Instances: tc.instances}, nil)
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}
			if len(got.Builds) != 1 || len(got.Builds[0].Controls) != 1 {
				t.Fatalf("got %d builds, want exactly one build with one control", len(got.Builds))
			}

			control := got.Builds[0].Controls[0]
			if control.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", control.Status, tc.wantStatus)
			}
			if !reflect.DeepEqual(control.SatisfiedIn, tc.wantIn) {
				t.Errorf("SatisfiedIn = %v, want %v", control.SatisfiedIn, tc.wantIn)
			}
		})
	}
}

// TestBuildRecordsBuildLevelFactsOnce checks that a record the producer
// stamps into every manifest of a build is carried once. Three instances of a
// build whose posture was degraded for one reason report that one reason, not
// three.
func TestBuildRecordsBuildLevelFactsOnce(t *testing.T) {
	instances := make([]ctfkit.ModuleInstance, 0, 3)
	for _, key := range []string{"archive", "artifacts", "data"} {
		m := manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
			control("c_one", ctfkit.ManifestControlEnforced, nil))
		m.Posture.Degraded = []string{"org-rules-unavailable"}
		m.Build.ControlsSuperseded = map[string]string{"c_weak": "c_one"}
		m.OperationalRules = []ctfkit.ManifestOperationalRule{
			{Rule: "example/prevent_destroy_data", Outcome: "enforced"},
		}
		instances = append(instances, instanceWith(key, "bobthecorp.compliance.tf/s3-bucket/aws", m))
	}

	got, err := inventory.Build(&ctfkit.ModuleInventory{Instances: instances}, nil)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	build := got.Builds[0]
	if want := []string{"org-rules-unavailable"}; !reflect.DeepEqual(build.Degraded, want) {
		t.Errorf("Degraded = %v, want %v", build.Degraded, want)
	}
	if want := []inventory.OperationalRule{
		{Rule: "example/prevent_destroy_data", Outcome: "enforced"},
	}; !reflect.DeepEqual(build.OperationalRules, want) {
		t.Errorf("OperationalRules = %v, want %v", build.OperationalRules, want)
	}
	if want := map[string]string{"c_weak": "c_one"}; !reflect.DeepEqual(build.Superseded, want) {
		t.Errorf("Superseded = %v, want %v", build.Superseded, want)
	}
}

// TestBuildReadsBuildLevelFactsFromThePackageManifest checks which manifest
// answers for the build-level records when a configuration instantiates the
// package root and a subtree of it. Only a package-scope manifest carries
// them, and it is not always the first instance by key.
func TestBuildReadsBuildLevelFactsFromThePackageManifest(t *testing.T) {
	subtree := manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", "modules/child",
		control("c_one", ctfkit.ManifestControlEnforced, []string{"modules/child"}))
	pkg := manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
		control("c_one", ctfkit.ManifestControlDelegated, []string{"modules/child"}))
	pkg.Build.ControlsNotApplicable = []string{"c_two", "c_three"}
	pkg.Posture.Degraded = []string{"baseline-not-authored"}

	got, err := inventory.Build(&ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
		// "a_child" sorts before "pkg", so a record taken from the first
		// instance in key order would take the subtree's absent one.
		instanceWith("a_child", "bobthecorp.compliance.tf/s3-bucket/aws//modules/child", subtree),
		instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", pkg),
	}}, nil)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	build := got.Builds[0]
	if build.NotApplicable == nil {
		t.Fatalf("NotApplicable = null, want 2")
	}
	if *build.NotApplicable != 2 {
		t.Errorf("NotApplicable = %d, want 2", *build.NotApplicable)
	}
	if want := []string{"baseline-not-authored"}; !reflect.DeepEqual(build.Degraded, want) {
		t.Errorf("Degraded = %v, want %v", build.Degraded, want)
	}
}

// TestBuildRecordsDelegatedScopes checks that an unresolved delegated control
// keeps the scope it was delegated to. The analyzer names that scope in its
// finding, and nothing else in the pipeline reads a manifest.
func TestBuildRecordsDelegatedScopes(t *testing.T) {
	inv := &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
		instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
			control("c_one", ctfkit.ManifestControlDelegated, []string{"modules/child"}))),
	}}

	got, err := inventory.Build(inv, nil)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	want := []string{"modules/child"}
	if gotScopes := got.Builds[0].Controls[0].DelegatedTo; !reflect.DeepEqual(gotScopes, want) {
		t.Errorf("DelegatedTo = %v, want %v", gotScopes, want)
	}
}

// TestBuildRootResourceCoverage pins the coverage word to the root's own
// resource blocks and imported runs. A test never upgrades a resource past
// tested, because a passing test is evidence of behavior and a manifest is
// evidence of a built-in control.
func TestBuildRootResourceCoverage(t *testing.T) {
	const twoResources = `resource "aws_sns_topic" "a" { name = "a" }
resource "aws_sqs_queue" "b" { name = "b" }
data "aws_caller_identity" "c" {}
`

	cases := []struct {
		name         string
		files        []ctfkit.ConfigFile
		tests        *ctfkit.TestRun
		wantDeclared int
		wantCoverage inventory.ResourceCoverage
	}{
		{
			name:         "no resources of its own",
			files:        []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(`module "m" { source = "x" }`)}},
			wantDeclared: 0,
			wantCoverage: inventory.CoverageNotApplicable,
		},
		{
			name:         "declared resources with no imported run",
			files:        []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(twoResources)}},
			wantDeclared: 2,
			wantCoverage: inventory.CoverageUnattested,
		},
		{
			name:         "declared resources with an imported run",
			files:        []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(twoResources)}},
			tests:        &ctfkit.TestRun{Runs: 1, Passed: 1},
			wantDeclared: 2,
			wantCoverage: inventory.CoverageTested,
		},
		{
			name:         "an imported run with no run block covers nothing",
			files:        []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(twoResources)}},
			tests:        &ctfkit.TestRun{},
			wantDeclared: 2,
			wantCoverage: inventory.CoverageUnattested,
		},
		{
			name: "a nested local module is not the root configuration",
			files: []ctfkit.ConfigFile{
				{Path: "main.tf", Bytes: []byte(`module "m" { source = "./modules/x" }`)},
				{Path: "modules/x/main.tf", Bytes: []byte(twoResources)},
			},
			wantDeclared: 0,
			wantCoverage: inventory.CoverageNotApplicable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := &ctfkit.ModuleInventory{Tests: tc.tests}

			got, err := inventory.Build(inv, &ctfkit.ConfigArchive{Root: ".", Files: tc.files})
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}
			if got.RootResources.Declared != tc.wantDeclared {
				t.Errorf("Declared = %d, want %d", got.RootResources.Declared, tc.wantDeclared)
			}
			if got.RootResources.Coverage != tc.wantCoverage {
				t.Errorf("Coverage = %q, want %q", got.RootResources.Coverage, tc.wantCoverage)
			}
		})
	}
}

// TestBuildListsInstancesWithoutManifest checks that an instance with no
// manifest is reported as not-evidence and sorted by key, never dropped and
// never grouped into a build.
func TestBuildListsInstancesWithoutManifest(t *testing.T) {
	inv := &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
		{Key: "zeta", Source: "./modules/zeta"},
		instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
			control("c_one", ctfkit.ManifestControlEnforced, nil))),
		{Key: "alpha", Source: "./modules/alpha"},
	}}

	got, err := inventory.Build(inv, nil)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	want := []inventory.Instance{
		{Key: "alpha", Source: "./modules/alpha"},
		{Key: "zeta", Source: "./modules/zeta"},
	}
	if !reflect.DeepEqual(got.InstancesWithoutManifest, want) {
		t.Errorf("InstancesWithoutManifest = %v, want %v", got.InstancesWithoutManifest, want)
	}
	if len(got.Builds) != 1 || len(got.Builds[0].Keys) != 1 {
		t.Errorf("an instance without a manifest was grouped into a build: %+v", got.Builds)
	}
}

// TestBuildNotApplicableIsTriState checks the difference between a build that
// classified and found none and a manifest that never classified. Zero would
// assert an evaluation that a subtree manifest never records.
func TestBuildNotApplicableIsTriState(t *testing.T) {
	cases := []struct {
		name    string
		listed  []string
		wantNil bool
		want    int
	}{
		{name: "never classified", listed: nil, wantNil: true},
		{name: "classified and found none", listed: []string{}, want: 0},
		{name: "classified and found some", listed: []string{"c_two", "c_three"}, want: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			instance := instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws", manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".",
				control("c_one", ctfkit.ManifestControlEnforced, nil)))
			instance.Manifest.Build.ControlsNotApplicable = tc.listed

			got, err := inventory.Build(&ctfkit.ModuleInventory{
				Instances: []ctfkit.ModuleInstance{instance},
			}, nil)
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}

			na := got.Builds[0].NotApplicable
			if tc.wantNil {
				if na != nil {
					t.Fatalf("NotApplicable = %d, want null", *na)
				}
				return
			}
			if na == nil {
				t.Fatalf("NotApplicable = null, want %d", tc.want)
			}
			if *na != tc.want {
				t.Errorf("NotApplicable = %d, want %d", *na, tc.want)
			}
		})
	}
}

// TestBuildSupportingClausesAreASubset pins how the schema 3.4 supporting
// clauses reach the record. Absent stays nil (unknown, never "nothing
// hedged"); present is filtered to the clauses the control lists, in their
// listed order, so a manifest cannot hedge a clause it never claimed; and a
// framework the producer left out of the supporting map stays out, because an
// empty list there would read as "nothing hedged".
func TestBuildSupportingClausesAreASubset(t *testing.T) {
	cases := []struct {
		name       string
		clauses    map[string][]string
		supporting map[string][]string
		want       map[string][]string
	}{
		{name: "absent is unknown", clauses: map[string][]string{"soc_2": {"CC6.1 a"}}},
		{
			name:       "classified and nothing hedged",
			clauses:    map[string][]string{"soc_2": {"CC6.1 a"}},
			supporting: map[string][]string{"soc_2": {}},
			want:       map[string][]string{"soc_2": {}},
		},
		{
			name:       "filtered in listed order, unlisted clause dropped",
			clauses:    map[string][]string{"soc_2": {"CC6.1 a", "CC7.2 b", "CC7.3 c"}},
			supporting: map[string][]string{"soc_2": {"CC7.3 c", "CC9.9 never listed", "CC6.1 a"}},
			want:       map[string][]string{"soc_2": {"CC6.1 a", "CC7.3 c"}},
		},
		{
			name:       "a framework missing from the supporting map stays unknown",
			clauses:    map[string][]string{"soc_2": {"CC6.1 a"}, "pci_dss_v40": {"3.4 x"}},
			supporting: map[string][]string{"soc_2": {"CC6.1 a"}, "hipaa": {"164.312 y"}},
			want:       map[string][]string{"soc_2": {"CC6.1 a"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := control("c_one", ctfkit.ManifestControlEnforced, nil)
			entry.ClausesByFramework = tc.clauses
			entry.SupportingClausesByFramework = tc.supporting
			instance := instanceWith("pkg", "bobthecorp.compliance.tf/s3-bucket/aws",
				manifest("bobthecorp.compliance.tf/s3-bucket/aws", "1.0.0", ".", entry))

			got, err := inventory.Build(&ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{instance}}, nil)
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}

			supporting := got.Builds[0].Controls[0].SupportingClausesByFramework
			if tc.want == nil {
				if supporting != nil {
					t.Fatalf("SupportingClausesByFramework = %v, want nil (unknown)", supporting)
				}
				return
			}
			if !reflect.DeepEqual(supporting, tc.want) {
				t.Errorf("SupportingClausesByFramework = %#v, want %#v", supporting, tc.want)
			}
		})
	}
}

// TestBuildCarriesNoScore guards the vocabulary from the other side: no
// projection this package feeds may carry a severity, a weight or a
// percentage, so no rendered byte of it may contain a percent sign.
func TestBuildCarriesNoScore(t *testing.T) {
	root := filepath.Join(fixtureRoot, "blueprint-wrapper", "input")

	got, err := inventory.Build(loadInventory(t, root), loadConfig(t, root))
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshaling the inventory: %v", err)
	}
	for _, banned := range []string{"%", "severity", "score", "weight"} {
		if strings.Contains(strings.ToLower(string(encoded)), banned) {
			t.Errorf("the rendered inventory contains %q", banned)
		}
	}
}

// loadInventory reads a fixture's recorded module tree.
func loadInventory(t *testing.T, root string) *ctfkit.ModuleInventory {
	t.Helper()

	inv, err := loader.LoadModules(root)
	if err != nil {
		t.Fatalf("LoadModules(%s): %v", root, err)
	}

	testsPath := filepath.Join(root, "tests.json")
	if _, statErr := os.Stat(testsPath); statErr == nil {
		run, importErr := loader.ImportTests(testsPath)
		if importErr != nil {
			t.Fatalf("ImportTests(%s): %v", testsPath, importErr)
		}
		inv.Tests = run
	}

	return inv
}

// loadConfig reads a fixture's root configuration.
func loadConfig(t *testing.T, root string) *ctfkit.ConfigArchive {
	t.Helper()

	cfg, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", root, err)
	}

	return cfg
}

// loadReceipt reads the recorded receipt of a fixture case.
func loadReceipt(t *testing.T, path string) recordedReceipt {
	t.Helper()

	content, err := os.ReadFile(path) //nolint:gosec // a committed fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var receipt recordedReceipt
	if unmarshalErr := json.Unmarshal(content, &receipt); unmarshalErr != nil {
		t.Fatalf("parsing %s: %v", path, unmarshalErr)
	}

	return receipt
}

// assertJSONEqual compares a built block against the recorded bytes of the
// same block. The comparison is over the decoded documents, so it asserts the
// JSON field names and the array order this package has to produce without
// asserting a key order the renderer decides.
func assertJSONEqual(t *testing.T, block string, got any, want json.RawMessage, why string) {
	t.Helper()

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshaling %s: %v", block, err)
	}

	var gotDoc, wantDoc any
	if unmarshalErr := json.Unmarshal(encoded, &gotDoc); unmarshalErr != nil {
		t.Fatalf("parsing the built %s: %v", block, unmarshalErr)
	}
	if unmarshalErr := json.Unmarshal(want, &wantDoc); unmarshalErr != nil {
		t.Fatalf("parsing the recorded %s: %v", block, unmarshalErr)
	}

	if !reflect.DeepEqual(gotDoc, wantDoc) {
		wantPretty, _ := json.MarshalIndent(wantDoc, "", "  ")
		gotPretty, _ := json.MarshalIndent(gotDoc, "", "  ")
		t.Errorf("%s does not match the recorded receipt (%s)\n got: %s\nwant: %s",
			block, why, gotPretty, wantPretty)
	}
}

// manifest builds the smallest manifest a unit case needs.
func manifest(source, version, scopePath string, controls ...ctfkit.ManifestControl) *ctfkit.Manifest {
	return &ctfkit.Manifest{
		SchemaVersion: "3.3",
		ScopePath:     scopePath,
		Module: ctfkit.ManifestModule{
			RegistrySource: source,
			Version:        version,
			Frameworks:     []string{"soc_2"},
			FrameworkNames: map[string]string{"soc_2": "SOC 2"},
		},
		Controls: controls,
	}
}

// control builds one manifest control entry.
func control(id, status string, appliesIn []string) ctfkit.ManifestControl {
	return ctfkit.ManifestControl{
		ControlID:          id,
		Name:               "control " + id,
		Status:             status,
		AppliesIn:          appliesIn,
		ClausesByFramework: map[string][]string{"soc_2": {"CC6.1 clause text"}},
	}
}

// instanceWith builds one module instance around a manifest.
func instanceWith(key, source string, m *ctfkit.Manifest) ctfkit.ModuleInstance {
	return ctfkit.ModuleInstance{
		Key:        key,
		Source:     source,
		Dir:        ".terraform/modules/" + key,
		Manifest:   m,
		Provenance: ctfkit.ProvenanceLocalUnverified,
	}
}

// withNotApplicable records control ids the build evaluated and found no
// resource of their target type for.
func withNotApplicable(instance ctfkit.ModuleInstance, ids ...string) ctfkit.ModuleInstance {
	instance.Manifest.Build.ControlsNotApplicable = ids

	return instance
}
