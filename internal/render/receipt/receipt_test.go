package receipt_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/render/receipt"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// update re-records the committed receipts. The fixture pack states that
// nothing under testdata/ is generated at test time, so this flag is for a
// deliberate re-record after a specification change and is never part of a
// normal run: the committed bytes are the oracle, and a renderer that
// rewrites its own oracle proves nothing.
var update = flag.Bool("update", false, "re-record expected/receipt.json of every case from the current renderer")

// repoRoot is where every test in this package runs from; see TestMain.
const repoRoot = "../../.."

// fixtureRoot is where the recorded report cases live, relative to repoRoot.
const fixtureRoot = "testdata/fixtures/report"

// receiptFile is the recorded projection this package answers for, whole.
const receiptFile = "expected/receipt.json"

// schemaFile is the published envelope the rendered bytes must satisfy.
const schemaFile = "schema/receipt-1.schema.json"

// The run context every recorded receipt was frozen with. The receipt records
// the run clock rather than reading one, which is what lets a fixture be an
// oracle on any day.
var fixtureMetadata = ctfkit.RunMetadata{
	RunID:    "ctfkit-fixture-run",
	Platform: "local",
	Commit:   "0000000000000000000000000000000000000000",
	Now:      time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
}

var fixtureGenerator = receipt.Generator{Name: "ctfkit", Version: "1.0.0"}

// TestMain runs the whole package from the repository root. The recorded
// receipts name their subject as the path the recording command was given,
// and that command was run from the repository root, so the test has to be
// too: the receipt records the root verbatim rather than resolving it, and a
// subject that depended on the reader's working directory would name a
// different configuration on every machine.
func TestMain(m *testing.M) {
	flag.Parse()
	if err := os.Chdir(repoRoot); err != nil {
		panic("receipt tests: " + err.Error())
	}
	os.Exit(m.Run())
}

type reportCase struct {
	name string
	// why names what the case is the oracle for, so a failure reads as a
	// broken rule rather than a broken directory.
	why string
	// tests is the imported test document the case renders, nil when the case
	// imported none. The counts are the recorded run's own summary; the
	// digest is computed from the file so a re-recorded fixture cannot drift
	// from the bytes beside it.
	tests *ctfkit.TestRun
}

// reportCases are every recorded case that renders a receipt.
// report/schema-4-stub is deliberately absent: it records exit code 2 and
// stderr, because the command stops on an unsupported schema major before any
// projection exists.
func reportCases() []reportCase {
	return []reportCase{
		{name: "served-leaf", why: "absent notApplicable stays null, empty superseded, no findings"},
		{name: "blueprint-wrapper", why: "root resources declared and unattested, superseded pairs"},
		{
			name:  "example-multi-instance",
			why:   "inputs.tests, three manifest entries for one build, multi-key build",
			tests: &ctfkit.TestRun{Runs: 3, Passed: 2, Failed: 1},
		},
		{name: "degraded-build", why: "degraded[], four findings in analyzer order, unknown obligation token"},
		{name: "missing-manifest", why: "an instance with no manifest is listed, never omitted"},
		{name: "helper-module", why: "a resource-free helper is listed with no manifest_missing finding"},
		{name: "delegated-with-sibling", why: "satisfiedIn on a resolved delegated control, nine obligations"},
		{name: "delegated-without-sibling", why: "satisfiedIn stays [] on an unresolved delegated control"},
		{name: "supporting-clauses", why: "schema 3.4 supportingClausesByFramework, [] when classified and nothing hedged"},
	}
}

// TestRenderGolden is the whole contract: the rendered bytes are the recorded
// bytes, byte for byte, because the statement is what a future signature will
// cover.
func TestRenderGolden(t *testing.T) {
	for _, tc := range reportCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := receipt.Render(inputFor(t, tc))
			if err != nil {
				t.Fatalf("Render(%s) returned error: %v", tc.name, err)
			}

			path := filepath.Join(fixtureRoot, tc.name, receiptFile)
			if *update {
				if writeErr := os.WriteFile(path, got, 0o644); writeErr != nil {
					t.Fatalf("re-recording %s: %v", path, writeErr)
				}
				t.Logf("re-recorded %s", path)
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			if string(got) != string(want) {
				t.Errorf("rendered receipt differs from %s (%s)\n got: %s\nwant: %s",
					path, tc.why, firstDifference(got, want), tc.why)
			}
		})
	}
}

// TestRenderEndsWithoutNewline pins the one whitespace rule a diff of two JSON
// documents hides: canonical JSON has no trailing newline, and a signature
// over the file would not cover one.
func TestRenderEndsWithoutNewline(t *testing.T) {
	for _, tc := range reportCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := receipt.Render(inputFor(t, tc))
			if err != nil {
				t.Fatalf("Render returned error: %v", err)
			}
			if len(got) == 0 || got[len(got)-1] != '}' {
				t.Errorf("receipt ends with %q, want the closing brace and nothing after it", lastByte(got))
			}
		})
	}
}

// TestRenderValidatesAgainstSchema checks the rendered bytes against the
// published envelope rather than against the recorded file, so a fixture and a
// renderer cannot agree on a shape the schema refuses.
func TestRenderValidatesAgainstSchema(t *testing.T) {
	schema := compileSchema(t)

	for _, tc := range reportCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := receipt.Render(inputFor(t, tc))
			if err != nil {
				t.Fatalf("Render returned error: %v", err)
			}

			var doc any
			if err := json.Unmarshal(got, &doc); err != nil {
				t.Fatalf("rendered receipt is not JSON: %v", err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("rendered receipt fails %s: %v", schemaFile, err)
			}
		})
	}
}

// TestStatementReserializesToTheSameDigest is the canonical-ordering proof.
// A signature covers the statement bytes, so parsing the statement and
// serializing it again has to reproduce them: any ordering that depends on map
// iteration or on struct field order would produce a second digest here.
func TestStatementReserializesToTheSameDigest(t *testing.T) {
	for _, tc := range reportCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := receipt.Render(inputFor(t, tc))
			if err != nil {
				t.Fatalf("Render returned error: %v", err)
			}

			var doc struct {
				Statement json.RawMessage `json:"statement"`
			}
			if parseErr := json.Unmarshal(got, &doc); parseErr != nil {
				t.Fatalf("rendered receipt is not JSON: %v", parseErr)
			}

			again, err := jcs.Transform(doc.Statement)
			if err != nil {
				t.Fatalf("Transform returned error: %v", err)
			}
			if first, second := digest(doc.Statement), digest(again); first != second {
				t.Errorf("statement digest changed on re-serialization: %s then %s", first, second)
			}
		})
	}
}

// TestRenderWatermarkBanner guards the one envelope field an operator can
// influence: absent with no --watermark, the banner verbatim when set, and
// refused when it is not one printable line.
func TestRenderWatermarkBanner(t *testing.T) {
	in := inputFor(t, reportCase{name: "served-leaf"})

	plain, err := receipt.Render(in)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if strings.Contains(string(plain), `"watermark"`) {
		t.Errorf("a receipt with no --watermark carries a watermark key:\n%s", plain)
	}

	// An escape sequence would let banner text rewrite what a terminal shows
	// around it, and a second line is not a banner line.
	for _, bad := range []string{"reviewed internally\nand again", "reviewed\x1b[2Kinternally"} {
		in.Watermark = bad
		if _, renderErr := receipt.Render(in); renderErr == nil {
			t.Errorf("Render accepted the watermark %q, want an error", bad)
		}
	}

	in.Watermark = "reviewed internally"
	got, err := receipt.Render(in)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	var doc struct {
		Watermark string `json:"watermark"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("rendered receipt is not JSON: %v", err)
	}
	if want := "reviewed internally"; doc.Watermark != want {
		t.Errorf("watermark = %q, want %q", doc.Watermark, want)
	}
}

// TestRenderRejectsMissingInputs checks the three callers' bugs that would
// otherwise render a receipt asserting less than it looks like it asserts.
func TestRenderRejectsMissingInputs(t *testing.T) {
	valid := inputFor(t, reportCase{name: "served-leaf"})

	cases := map[string]func(*receipt.Input){
		"no inventory":         func(in *receipt.Input) { in.Inventory = nil },
		"no modules":           func(in *receipt.Input) { in.Modules = nil },
		"no modules.json hash": func(in *receipt.Input) { in.ModulesJSONSHA256 = "" },
		"no run clock":         func(in *receipt.Input) { in.Metadata.Now = time.Time{} },
		"no generator name":    func(in *receipt.Input) { in.Generator.Name = "" },
		"no generator version": func(in *receipt.Input) { in.Generator.Version = "" },
	}

	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			in := valid
			corrupt(&in)
			if _, err := receipt.Render(in); err == nil {
				t.Errorf("Render accepted an input with %s, want an error", name)
			}
		})
	}
}

// TestVerdictIgnoresTheFailOnThreshold pins the rule the appendix wording does
// not: the verdict is fail when any unsuppressed error-level finding exists,
// whatever --fail-on was set to, which is what makes a shadow-mode run's
// evidence worth keeping.
func TestVerdictIgnoresTheFailOnThreshold(t *testing.T) {
	cases := []struct {
		name     string
		findings ctfkit.Findings
		want     string
	}{
		{name: "no findings", want: "pass"},
		{
			name:     "warnings and notes only",
			findings: ctfkit.Findings{levelOnly(ctfkit.LevelWarning), levelOnly(ctfkit.LevelNote)},
			want:     "pass",
		},
		{
			name:     "one error among notes",
			findings: ctfkit.Findings{levelOnly(ctfkit.LevelNote), levelOnly(ctfkit.LevelError)},
			want:     "fail",
		},
		{
			// An allowed exception is the whole of what a waiver buys: the
			// finding is still recorded, and it stops driving the verdict.
			name:     "the only error is suppressed",
			findings: ctfkit.Findings{levelOnly(ctfkit.LevelWarning), allowed(levelOnly(ctfkit.LevelError))},
			want:     "pass",
		},
		{
			name:     "a suppressed error beside an unsuppressed one",
			findings: ctfkit.Findings{allowed(levelOnly(ctfkit.LevelError)), levelOnly(ctfkit.LevelError)},
			want:     "fail",
		},
		{
			// An exception that was found but is out of its review window is
			// recorded with allowed false, and a waiver nobody renewed cannot
			// quietly keep passing the run.
			name:     "an expired waiver still counts",
			findings: ctfkit.Findings{expired(levelOnly(ctfkit.LevelError))},
			want:     "fail",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := inputFor(t, reportCase{name: "served-leaf"})
			in.Findings = tc.findings

			got, err := receipt.Render(in)
			if err != nil {
				t.Fatalf("Render returned error: %v", err)
			}

			var doc struct {
				Statement struct {
					Verdict string `json:"verdict"`
				} `json:"statement"`
			}
			if err := json.Unmarshal(got, &doc); err != nil {
				t.Fatalf("rendered receipt is not JSON: %v", err)
			}
			if doc.Statement.Verdict != tc.want {
				t.Errorf("verdict = %q, want %q", doc.Statement.Verdict, tc.want)
			}
		})
	}
}

// TestRenderSortsManifestsThatArriveUnsorted closes the gap every recorded
// case leaves open: in all seven, modules.json already lists its instances in
// ascending key order, so the sort is a no-op and a golden comparison would
// stay green with the sort deleted. A configuration's module calls are in
// whatever order the .tf file wrote them, which is normally not alphabetical,
// so the rule has to be pinned against input that is out of order.
func TestRenderSortsManifestsThatArriveUnsorted(t *testing.T) {
	modules := &ctfkit.ModuleInventory{
		Root: "somewhere",
		Instances: []ctfkit.ModuleInstance{
			servedInstance("zebra", "zzz"),
			servedInstance("archive", "aaa"),
			servedInstance("mango", "mmm"),
		},
	}

	got, err := receipt.Render(receipt.Input{
		Inventory:         &inventory.Inventory{Builds: []inventory.ServedBuild{}, InstancesWithoutManifest: []inventory.Instance{}},
		Modules:           modules,
		ModulesJSONSHA256: "16357d52a9e6530402f84a170f2228f8945cd9252b3f1096d9c9664cb302539f",
		Metadata:          fixtureMetadata,
		Generator:         fixtureGenerator,
	})
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	var doc struct {
		Statement struct {
			Inputs struct {
				Manifests []struct {
					Key    string `json:"key"`
					SHA256 string `json:"sha256"`
				} `json:"manifests"`
			} `json:"inputs"`
			Obligations []struct {
				Token string `json:"token"`
			} `json:"obligations"`
		} `json:"statement"`
	}
	if parseErr := json.Unmarshal(got, &doc); parseErr != nil {
		t.Fatalf("rendered receipt is not JSON: %v", parseErr)
	}

	var keys, digests []string
	for _, entry := range doc.Statement.Inputs.Manifests {
		keys = append(keys, entry.Key)
		digests = append(digests, entry.SHA256)
	}
	if want := []string{"archive", "mango", "zebra"}; !slices.Equal(keys, want) {
		t.Errorf("manifest keys = %v, want %v", keys, want)
	}
	// The digest travels with its own key rather than with its position, so a
	// sort that reordered the keys and left the digests behind is a different
	// failure from no sort at all.
	if want := []string{"aaa", "mmm", "zzz"}; !slices.Equal(digests, want) {
		t.Errorf("manifest digests = %v, want %v", digests, want)
	}

	var tokens []string
	for _, entry := range doc.Statement.Obligations {
		tokens = append(tokens, entry.Token)
	}
	if want := []string{"archive_obligation", "mango_obligation", "zebra_obligation"}; !slices.Equal(tokens, want) {
		t.Errorf("obligation tokens = %v, want %v", tokens, want)
	}
}

// TestRenderOmitsInstancesWithoutAManifestFromInputs pins the other half of
// the inputs rule: inputs.manifests names files that were read, and an
// instance with no manifest was never opened. It is listed as not-evidence
// under instancesWithoutManifest instead, which is the inventory step's
// output.
func TestRenderOmitsInstancesWithoutAManifestFromInputs(t *testing.T) {
	modules := &ctfkit.ModuleInventory{
		Root: "somewhere",
		Instances: []ctfkit.ModuleInstance{
			servedInstance("archive", "aaa"),
			{Key: "replication_role", Source: "./modules/replication_role"},
		},
	}

	got, err := receipt.Render(receipt.Input{
		Inventory:         &inventory.Inventory{Builds: []inventory.ServedBuild{}, InstancesWithoutManifest: []inventory.Instance{}},
		Modules:           modules,
		ModulesJSONSHA256: "16357d52a9e6530402f84a170f2228f8945cd9252b3f1096d9c9664cb302539f",
		Metadata:          fixtureMetadata,
		Generator:         fixtureGenerator,
	})
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	var doc struct {
		Statement struct {
			Inputs struct {
				Manifests []struct {
					Key string `json:"key"`
				} `json:"manifests"`
			} `json:"inputs"`
		} `json:"statement"`
	}
	if parseErr := json.Unmarshal(got, &doc); parseErr != nil {
		t.Fatalf("rendered receipt is not JSON: %v", parseErr)
	}
	if len(doc.Statement.Inputs.Manifests) != 1 || doc.Statement.Inputs.Manifests[0].Key != "archive" {
		t.Errorf("inputs.manifests = %v, want the one instance that has a manifest", doc.Statement.Inputs.Manifests)
	}
}

// servedInstance is one instance of a served build whose manifest carries a
// single obligation token named after the key, so a sort that loses the
// association between a key and its own record is visible.
func servedInstance(key, digest string) ctfkit.ModuleInstance {
	return ctfkit.ModuleInstance{
		Key:            key,
		Source:         "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws",
		ManifestSHA256: digest,
		Provenance:     ctfkit.ProvenanceLocalUnverified,
		Manifest: &ctfkit.Manifest{
			Module: ctfkit.ManifestModule{
				RegistrySource: "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws",
				Version:        "5.16.1-1e4b692ae5e0a847",
			},
			Scope: ctfkit.ManifestScope{DoesNotProve: []ctfkit.ManifestObligation{
				{Token: key + "_obligation", ConsumerObligation: "Must do something about " + key + "."},
			}},
		},
	}
}

// TestRenderWritesEmptyListsRatherThanNull pins the difference between "no
// build was instantiated" and "this receipt does not say". A nil slice
// marshals to null, which the published schema refuses, and a caller that
// built an Inventory by hand rather than through the inventory step would
// otherwise produce one.
func TestRenderWritesEmptyListsRatherThanNull(t *testing.T) {
	got, err := receipt.Render(receipt.Input{
		// Every list is nil here, which is what a caller that built an
		// Inventory by hand rather than through the inventory step produces.
		// RootResources is the one field that has no empty reading: its
		// coverage vocabulary is closed, so the zero value is a caller bug
		// the published schema catches rather than something to render.
		Inventory: &inventory.Inventory{
			RootResources: inventory.RootResources{Coverage: inventory.CoverageNotApplicable},
		},
		Modules:           &ctfkit.ModuleInventory{Root: "somewhere"},
		ModulesJSONSHA256: "16357d52a9e6530402f84a170f2228f8945cd9252b3f1096d9c9664cb302539f",
		Metadata:          fixtureMetadata,
		Generator:         fixtureGenerator,
	})
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	for _, empty := range []string{
		`"builds":[]`,
		`"findings":[]`,
		`"instancesWithoutManifest":[]`,
		`"manifests":[]`,
		`"obligations":[]`,
		`"complianceTf":[]`,
		`"customerCi":[]`,
	} {
		if !strings.Contains(string(got), empty) {
			t.Errorf("rendered receipt does not contain %s", empty)
		}
	}
	if strings.Contains(string(got), "null") {
		t.Errorf("rendered receipt contains a null: %s", got)
	}

	var doc any
	if parseErr := json.Unmarshal(got, &doc); parseErr != nil {
		t.Fatalf("rendered receipt is not JSON: %v", parseErr)
	}
	if validateErr := compileSchema(t).Validate(doc); validateErr != nil {
		t.Errorf("an empty receipt fails %s: %v", schemaFile, validateErr)
	}
}

// inputFor assembles the renderer's input from the recorded tree the way the
// command will: the loaders read the case, the inventory step groups it, and
// the findings come from the case's own recorded SARIF rather than from the
// analyzer, so this package is tested against the specification and not
// against a sibling implementation.
func inputFor(t *testing.T, tc reportCase) receipt.Input {
	t.Helper()

	root := filepath.Join(fixtureRoot, tc.name, "input")

	modules, err := loader.LoadModules(root)
	if err != nil {
		t.Fatalf("LoadModules(%s): %v", root, err)
	}
	config, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", root, err)
	}
	inv, err := inventory.Build(modules, config)
	if err != nil {
		t.Fatalf("inventory.Build(%s): %v", root, err)
	}

	in := receipt.Input{
		Inventory:         inv,
		Modules:           modules,
		ModulesJSONSHA256: fileDigest(t, filepath.Join(root, ".terraform", "modules", "modules.json")),
		Findings:          recordedFindings(t, tc.name),
		Metadata:          fixtureMetadata,
		Generator:         fixtureGenerator,
	}

	if tc.tests != nil {
		tests := *tc.tests
		tests.File = filepath.Join(root, "tests.json")
		tests.SHA256 = fileDigest(t, tests.File)
		in.Tests = &tests
	}

	return in
}

// recordedFindings reads the case's expected SARIF and returns its results as
// findings. Only the three members the receipt carries are read; the SARIF
// projection is another step's contract.
func recordedFindings(t *testing.T, name string) ctfkit.Findings {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(fixtureRoot, name, "expected", "findings.sarif"))
	if err != nil {
		t.Fatalf("reading recorded SARIF for %s: %v", name, err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing recorded SARIF for %s: %v", name, err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("recorded SARIF for %s has %d runs, want 1", name, len(doc.Runs))
	}

	findings := make(ctfkit.Findings, 0, len(doc.Runs[0].Results))
	for _, result := range doc.Runs[0].Results {
		findings = append(findings, ctfkit.Finding{
			RuleID:  result.RuleID,
			Level:   result.Level,
			Message: ctfkit.Message{Text: result.Message.Text},
		})
	}
	return findings
}

// levelOnly is a finding whose level is the only thing under test.
func levelOnly(level string) ctfkit.Finding {
	return ctfkit.Finding{
		RuleID:  "ctf.coverage.manifest_missing",
		Level:   level,
		Message: ctfkit.Message{Text: "under test"},
	}
}

// allowed is a finding an exception waives. It mirrors the helper the
// spacelift renderer's tests use, so the two renderers are exercised with the
// same shape of input.
func allowed(f ctfkit.Finding) ctfkit.Finding {
	f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: true, EntryID: "bobthecorp-1"}
	return f
}

// expired is a finding whose exception was found and is out of its review
// window, which is recorded but does not waive anything.
func expired(f ctfkit.Finding) ctfkit.Finding {
	f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: false, EntryID: "bobthecorp-1"}
	return f
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	raw, err := os.Open(schemaFile)
	if err != nil {
		t.Fatalf("opening %s: %v", schemaFile, err)
	}
	defer func() { _ = raw.Close() }()

	doc, err := jsonschema.UnmarshalJSON(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", schemaFile, err)
	}

	compiler := jsonschema.NewCompiler()
	if addErr := compiler.AddResource(schemaFile, doc); addErr != nil {
		t.Fatalf("adding %s: %v", schemaFile, addErr)
	}
	schema, err := compiler.Compile(schemaFile)
	if err != nil {
		t.Fatalf("compiling %s: %v", schemaFile, err)
	}
	return schema
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return digest(raw)
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// firstDifference reports where two documents diverge, because a byte-for-byte
// diff of one long line is unreadable otherwise.
func firstDifference(got, want []byte) string {
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			return "at byte " + strconv.Itoa(i) + ": " + window(got, i) + " (want " + window(want, i) + ")"
		}
	}
	if len(got) == len(want) {
		return "nowhere: the documents are equal"
	}
	return "at byte " + strconv.Itoa(min(len(got), len(want))) + ": one document is longer"
}

func window(raw []byte, at int) string {
	start := max(at-40, 0)
	end := min(at+40, len(raw))
	return string(raw[start:end])
}

func lastByte(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return string(raw[len(raw)-1:])
}
