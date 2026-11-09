package coverage_test

import (
	"context"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/coverage"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// TestRegisterRegistersTheSixEmittingRules pins the family: six rule ids at
// post_init, and nothing at any other stage.
func TestRegisterRegistersTheSixEmittingRules(t *testing.T) {
	want := []string{
		"ctf.coverage.manifest_missing",
		"ctf.coverage.posture_degraded",
		"ctf.coverage.delegation_unresolved",
		"ctf.coverage.obligation_unknown",
		"ctf.coverage.resource_unattested",
		"ctf.coverage.tests_failed",
	}

	registry := ctfkit.NewRegistry()
	coverage.Register(registry)

	all := registry.All()
	if len(all) != len(want) {
		t.Fatalf("registered %d analyzers, want %d", len(all), len(want))
	}
	for i, id := range want {
		if all[i].ID() != id {
			t.Errorf("analyzer %d is %s, want %s", i, all[i].ID(), id)
		}
		if all[i].Stage() != ctfkit.PostInit {
			t.Errorf("%s runs at %s, want %s", id, all[i].Stage(), ctfkit.PostInit)
		}
	}
}

// TestNoInventoryIsNotAnError records the nil rule: an analyzer of this
// family selected before post_init reports nothing rather than failing the
// run.
func TestNoInventoryIsNotAnError(t *testing.T) {
	registry := ctfkit.NewRegistry()
	coverage.Register(registry)

	for _, a := range registry.All() {
		findings, err := a.Analyze(context.Background(), ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan})
		if err != nil {
			t.Errorf("%s: %v", a.ID(), err)
		}
		if len(findings) != 0 {
			t.Errorf("%s produced %d finding(s) with no module inventory", a.ID(), len(findings))
		}
	}
}

// TestCanceledContextIsAnError records that a canceled run is a tool failure
// and never a clean pass.
func TestCanceledContextIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	registry := ctfkit.NewRegistry()
	coverage.Register(registry)

	for _, a := range registry.All() {
		if _, err := a.Analyze(ctx, ctfkit.AnalyzerInput{Stage: ctfkit.PostInit}); err == nil {
			t.Errorf("%s accepted a canceled context", a.ID())
		}
	}
}

// TestObligationUnknownUsesTheShippedList checks the token list the binary
// ships: a known token is silent, an unknown one is a note, and one token
// repeated across two manifests is reported once.
func TestObligationUnknownUsesTheShippedList(t *testing.T) {
	cases := []struct {
		name   string
		tokens [][]string
		want   []string
	}{
		{
			name:   "every token known",
			tokens: [][]string{{"runtime_state", "ongoing_operation"}},
		},
		{
			name:   "one unknown token",
			tokens: [][]string{{"runtime_state", "org_baseline_not_evidenced"}},
			want:   []string{"org_baseline_not_evidenced"},
		},
		{
			name:   "the same unknown token in two manifests",
			tokens: [][]string{{"zeta_unknown"}, {"zeta_unknown", "alpha_unknown"}},
			want:   []string{"alpha_unknown", "zeta_unknown"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			instances := make([]ctfkit.ModuleInstance, 0, len(tc.tokens))
			for i, tokens := range tc.tokens {
				instances = append(instances, instanceWithObligations(string(rune('a'+i)), tokens))
			}

			findings := analyzeOne(t, coverage.ObligationUnknown{}, ctfkit.AnalyzerInput{
				Stage:   ctfkit.PostInit,
				Modules: &ctfkit.ModuleInventory{Root: ".", Instances: instances},
			})

			if len(findings) != len(tc.want) {
				t.Fatalf("got %d finding(s), want %d", len(findings), len(tc.want))
			}
			for i, token := range tc.want {
				if !strings.Contains(findings[i].Message.Text, token) {
					t.Errorf("finding %d does not name %s: %s", i, token, findings[i].Message.Text)
				}
				if findings[i].Level != ctfkit.LevelNote {
					t.Errorf("finding %d is %s, want %s", i, findings[i].Level, ctfkit.LevelNote)
				}
			}
		})
	}
}

// TestTestsFailedReadsTheImportedRun checks the counts come from
// ModuleInventory.Tests, which is where the loader attaches an imported
// document, and that an absent or clean run is not a finding.
func TestTestsFailedReadsTheImportedRun(t *testing.T) {
	cases := []struct {
		name string
		run  *ctfkit.TestRun
		want string
	}{
		{name: "no imported document"},
		{name: "every run passed", run: &ctfkit.TestRun{Runs: 3, Passed: 3}},
		{
			name: "one failed run",
			run:  &ctfkit.TestRun{Runs: 3, Passed: 2, Failed: 1},
			want: "Imported test results report 1 failed and 0 errored run(s) of 3",
		},
		{
			name: "one errored run",
			run:  &ctfkit.TestRun{Runs: 2, Passed: 1, Errored: 1},
			want: "Imported test results report 0 failed and 1 errored run(s) of 2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := analyzeOne(t, coverage.TestsFailed{}, ctfkit.AnalyzerInput{
				Stage:   ctfkit.PostInit,
				Modules: &ctfkit.ModuleInventory{Root: ".", Tests: tc.run},
			})

			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("got %d finding(s), want none", len(findings))
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d finding(s), want 1", len(findings))
			}
			if findings[0].Message.Text != tc.want {
				t.Errorf("message is %q, want %q", findings[0].Message.Text, tc.want)
			}
			if findings[0].Level != ctfkit.LevelError {
				t.Errorf("level is %s, want %s", findings[0].Level, ctfkit.LevelError)
			}
		})
	}
}

// TestManifestMissingNamesAServedEquivalent exercises the remediation path no
// recorded fixture reaches: a manifest-less local module that declares a
// resource type the catalog covers is told which compliance.tf module would
// have prevented the finding, and the finding is preventive.
func TestManifestMissingNamesAServedEquivalent(t *testing.T) {
	cases := []struct {
		name         string
		resourceType string
		wantSource   string
		wantVersion  string
	}{
		{
			name:         "a covered resource type",
			resourceType: "aws_s3_bucket",
			wantSource:   "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws",
			wantVersion:  "~> 5.0",
		},
		{
			name:         "a resource type the catalog does not cover",
			resourceType: "aws_iam_role",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ctfkit.AnalyzerInput{
				Stage:   ctfkit.PostInit,
				Catalog: fixtureCatalog(t),
				Config: &ctfkit.ConfigArchive{
					Root: ".",
					Files: []ctfkit.ConfigFile{{
						Path:  "modules/local/main.tf",
						Bytes: []byte("resource \"" + tc.resourceType + "\" \"this\" {}\n"),
					}},
				},
				Modules: &ctfkit.ModuleInventory{
					Root: ".",
					Instances: []ctfkit.ModuleInstance{{
						Key:    "local",
						Source: "./modules/local",
						Dir:    "modules/local",
					}},
				},
			}

			findings := analyzeOne(t, coverage.ManifestMissing{}, in)
			if len(findings) != 1 {
				t.Fatalf("got %d finding(s), want 1", len(findings))
			}

			remediation := findings[0].Props.Remediation
			if tc.wantSource == "" {
				if remediation != nil {
					t.Fatalf("got remediation %+v, want none", *remediation)
				}
				if findings[0].Props.Preventive {
					t.Error("finding is preventive with no served equivalent")
				}
				return
			}

			if remediation == nil {
				t.Fatal("got no remediation, want the served equivalent")
			}
			if remediation.ModuleSource != tc.wantSource {
				t.Errorf("moduleSource is %q, want %q", remediation.ModuleSource, tc.wantSource)
			}
			if remediation.Version != tc.wantVersion {
				t.Errorf("version is %q, want %q", remediation.Version, tc.wantVersion)
			}
			if !findings[0].Props.Preventive {
				t.Error("finding is not preventive although a served equivalent exists")
			}
		})
	}
}

// TestManifestMissingSkipsWrappersOutsideTheRoot records the module-author
// pattern: an example calls the blueprint under test with source = "../..",
// and the blueprint's own root reports on it. A wrapper outside the root whose
// descendants carry manifests is not reported; a module outside the root with
// no served descendant, and a local module inside the root, still are.
func TestManifestMissingSkipsWrappersOutsideTheRoot(t *testing.T) {
	served := &ctfkit.Manifest{
		SchemaVersion: "3.3",
		ScopePath:     ".",
		Module:        ctfkit.ManifestModule{RegistrySource: "example", Version: "1.0.0"},
	}

	in := ctfkit.AnalyzerInput{
		Stage:   ctfkit.PostInit,
		Catalog: fixtureCatalog(t),
		Modules: &ctfkit.ModuleInventory{
			Root: ".",
			Instances: []ctfkit.ModuleInstance{
				{Key: "complete", Source: "../..", Dir: "../.."},
				{Key: "complete.s3_bucket", Source: "example", Dir: ".terraform/modules/complete.s3_bucket", Manifest: served},
				{Key: "raw", Source: "../modules/raw", Dir: "../modules/raw"},
				{Key: "inside", Source: "./modules/inside", Dir: "modules/inside"},
				{Key: "inside.s3_bucket", Source: "example", Dir: ".terraform/modules/inside.s3_bucket", Manifest: served},
				{Key: "completely", Source: "example/other", Dir: ".terraform/modules/completely"},
			},
		},
	}

	findings := analyzeOne(t, coverage.ManifestMissing{}, in)

	var got []string
	for _, f := range findings {
		got = append(got, f.Subject())
	}
	want := []string{"module.completely", "module.inside", "module.raw"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("reported instances %v, want %v", got, want)
	}
}

// TestManifestMissingSkipsModulesThatDeclareNoResources records the helper
// carve-out: a manifest-less instance whose own directory declares no resource
// block creates nothing, so it leaves no evidence gap and is not reported. It
// is judged on its own directory only: a child with resources under a
// resource-free parent is a separate instance and is still reported, and an
// instance the loader could not judge keeps the finding.
func TestManifestMissingSkipsModulesThatDeclareNoResources(t *testing.T) {
	in := ctfkit.AnalyzerInput{
		Stage: ctfkit.PostInit,
		Modules: &ctfkit.ModuleInventory{
			Root: ".",
			Instances: []ctfkit.ModuleInstance{
				{Key: "template", Source: "hashicorp/dir/template", Dir: ".terraform/modules/template", DeclaresNoResources: true},
				{Key: "wrapper", Source: "./modules/wrapper", Dir: "modules/wrapper", DeclaresNoResources: true},
				{Key: "wrapper.role", Source: "./role", Dir: "modules/wrapper/role"},
				{Key: "raw", Source: "./modules/raw", Dir: "modules/raw"},
			},
		},
	}

	var got []string
	for _, f := range analyzeOne(t, coverage.ManifestMissing{}, in) {
		got = append(got, f.Subject())
	}
	want := []string{"module.raw", "module.wrapper.module.role"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("reported instances %v, want %v", got, want)
	}
}

// TestManifestMissingSubjectIsTheModuleAddress records that each finding names
// its instance as a module logical location, so a rule-keyed exception can be
// scoped to it. A nested modules.json key becomes the nested module address.
func TestManifestMissingSubjectIsTheModuleAddress(t *testing.T) {
	in := ctfkit.AnalyzerInput{
		Stage: ctfkit.PostInit,
		Modules: &ctfkit.ModuleInventory{
			Root: ".",
			Instances: []ctfkit.ModuleInstance{
				{Key: "template", Source: "hashicorp/dir/template", Dir: ".terraform/modules/template"},
				{Key: "vpc.flow_log", Source: "example/flow-log", Dir: ".terraform/modules/vpc.flow_log"},
			},
		},
	}

	var got []string
	for _, f := range analyzeOne(t, coverage.ManifestMissing{}, in) {
		got = append(got, f.Subject())
	}
	want := []string{"module.template", "module.vpc.module.flow_log"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("subjects %v, want %v", got, want)
	}
}

// TestDelegationUnresolvedNeedsAScope records that a control left delegated
// with no scope recorded is not reported: there is nothing to tell the reader
// to instantiate.
func TestDelegationUnresolvedNeedsAScope(t *testing.T) {
	in := ctfkit.AnalyzerInput{
		Stage:   ctfkit.PostInit,
		Catalog: fixtureCatalog(t),
		Modules: &ctfkit.ModuleInventory{
			Root: ".",
			Instances: []ctfkit.ModuleInstance{{
				Key: "s3_bucket",
				Dir: ".terraform/modules/s3_bucket",
				Manifest: &ctfkit.Manifest{
					SchemaVersion: "3.3",
					ScopePath:     ".",
					Module: ctfkit.ManifestModule{
						RegistrySource: "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws",
						Version:        "5.16.1",
						Frameworks:     []string{"soc_2"},
					},
					Controls: []ctfkit.ManifestControl{{
						ControlID: "s3_bucket_versioning_enabled",
						Status:    ctfkit.ManifestControlDelegated,
					}},
				},
			}},
		},
	}

	findings := analyzeOne(t, coverage.DelegationUnresolved{}, in)
	if len(findings) != 0 {
		t.Fatalf("got %d finding(s), want none: %s", len(findings), findings[0].Message.Text)
	}
}

// TestDelegationUnresolvedToleratesAControlTheCatalogLacks records that a
// served manifest newer than the embedded catalog does not fail the run: the
// unknown id stays in the message, ctf.controlIds stays empty, and the
// finding passes the runner's check. A known id keeps its control id.
func TestDelegationUnresolvedToleratesAControlTheCatalogLacks(t *testing.T) {
	const unknown = "vpc_control_from_a_newer_catalog"
	cat := fixtureCatalog(t)
	in := ctfkit.AnalyzerInput{
		Stage:   ctfkit.PostInit,
		Catalog: cat,
		Modules: &ctfkit.ModuleInventory{
			Root: ".",
			Instances: []ctfkit.ModuleInstance{{
				Key: "vpc",
				Dir: ".terraform/modules/vpc",
				Manifest: &ctfkit.Manifest{
					SchemaVersion: "3.5",
					ScopePath:     ".",
					Module: ctfkit.ManifestModule{
						RegistrySource: "bobthecorp.compliance.tf/terraform-aws-modules/vpc/aws",
						Version:        "6.7.3",
						Frameworks:     []string{"iso_27001_2022"},
					},
					Controls: []ctfkit.ManifestControl{
						{ControlID: unknown, Status: ctfkit.ManifestControlDelegated, AppliesIn: []string{"modules/flow-log"}},
						{ControlID: "s3_bucket_versioning_enabled", Status: ctfkit.ManifestControlDelegated, AppliesIn: []string{"modules/flow-log"}},
					},
				},
			}},
		},
	}

	findings := analyzeOne(t, coverage.DelegationUnresolved{}, in)
	if len(findings) != 2 {
		t.Fatalf("got %d finding(s), want 2", len(findings))
	}
	byID := make(map[string]ctfkit.Finding, len(findings))
	for _, f := range findings {
		if _, err := f.ValidateFor(f.RuleID, ctfkit.PostInit, cat); err != nil {
			t.Errorf("the runner would refuse %q: %v", f.Message.Text, err)
		}
		for _, id := range []string{unknown, "s3_bucket_versioning_enabled"} {
			if strings.Contains(f.Message.Text, "Control "+id+" ") {
				byID[id] = f
			}
		}
	}

	if f := byID[unknown]; len(f.Props.ControlIDs) != 0 ||
		!strings.Contains(f.Message.Text, "does not hold this control id") {
		t.Errorf("unknown id: controlIds %v, message %q; want no control id and a message naming the gap",
			f.Props.ControlIDs, f.Message.Text)
	}
	if f := byID["s3_bucket_versioning_enabled"]; len(f.Props.ControlIDs) != 1 ||
		strings.Contains(f.Message.Text, "does not hold") {
		t.Errorf("known id: controlIds %v, message %q; want its control id and the plain message",
			f.Props.ControlIDs, f.Message.Text)
	}
}

// Every rule of the family that quotes a module source, manifest_missing
// (the instance source as written) and posture_degraded and
// delegation_unresolved (the manifest's registry source), quotes it through
// ctfkit.RedactSource: no userinfo, no query.
func TestSourcesInMessagesAreRedacted(t *testing.T) {
	const canary = "git::https://CANARY-u:CANARY-t@example.com/bobthecorp/app.git?ref=v1&sshkey=CANARY-k"
	in := ctfkit.AnalyzerInput{
		Stage:   ctfkit.PostInit,
		Catalog: fixtureCatalog(t),
		Modules: &ctfkit.ModuleInventory{
			Root: ".",
			Instances: []ctfkit.ModuleInstance{
				{Key: "raw", Source: canary, Dir: ".terraform/modules/raw"},
				{
					Key:    "served",
					Source: canary,
					Dir:    ".terraform/modules/served",
					Manifest: &ctfkit.Manifest{
						SchemaVersion: "3.3",
						ScopePath:     ".",
						Module:        ctfkit.ManifestModule{RegistrySource: canary, Version: "1.0.0", Frameworks: []string{"soc_2"}},
						Controls: []ctfkit.ManifestControl{{
							ControlID: "s3_bucket_versioning_enabled",
							Status:    ctfkit.ManifestControlDelegated,
							AppliesIn: []string{"modules/notification"},
						}},
						Posture: ctfkit.ManifestPosture{Degraded: []string{"org-rules-unavailable"}},
					},
				},
			},
		},
	}

	for _, a := range []ctfkit.Analyzer{coverage.ManifestMissing{}, coverage.PostureDegraded{}, coverage.DelegationUnresolved{}} {
		t.Run(a.ID(), func(t *testing.T) {
			findings := analyzeOne(t, a, in)
			if len(findings) == 0 {
				t.Fatalf("%s did not fire, so the redaction is not exercised", a.ID())
			}
			for _, f := range findings {
				text := f.Message.Text
				if strings.Contains(text, "CANARY") || strings.Contains(text, "ref=") ||
					!strings.Contains(text, "git::https://example.com/bobthecorp/app.git") {
					t.Errorf("message %q quotes the source unredacted", text)
				}
			}
		})
	}
}

// instanceWithObligations is a manifest-carrying instance whose only
// interesting content is its does_not_prove list.
func instanceWithObligations(key string, tokens []string) ctfkit.ModuleInstance {
	obligations := make([]ctfkit.ManifestObligation, 0, len(tokens))
	for _, token := range tokens {
		obligations = append(obligations, ctfkit.ManifestObligation{Token: token})
	}

	return ctfkit.ModuleInstance{
		Key: key,
		Manifest: &ctfkit.Manifest{
			SchemaVersion: "3.3",
			ScopePath:     ".",
			Module:        ctfkit.ManifestModule{RegistrySource: "example", Version: "1.0.0"},
			Scope:         ctfkit.ManifestScope{DoesNotProve: obligations},
		},
	}
}

// analyzeOne runs a single rule and fails the test on a tool error.
func analyzeOne(t *testing.T, a ctfkit.Analyzer, in ctfkit.AnalyzerInput) ctfkit.Findings {
	t.Helper()

	findings, err := a.Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("%s: %v", a.ID(), err)
	}
	return findings
}
