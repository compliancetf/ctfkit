package codeexec_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/analyzer/codeexec"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/conformance"
	"github.com/compliancetf/ctfkit/internal/exceptions"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Every rule the family registers needs a tool.driver.rules entry and every
// entry names a registered rule. provisioner, external_data and
// module_uninspected run at pre_plan and post_init; module_endpoint at
// post_init only.
func TestDescriptorsCoverEveryRegisteredRule(t *testing.T) {
	r := ctfkit.NewRegistry()
	codeexec.Register(r)

	registered := map[string]bool{}
	var stages []string
	for _, a := range r.All() {
		registered[a.ID()] = true
		stages = append(stages, a.ID()+"@"+a.Stage().String())
	}
	sort.Strings(stages)
	wantStages := []string{
		"ctf.exec.external_data@post_init", "ctf.exec.external_data@pre_plan",
		"ctf.exec.module_endpoint@post_init",
		"ctf.exec.module_uninspected@post_init", "ctf.exec.module_uninspected@pre_plan",
		"ctf.exec.provisioner@post_init", "ctf.exec.provisioner@pre_plan",
	}
	if strings.Join(stages, ",") != strings.Join(wantStages, ",") {
		t.Errorf("registered %v, want %v", stages, wantStages)
	}

	levels := map[string]string{}
	for _, d := range codeexec.Descriptors() {
		if d.ShortDescription == "" || !registered[d.ID] || levels[d.ID] != "" {
			t.Errorf("descriptor %s: %+v", d.ID, d)
		}
		levels[d.ID] = d.Level
	}
	if len(levels) != len(registered) {
		t.Errorf("descriptors %v, registered rule ids %v", levels, registered)
	}
	if levels["ctf.exec.module_uninspected"] != ctfkit.LevelWarning || levels["ctf.exec.provisioner"] != ctfkit.LevelError {
		t.Errorf("levels = %v", levels)
	}
}

// analyze runs every post_init rule of the family on in and returns
// "rule|subject|uri" for each finding, sorted, failing on an error or a
// finding without a file.
func analyze(t *testing.T, in ctfkit.AnalyzerInput) []string {
	t.Helper()
	return analyzeAt(t, ctfkit.PostInit, in)
}

// analyzeAt is analyze at the given stage.
func analyzeAt(t *testing.T, stage ctfkit.Stage, in ctfkit.AnalyzerInput) []string {
	t.Helper()
	r := ctfkit.NewRegistry()
	codeexec.Register(r)
	var out []string
	for _, a := range r.ByStage(stage) {
		findings, err := a.Analyze(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", a.ID(), err)
		}
		for _, f := range findings {
			p := f.Locations[0].PhysicalLocation
			if p == nil || p.ArtifactLocation.URI == "" {
				t.Errorf("%s|%s has no file", f.RuleID, f.Subject())
				continue
			}
			if f.Props.Stage != stage {
				t.Errorf("%s|%s carries stage %s, want %s", f.RuleID, f.Subject(), f.Props.Stage, stage)
			}
			out = append(out, f.RuleID+"|"+f.Subject()+"|"+p.ArtifactLocation.URI)
		}
	}
	sort.Strings(out)
	return out
}

// provisioned is a native-syntax resource with one local-exec provisioner.
func provisioned(name string) string {
	return "resource \"terraform_data\" \"" + name + "\" {\n  provisioner \"local-exec\" {}\n}\n"
}

// instance is one installed module with its files written inline.
func instance(key, source, dir string, files map[string]string) ctfkit.ModuleInstance {
	m := ctfkit.ModuleInstance{Key: key, Source: source, Dir: dir}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m.Files = append(m.Files, ctfkit.ConfigFile{Path: dir + "/" + name, Bytes: []byte(files[name])})
	}
	return m
}

// The rules read all four suffixes in a downloaded module, native and JSON,
// and anchor each finding to the file that holds the block.
func TestEverySuffixInADownloadedModule(t *testing.T) {
	const dir = ".terraform/modules/app"
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostInit, Modules: &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
		instance("app", "./app", dir, map[string]string{
			"a.tf":        provisioned("a"),
			"b.tofu":      `data "external" "b" {}`,
			"c.tf.json":   `{"resource": {"terraform_data": {"c": {"provisioner": {"remote-exec": {}}}}}}`,
			"d.tofu.json": `{"data": [{"external": {"d": {}}}]}`,
			"e.tf":        `data "http" "not_a_program" {}`,
		}),
	}}}
	want := []string{
		"ctf.exec.external_data|module.app.data.external.b|" + dir + "/b.tofu",
		"ctf.exec.external_data|module.app.data.external.d|" + dir + "/d.tofu.json",
		"ctf.exec.provisioner|module.app.terraform_data.a|" + dir + "/a.tf",
		"ctf.exec.provisioner|module.app.terraform_data.c|" + dir + "/c.tf.json",
	}
	if got := analyze(t, in); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Only the files directly in the root are the root module's: a local module
// is an instance read from its own directory, and a directory nothing calls is
// not part of the configuration.
func TestRootReadsItsOwnDirectoryOnly(t *testing.T) {
	in := ctfkit.AnalyzerInput{
		Stage: ctfkit.PostInit,
		Config: &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{
			{Path: "main.tf", Bytes: []byte(provisioned("r"))},
			{Path: "examples/demo/main.tf", Bytes: []byte(`data "external" "e" {}`)},
		}},
	}
	want := []string{"ctf.exec.provisioner|terraform_data.r|main.tf"}
	if got := analyze(t, in); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %q, want %q", got, want)
	}
}

// module_endpoint judges only calls made from inside another module: a root
// call is module_source's at scan time, whatever its source. A nested finding
// points at the block whose source init installed, which is the override
// file's when one replaced it; with no block read it points at modules.json.
// A local child of a remote module is never reported itself.
func TestModuleEndpointNestedCallsOnly(t *testing.T) {
	const appDir = ".terraform/modules/app"
	in := ctfkit.AnalyzerInput{
		Stage: ctfkit.PostInit,
		Config: &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{
			{Path: "main.tf", Bytes: []byte(`module "app" { source = "git::https://example.com/bobthecorp/app.git" }`)},
		}},
		Modules: &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
			instance("app", "git::https://example.com/bobthecorp/app.git", appDir, map[string]string{
				"main.tf":         `module "net" { source = "bobthecorp.compliance.tf/terraform-aws-modules/vpc/aws" }`,
				"net_override.tf": `module "net" { source = "terraform-aws-modules/vpc/aws" }`,
			}),
			{Key: "app.child", Source: "./child", Dir: appDir + "/child"},
			{Key: "app.net", Source: "terraform-aws-modules/vpc/aws", Dir: ".terraform/modules/app.net"},
			{Key: "app.net.deep", Source: "registry.bobthecorp.example/net/deep/aws", Dir: ".terraform/modules/app.net.deep"},
		}},
	}
	want := []string{
		"ctf.exec.module_endpoint|module.app.module.net.module.deep|.terraform/modules/modules.json",
		"ctf.exec.module_endpoint|module.app.module.net|" + appDir + "/net_override.tf",
	}
	if got := analyze(t, in); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A module source in a message loses its userinfo and its query, which can
// carry a token or an SSH key.
func TestModuleEndpointRedactsTheSource(t *testing.T) {
	const source = "git::https://CANARY-user:CANARY-token@example.com/bobthecorp/tools.git?ref=v1&sshkey=CANARY-key"
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostInit, Modules: &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
		{Key: "app.tools", Source: source, Dir: ".terraform/modules/app.tools"},
	}}}
	findings, err := codeexec.ModuleEndpoint{}.Analyze(context.Background(), in)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %v, err = %v", findings, err)
	}
	text := findings[0].Message.Text
	if strings.Contains(text, "CANARY") || strings.Contains(text, "ref=") ||
		!strings.Contains(text, "git::https://example.com/bobthecorp/tools.git,") {
		t.Errorf("message = %q, want the source without userinfo or query", text)
	}
}

// At pre_plan an absent ../ module directory is a warning at the module block
// that names it; a local module the scan read is not. post_init has no such
// rule: there a directory that cannot be read is a loader error.
func TestModuleUninspected(t *testing.T) {
	config := &ctfkit.ConfigArchive{
		Files: []ctfkit.ConfigFile{
			{Path: "main.tf", Bytes: []byte("module \"shared\" {\n  source = \"../shared\"\n}\n\nmodule \"near\" {\n  source = \"../near\"\n}\n")},
		},
		LocalModules: []ctfkit.LocalModule{{Dir: "../shared", Unread: true}, {Dir: "../near"}},
	}
	want := []string{"ctf.exec.module_uninspected|module.shared|main.tf"}
	if got := analyzeAt(t, ctfkit.PrePlan, ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan, Config: config}); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("pre_plan: got %q, want %q", got, want)
	}
	if got := analyze(t, ctfkit.AnalyzerInput{Stage: ctfkit.PostInit, Config: config}); len(got) != 0 {
		t.Errorf("post_init: got %q, want nothing", got)
	}
}

// A data source scoped to a check block in a module carries the module's
// address, as Terraform addresses it, at both stages: two modules that use
// the same check name report two distinct subjects. At pre_plan the address
// comes from the local module calls scan read.
func TestCheckScopedDataSourceCarriesTheModuleAddress(t *testing.T) {
	check := "check \"health\" {\n  data \"external\" \"probe\" {}\n\n  assert {\n    condition     = true\n    error_message = \"x\"\n  }\n}\n"
	root := ctfkit.ConfigFile{Path: "main.tf", Bytes: []byte("module \"a\" {\n  source = \"./a\"\n}\n\nmodule \"b\" {\n  source = \"./b\"\n}\n")}
	a := ctfkit.ConfigFile{Path: "a/main.tf", Bytes: []byte(check)}
	b := ctfkit.ConfigFile{Path: "b/main.tf", Bytes: []byte(check)}
	want := []string{
		"ctf.exec.external_data|module.a.check.health.data.external.probe|a/main.tf",
		"ctf.exec.external_data|module.b.check.health.data.external.probe|b/main.tf",
	}

	preplan := analyzeAt(t, ctfkit.PrePlan, ctfkit.AnalyzerInput{
		Stage: ctfkit.PrePlan, Config: &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{root, a, b}},
	})
	if strings.Join(preplan, "\n") != strings.Join(want, "\n") {
		t.Errorf("pre_plan: got\n%s\nwant\n%s", strings.Join(preplan, "\n"), strings.Join(want, "\n"))
	}

	postinit := analyze(t, ctfkit.AnalyzerInput{
		Stage:  ctfkit.PostInit,
		Config: &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{root}},
		Modules: &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
			{Key: "a", Source: "./a", Dir: "a", Files: []ctfkit.ConfigFile{a}},
			{Key: "b", Source: "./b", Dir: "b", Files: []ctfkit.ConfigFile{b}},
		}},
	})
	if strings.Join(postinit, "\n") != strings.Join(want, "\n") {
		t.Errorf("post_init: got\n%s\nwant\n%s", strings.Join(postinit, "\n"), strings.Join(want, "\n"))
	}
}

// subjectsOf is the subject of each finding, in output order.
func subjectsOf(t *testing.T, a ctfkit.Analyzer, in ctfkit.AnalyzerInput) []string {
	t.Helper()
	findings, err := a.Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("%s: %v", a.ID(), err)
	}
	var out []string
	for _, f := range findings {
		out = append(out, f.Subject())
	}
	return out
}

// At pre_plan a module directory takes the address of
// every call path that reaches it, one finding per path in sorted order, and
// a call is followed to the directory the scan resolved it to (LocalCalls),
// not to its source text. Here ../alias is a symlink to ../libs/pkg, which
// ./wrap also calls; ../libs/pkg calls ../gone, which is absent.
func TestPrePlanAddressesEveryCallPath(t *testing.T) {
	check := "check \"health\" {\n  data \"external\" \"probe\" {}\n\n  assert {\n    condition     = true\n    error_message = \"x\"\n  }\n}\n\n" +
		"module \"gone\" {\n  source = \"../gone\"\n}\n"
	config := &ctfkit.ConfigArchive{
		Files: []ctfkit.ConfigFile{
			{Path: "main.tf", Bytes: []byte("module \"a\" {\n  source = \"../alias\"\n}\n\nmodule \"b\" {\n  source = \"./wrap\"\n}\n")},
			{Path: "wrap/main.tf", Bytes: []byte("module \"c\" {\n  source = \"../../libs/pkg\"\n}\n")},
		},
		LocalModules: []ctfkit.LocalModule{
			{Dir: "../libs/pkg", Files: []ctfkit.ConfigFile{{Path: "../libs/pkg/main.tf", Bytes: []byte(check)}}},
			{Dir: "../libs/gone", Unread: true},
		},
		LocalCalls: []ctfkit.LocalCall{
			{From: ".", Name: "a", To: "../libs/pkg"},
			{From: ".", Name: "b", To: "wrap"},
			{From: "wrap", Name: "c", To: "../libs/pkg"},
			{From: "../libs/pkg", Name: "gone", To: "../libs/gone"},
		},
	}
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan, Config: config}

	want := []string{
		"module.a.check.health.data.external.probe",
		"module.b.module.c.check.health.data.external.probe",
	}
	if got := subjectsOf(t, codeexec.ExternalDataPrePlan{}, in); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("external_data subjects, in output order: got %q, want %q", got, want)
	}
	want = []string{"module.a.module.gone", "module.b.module.c.module.gone"}
	if got := subjectsOf(t, codeexec.ModuleUninspectedPrePlan{}, in); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("module_uninspected subjects, in output order: got %q, want %q", got, want)
	}

	// Without LocalCalls, as for an archive built by hand, ../alias is
	// joined as written and reaches no directory read; module b's path to
	// ../libs/pkg is still found.
	config.LocalCalls = nil
	got := analyzeAt(t, ctfkit.PrePlan, in)
	if !slices.Contains(got, "ctf.exec.external_data|module.b.module.c.check.health.data.external.probe|../libs/pkg/main.tf") {
		t.Errorf("hand-built archive: got %q", got)
	}
}

// A call with no resolved entry, in an archive built
// without LocalCalls or with only some, never leaves the directory it reads
// with an empty prefix. Here ../alias cannot be followed to ../libs/pkg, so
// the module's data source takes module.a.<unresolved>., and no waiver
// covers that address: not one for the root-level subject, not one written
// for the marked address itself.
func TestUnresolvedCallIsNeverARoot(t *testing.T) {
	check := "check \"health\" {\n  data \"external\" \"probe\" {}\n\n  assert {\n    condition     = true\n    error_message = \"x\"\n  }\n}\n"
	root := ctfkit.ConfigFile{Path: "main.tf", Bytes: []byte("module \"a\" {\n  source = \"../alias\"\n}\n\nmodule \"b\" {\n  source = \"./b\"\n}\n")}
	b := ctfkit.ConfigFile{Path: "b/main.tf", Bytes: []byte("locals {}\n")}
	module := ctfkit.LocalModule{Dir: "../libs/pkg", Files: []ctfkit.ConfigFile{{Path: "../libs/pkg/main.tf", Bytes: []byte(check)}}}
	marked := "module.a." + ctfkit.UnresolvedModule + ".check.health.data.external.probe"

	registry := filepath.Join(t.TempDir(), "exceptions.yaml")
	entry := func(resource string) string {
		return "  - rule: ctf.exec.external_data\n    resource: \"" + resource + "\"\n    justification: \"Reviewed probe.\"\n" +
			"    approved_by: compliance@bobthecorp.example\n    approval_ticket: SEC-1\n    review_date: \"2099-01-01\"\n"
	}
	body := "schema_version: \"1.0\"\nexceptions:\n" + entry("check.health.data.external.probe") + entry(marked)
	if err := os.WriteFile(registry, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := exceptions.Load(registry)
	if err != nil {
		t.Fatal(err)
	}

	for name, calls := range map[string][]ctfkit.LocalCall{
		"no LocalCalls":      nil,
		"partial LocalCalls": {{From: ".", Name: "b", To: "b"}},
	} {
		t.Run(name, func(t *testing.T) {
			in := ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan, Config: &ctfkit.ConfigArchive{
				Files: []ctfkit.ConfigFile{root, b}, LocalModules: []ctfkit.LocalModule{module}, LocalCalls: calls,
			}}
			findings, err := codeexec.ExternalDataPrePlan{}.Analyze(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].Subject() != marked {
				t.Fatalf("findings = %v, want one at %s", findings, marked)
			}
			if p, waived := ctfkit.Decide(findings[0], reg, time.Now()); p != nil || waived {
				t.Errorf("Decide waived %s: %+v", marked, p)
			}
		})
	}
}

// unwaivable fails unless every finding's subject holds the unresolved marker
// and no waiver, written for the bare call address or the marked one, covers
// it.
func unwaivable(t *testing.T, findings ctfkit.Findings) {
	t.Helper()
	registry := filepath.Join(t.TempDir(), "exceptions.yaml")
	body := "schema_version: \"1.0\"\nexceptions:\n"
	for _, f := range findings {
		for _, resource := range []string{f.Subject(), strings.TrimSuffix(f.Subject(), "."+ctfkit.UnresolvedModule)} {
			body += "  - rule: " + f.RuleID + "\n    resource: \"" + resource + "\"\n    justification: \"Reviewed.\"\n" +
				"    approved_by: compliance@bobthecorp.example\n    approval_ticket: SEC-1\n    review_date: \"2099-01-01\"\n"
		}
	}
	if err := os.WriteFile(registry, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := exceptions.Load(registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if !strings.HasSuffix(f.Subject(), "."+ctfkit.UnresolvedModule) {
			t.Errorf("%s: subject %s carries no unresolved marker", f.RuleID, f.Subject())
		}
		if p, waived := ctfkit.Decide(f, reg, time.Now()); p != nil || waived {
			t.Errorf("Decide waived %s: %+v", f.Subject(), p)
		}
	}
}

// SDK fallback: an archive with no call graph, or only part of one,
// cannot tell a "./" directory that is missing, unreadable or a symlink out of
// the root from one it was never given. A call whose join names no directory
// the archive carries is a module_uninspected warning under its marked
// address, never skipped and never waived; a call that reaches a directory
// read, or one a directory scan found absent, is not.
func TestUnfollowedLocalCallIsMarked(t *testing.T) {
	root := ctfkit.ConfigFile{Path: "main.tf", Bytes: []byte(
		"module \"gone\" {\n  source = \"./gone\"\n}\n\nmodule \"link\" {\n  source = \"./link\"\n}\n\n" +
			"module \"sub\" {\n  source = \"./sub\"\n}\n\nmodule \"far\" {\n  source = \"../far\"\n}\n" +
			"\nmodule \"win\" {\n  source = \".\\\\win\"\n}\n")}
	sub := ctfkit.ConfigFile{Path: "sub/main.tf", Bytes: []byte("module \"deep\" {\n  source = \"./deep\"\n}\n")}
	want := []string{
		"ctf.exec.module_uninspected|module.gone." + ctfkit.UnresolvedModule + "|main.tf",
		"ctf.exec.module_uninspected|module.link." + ctfkit.UnresolvedModule + "|main.tf",
		"ctf.exec.module_uninspected|module.sub.module.deep." + ctfkit.UnresolvedModule + "|sub/main.tf",
		"ctf.exec.module_uninspected|module.win." + ctfkit.UnresolvedModule + "|main.tf",
	}
	for name, calls := range map[string][]ctfkit.LocalCall{
		"no LocalCalls":      nil,
		"partial LocalCalls": {{From: ".", Name: "sub", To: "sub"}},
	} {
		t.Run(name, func(t *testing.T) {
			in := ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan, Config: &ctfkit.ConfigArchive{
				Files:        []ctfkit.ConfigFile{root, sub},
				LocalModules: []ctfkit.LocalModule{{Dir: "../far"}},
				LocalCalls:   calls,
			}}
			if got := analyzeAt(t, ctfkit.PrePlan, in); strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			findings, err := codeexec.ModuleUninspectedPrePlan{}.Analyze(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			unwaivable(t, findings)
		})
	}
}

// A Partial archive, such as a pre-commit file list, is a subset the operator
// chose: a "./" call to a directory it leaves out is outside that subset, so
// the fallback reports nothing for it. The same archive without Partial still
// reports the call, so the zero value keeps the SDK fallback.
func TestPartialArchiveSkipsUnfollowedCall(t *testing.T) {
	file := ctfkit.ConfigFile{Path: "main.tf", Bytes: []byte("module \"helper\" {\n  source = \"./modules/helper\"\n}\n")}
	for partial, want := range map[bool][]string{
		true:  nil,
		false: {"ctf.exec.module_uninspected|module.helper." + ctfkit.UnresolvedModule + "|main.tf"},
	} {
		in := ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan, Config: &ctfkit.ConfigArchive{
			Files:   []ctfkit.ConfigFile{file},
			Partial: partial,
		}}
		if got := analyzeAt(t, ctfkit.PrePlan, in); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("Partial=%v: got\n%s\nwant\n%s", partial, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

// At post_init every module block, in the root or in an installed
// module, that modules.json holds no record for is a module_uninspected
// warning under its marked address: a remote call, a nested call, and a
// local ./helper whose directory exists and would join. The helper's
// directory is not read in its place, so its provisioner is not reported
// under any address a waiver could match.
func TestUnrecordedCallIsMarked(t *testing.T) {
	const appDir = ".terraform/modules/app"
	in := ctfkit.AnalyzerInput{
		Stage: ctfkit.PostInit,
		Config: &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{
			{Path: "main.tf", Bytes: []byte("module \"app\" {\n  source = \"bobthecorp.compliance.tf/terraform-aws-modules/app/aws\"\n}\n\n" +
				"module \"helper\" {\n  source = \"./helper\"\n}\n\n" +
				"module \"remote\" {\n  source = \"git::https://example.com/bobthecorp/remote.git\"\n}\n")},
			{Path: "helper/main.tf", Bytes: []byte(provisioned("planted"))},
		}},
		Modules: &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
			instance("app", "bobthecorp.compliance.tf/terraform-aws-modules/app/aws", appDir, map[string]string{
				"main.tf": "module \"net\" {\n  source = \"./net\"\n}\n\nmodule \"kept\" {\n  source = \"./kept\"\n}\n",
			}),
			{Key: "app.kept", Source: "./kept", Dir: appDir + "/kept"},
		}},
	}
	want := []string{
		"ctf.exec.module_uninspected|module.app.module.net." + ctfkit.UnresolvedModule + "|" + appDir + "/main.tf",
		"ctf.exec.module_uninspected|module.helper." + ctfkit.UnresolvedModule + "|main.tf",
		"ctf.exec.module_uninspected|module.remote." + ctfkit.UnresolvedModule + "|main.tf",
	}
	if got := analyze(t, in); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	findings, err := codeexec.ModuleUninspected{}.Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	unwaivable(t, findings)
}

// A module block and its override name different sources
// for one call, and the call leads to both. With the override sorting first
// (a_override.tf before main.tf), neither directory is left unprefixed for a
// root-only waiver to match.
func TestOverrideKeepsEveryTargetOfACall(t *testing.T) {
	check := "check \"health\" {\n  data \"external\" \"probe\" {}\n\n  assert {\n    condition     = true\n    error_message = \"x\"\n  }\n}\n"
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan, Config: &ctfkit.ConfigArchive{
		Files: []ctfkit.ConfigFile{
			{Path: "a_override.tf", Bytes: []byte("module \"a\" {\n  source = \"../other\"\n}\n")},
			{Path: "main.tf", Bytes: []byte("module \"a\" {\n  source = \"../real\"\n}\n")},
		},
		LocalModules: []ctfkit.LocalModule{
			{Dir: "../other", Files: []ctfkit.ConfigFile{{Path: "../other/main.tf", Bytes: []byte(check)}}},
			{Dir: "../real", Files: []ctfkit.ConfigFile{{Path: "../real/main.tf", Bytes: []byte(check)}}},
		},
		LocalCalls: []ctfkit.LocalCall{
			{From: ".", Name: "a", To: "../other"},
			{From: ".", Name: "a", To: "../real"},
		},
	}}
	want := []string{
		"ctf.exec.external_data|module.a.check.health.data.external.probe|../other/main.tf",
		"ctf.exec.external_data|module.a.check.health.data.external.probe|../real/main.tf",
	}
	if got := analyzeAt(t, ctfkit.PrePlan, in); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A test. key that is not the shape init writes for
// a run block (here test.x, two segments, no test record) is configuration,
// and the provisioner in its directory is reported.
func TestUnknownShapedTestKeyIsInspected(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"main.tf":   "module \"x\" {\n  source = \"./x\"\n}\n",
		"x/main.tf": provisioned("probe"),
		".terraform/modules/modules.json": `{"Modules":[{"Key":"","Source":"","Dir":"."},` +
			`{"Key":"test.x","Source":"./x","Dir":"x"}]}`,
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	modules, err := loader.LoadModules(root)
	if err != nil {
		t.Fatal(err)
	}
	got := analyze(t, ctfkit.AnalyzerInput{Stage: ctfkit.PostInit, Config: cfg, Modules: modules, Catalog: catalog.Embedded()})
	// The root's module x has no record of its own (only test.x does), so
	// the call is reported as never inspected under its marked address.
	want := []string{
		"ctf.exec.module_uninspected|module.x." + ctfkit.UnresolvedModule + "|main.tf",
		"ctf.exec.provisioner|module.test.module.x.terraform_data.probe|x/main.tf",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A root module call named test is configuration. Over
// the recorded tofu layout, its child's provisioner and the provisioner of the
// ../shared module's child are reported at post_init; the provisioner of the
// module a main.tftest.hcl run block installs (key test.main.setup) is not.
func TestRootModuleNamedTestIsInspected(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "loader", "tofu-local-layout", "repo")
	cfg, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	modules, err := loader.LoadModules(root)
	if err != nil {
		t.Fatal(err)
	}
	got := analyze(t, ctfkit.AnalyzerInput{Stage: ctfkit.PostInit, Config: cfg, Modules: modules, Catalog: catalog.Embedded()})
	want := []string{
		"ctf.exec.provisioner|module.shared.module.sub.terraform_data.sub|../shared/sub/main.tf",
		"ctf.exec.provisioner|module.test.module.hook.terraform_data.hook|test/hook/main.tf",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// At pre_plan the two rules read every file scan read, the root and its local
// module directories, with no module prefix, and a file that does not parse
// contributes the blocks that did rather than failing the scan.
func TestPrePlanReadsEveryFileScanRead(t *testing.T) {
	in := ctfkit.AnalyzerInput{
		Stage: ctfkit.PrePlan,
		Config: &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{
			{Path: "main.tf", Bytes: []byte(provisioned("root"))},
			{Path: "modules/hook/main.tf.json", Bytes: []byte(`{"data": {"external": {"probe": {}}}}`)},
			{Path: "broken.tf", Bytes: []byte("locals {\n")},
		}},
	}
	want := []string{
		"ctf.exec.external_data|data.external.probe|modules/hook/main.tf.json",
		"ctf.exec.provisioner|terraform_data.root|main.tf",
	}
	if got := analyzeAt(t, ctfkit.PrePlan, in); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// An analyzer selected without the inputs its stage supplies reports nothing,
// and a canceled context is a malfunction, not a clean run.
func TestMissingInputsAndCancellation(t *testing.T) {
	if got := analyze(t, ctfkit.AnalyzerInput{Stage: ctfkit.PostInit}); len(got) != 0 {
		t.Errorf("no inputs: got %q", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := ctfkit.NewRegistry()
	codeexec.Register(r)
	for _, a := range r.All() {
		if _, err := a.Analyze(ctx, ctfkit.AnalyzerInput{Stage: ctfkit.PostInit}); err == nil {
			t.Errorf("%s: canceled context returned no error", a.ID())
		}
	}
}

// At post_init a file the parser cannot read is an error from every rule,
// naming the file and line but none of its text, never a clean run.
func TestUnparseableFileIsAnError(t *testing.T) {
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostInit, Modules: &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
		instance("app", "./app", ".terraform/modules/app", map[string]string{
			"main.tf": "resource \"terraform_data\" \"x\" { provisioner \"local-exec\" { command = \"CANARY\" } }\n",
		}),
	}}}
	r := ctfkit.NewRegistry()
	codeexec.Register(r)
	for _, a := range r.ByStage(ctfkit.PostInit) {
		_, err := a.Analyze(context.Background(), in)
		if err == nil || !strings.Contains(err.Error(), ".terraform/modules/app/main.tf does not parse (line 1)") ||
			strings.Contains(err.Error(), "CANARY") {
			t.Errorf("%s: error = %v, want a parse error naming the file and line only", a.ID(), err)
		}
	}
}

// The family is pure over the code-exec fixture: two concurrent runs, under
// -race, leave the input unchanged.
func TestPureOverTheFixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "fixtures", "postinit", "code-exec", "input")
	cfg, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	modules, err := loader.LoadModules(root)
	if err != nil {
		t.Fatal(err)
	}
	r := ctfkit.NewRegistry()
	codeexec.Register(r)
	conformance.CheckPure(t, r.All(), ctfkit.AnalyzerInput{
		Stage: ctfkit.PostInit, Config: cfg, Modules: modules, Catalog: catalog.Embedded(),
	})
}
