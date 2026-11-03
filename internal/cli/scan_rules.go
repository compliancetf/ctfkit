package cli

import (
	"github.com/compliancetf/ctfkit/internal/analyzer/codeexec"
	"github.com/compliancetf/ctfkit/internal/analyzer/coverage"
	"github.com/compliancetf/ctfkit/internal/analyzer/disabledcontrol"
	"github.com/compliancetf/ctfkit/internal/analyzer/lockcheck"
	"github.com/compliancetf/ctfkit/internal/analyzer/modulesource"
	"github.com/compliancetf/ctfkit/internal/analyzer/origin"
	"github.com/compliancetf/ctfkit/internal/analyzer/sensitivechange"
	"github.com/compliancetf/ctfkit/internal/analyzer/tagging"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// scanAnalyzers is the registry of every analyzer scan runs. One stage runs per
// invocation, and the registry is keyed by (id, stage), so an analyzer that
// registers at both pre_plan and post_plan never reports twice.
func scanAnalyzers() ctfkit.Registry {
	r := ctfkit.NewRegistry()
	modulesource.Register(r)
	disabledcontrol.Register(r)
	origin.Register(r)
	tagging.Register(r)
	sensitivechange.Register(r)
	lockcheck.Register(r)
	// ctf.exec.provisioner and external_data at pre_plan; the family's
	// post_init values register too and never run here.
	codeexec.Register(r)
	return r
}

// ScanAnalyzers is the analyzer set `ctfkit scan` runs. It is exported for the
// conformance harness, which runs the same set under its purity check.
func ScanAnalyzers() ctfkit.Registry { return scanAnalyzers() }

// ReportAnalyzers is the analyzer set `ctfkit report` runs, exported for the
// same reason as ScanAnalyzers: every post_init analyzer. report is the
// post_init entry point, so the ctf.exec rules run here, before plan.
func ReportAnalyzers() ctfkit.Registry {
	r := ctfkit.NewRegistry()
	coverage.Register(r)
	codeexec.Register(r)
	return r
}

// scanRules are the tool.driver.rules entries of every rule scan can report,
// each family's own Descriptors in registration order. The SARIF renderer
// refuses a finding whose rule has no descriptor, so a rule an analyzer adds
// without one fails the run loudly (exit 2, category finding) instead of
// shipping a placeholder description; each family's test holds its descriptor
// ids equal to the rule ids it registers.
func scanRules() []sarif.RuleDescriptor {
	var rules []sarif.RuleDescriptor
	rules = append(rules, disabledcontrol.Descriptors()...)
	rules = append(rules, sensitivechange.Descriptors()...)
	rules = append(rules, modulesource.Descriptors()...)
	rules = append(rules, origin.Descriptors()...)
	rules = append(rules, tagging.Descriptors()...)
	rules = append(rules, lockcheck.Descriptors()...)
	rules = append(rules, codeexec.Descriptors()...)
	return rules
}

// reportRules are the tool.driver.rules entries of every rule report can
// report: the descriptors of each family ReportAnalyzers registers, kept beside
// it for the reason scanRules is kept beside scanAnalyzers.
func reportRules() []sarif.RuleDescriptor {
	return append(coverage.Descriptors(), codeexec.Descriptors()...)
}
