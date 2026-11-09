package coverage

import (
	"context"
	"fmt"
	"sort"
	"strings"

	catalogpkg "github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// ManifestMissing reports an instantiated module that carries no compliance
// manifest. It is not evidence, and a reader who could not see it would read
// the rest of the record as the whole configuration.
//
// A manifest-less instance whose own directory declares no resource block, a
// helper of data sources, locals and outputs, creates nothing and so leaves no
// evidence gap: it stays listed in the inventory and raises no finding. Each
// instance is judged on its own directory, so a child module with resources
// under a resource-free wrapper is still reported.
type ManifestMissing struct{}

// ID returns the rule id.
func (ManifestMissing) ID() string { return ruleManifestMissing }

// Stage returns post_init, the stage at which .terraform/modules exists.
func (ManifestMissing) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding per manifest-less instance that may declare
// resources, in key order.
func (r ManifestMissing) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	a, err := start(ctx, in)
	if a == nil || err != nil {
		return nil, err
	}

	var findings ctfkit.Findings
	for _, instance := range a.inventory.InstancesWithoutManifest {
		if instance.DeclaresNoResources || isWrapperOutsideRoot(instance, a.input.Modules.Instances) {
			continue
		}
		finding, buildErr := newFinding(r.ID(), ctfkit.LevelError,
			fmt.Sprintf(msgManifestMissing, instance.Key, ctfkit.RedactSource(instance.Source)), instance.Key,
			nil, nil, a.servedEquivalent(instance.Key))
		if buildErr != nil {
			return nil, buildErr
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// isWrapperOutsideRoot reports whether a manifest-less instance is a module
// sourced from outside the root (../) that wraps served modules. That is the
// module-author pattern of an example calling the blueprint under test, which
// the repository reports on at the blueprint's own root. It stays listed
// among the instances without a manifest; only the finding is not raised.
func isWrapperOutsideRoot(instance inventory.Instance, all []ctfkit.ModuleInstance) bool {
	if !strings.HasPrefix(instance.Source, "../") && instance.Source != ".." {
		return false
	}
	prefix := instance.Key + "."
	for _, other := range all {
		if other.Manifest != nil && strings.HasPrefix(other.Key, prefix) {
			return true
		}
	}

	return false
}

// PostureDegraded reports a served build whose manifest says the full org
// posture could not be applied, so the build was produced with less than the
// org asked for.
type PostureDegraded struct{}

// ID returns the rule id.
func (PostureDegraded) ID() string { return rulePostureDegraded }

// Stage returns post_init.
func (PostureDegraded) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding per degraded build, in build order, naming
// every reason the manifest recorded in the producer's own order.
func (r PostureDegraded) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	a, err := start(ctx, in)
	if a == nil || err != nil {
		return nil, err
	}

	var findings ctfkit.Findings
	for _, build := range a.inventory.Builds {
		if len(build.Degraded) == 0 {
			continue
		}
		finding, buildErr := newFinding(r.ID(), ctfkit.LevelError,
			fmt.Sprintf(msgPostureDegraded, ctfkit.RedactSource(build.Source), build.Version, strings.Join(build.Degraded, ", ")), "",
			nil, nil, nil)
		if buildErr != nil {
			return nil, buildErr
		}
		finding.Discriminator = build.Source
		findings = append(findings, finding)
	}

	return findings, nil
}

// DelegationUnresolved reports a control a manifest delegated to a scope that
// this configuration never instantiated. The evidence exists somewhere in the
// served package; it does not exist here.
type DelegationUnresolved struct{}

// ID returns the rule id.
func (DelegationUnresolved) ID() string { return ruleDelegationUnresolved }

// Stage returns post_init.
func (DelegationUnresolved) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding per unresolved control, in build order and then
// control id order, which internal/inventory has already put the record in.
//
// A control the record left delegated with no scope recorded is not reported:
// there is no scope to tell the reader to instantiate, and naming none would
// be a finding nobody can act on.
func (r DelegationUnresolved) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	a, err := start(ctx, in)
	if a == nil || err != nil {
		return nil, err
	}

	var findings ctfkit.Findings
	for _, build := range a.inventory.Builds {
		for _, control := range build.Controls {
			if control.Status != inventory.ControlDelegated || len(control.DelegatedTo) == 0 {
				continue
			}
			text := fmt.Sprintf(msgDelegationUnresolved,
				control.ID, strings.Join(control.DelegatedTo, ", "), ctfkit.RedactSource(build.Source), build.Version)
			controlIDs := []ctfkit.ControlID{ctfkit.ControlID(control.ID)}
			// The id comes from a served manifest, which can be newer than the
			// catalog this release embeds. ctf.controlIds holds catalog ids
			// only, so an id the catalog lacks stays in the message and the
			// finding is still reported, rather than failing the run.
			if cat := a.input.Catalog; cat != nil {
				if _, known := cat.Control(controlIDs[0]); !known {
					text += fmt.Sprintf(msgControlNotInCatalog, cat.Version().Version, catalogpkg.EmbeddedSubsetNote(cat.Version()))
					controlIDs = nil
				}
			}
			finding, buildErr := newFinding(r.ID(), ctfkit.LevelWarning, text, "",
				controlIDs, frameworkClauses(control), nil)
			if buildErr != nil {
				return nil, buildErr
			}
			finding.Discriminator = build.Source
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// ObligationUnknown reports a does_not_prove token that this release of
// ctfkit does not know. The obligation is passed to the reader verbatim and
// never blocks: a producer that states a new obligation must not be silenced
// by an older consumer.
type ObligationUnknown struct{}

// ID returns the rule id.
func (ObligationUnknown) ID() string { return ruleObligationUnknown }

// Stage returns post_init.
func (ObligationUnknown) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding per distinct unknown token across every
// manifest read, in ascending byte order. The tokens are read from the
// manifests directly: an obligation is a statement of the document rather
// than a fact about coverage, so the coverage record does not carry it.
func (r ObligationUnknown) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	a, err := start(ctx, in)
	if a == nil || err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var unknown []string
	for _, instance := range a.input.Modules.Instances {
		if instance.Manifest == nil {
			continue
		}
		for _, obligation := range instance.Manifest.Scope.DoesNotProve {
			if shippedObligationTokens[obligation.Token] || seen[obligation.Token] {
				continue
			}
			seen[obligation.Token] = true
			unknown = append(unknown, obligation.Token)
		}
	}
	sort.Strings(unknown)

	var findings ctfkit.Findings
	for _, token := range unknown {
		finding, buildErr := newFinding(r.ID(), ctfkit.LevelNote,
			fmt.Sprintf(msgObligationUnknown, token), "", nil, nil, nil)
		if buildErr != nil {
			return nil, buildErr
		}
		finding.Discriminator = token
		findings = append(findings, finding)
	}

	return findings, nil
}

// ResourceUnattested reports that the root configuration declares resources
// of its own that no served manifest and no imported test run covers. It is a
// note: an org that wants it to block says so with --fail-on.
type ResourceUnattested struct{}

// ID returns the rule id.
func (ResourceUnattested) ID() string { return ruleResourceUnattested }

// Stage returns post_init.
func (ResourceUnattested) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding when the coverage record says the root's own
// resources are unattested. A root that declares none is not-applicable
// rather than unattested, which is a different statement and not a finding.
func (r ResourceUnattested) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	a, err := start(ctx, in)
	if a == nil || err != nil {
		return nil, err
	}

	root := a.inventory.RootResources
	if root.Coverage != inventory.CoverageUnattested {
		return nil, nil
	}

	finding, buildErr := newFinding(r.ID(), ctfkit.LevelNote,
		fmt.Sprintf(msgResourceUnattested, root.Declared), "", nil, nil, nil)
	if buildErr != nil {
		return nil, buildErr
	}

	return ctfkit.Findings{finding}, nil
}

// TestsFailed reports that the imported test document records failed or
// errored runs. ctfkit did not run the tests; it reports what the runner's
// own summary said.
type TestsFailed struct{}

// ID returns the rule id.
func (TestsFailed) ID() string { return ruleTestsFailed }

// Stage returns post_init.
func (TestsFailed) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding when an imported run failed or errored. An
// absent test document is not a finding: importing one is optional.
func (r TestsFailed) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	a, err := start(ctx, in)
	if a == nil || err != nil {
		return nil, err
	}

	tests := a.input.Modules.Tests
	if tests == nil || tests.Failed+tests.Errored == 0 {
		return nil, nil
	}

	finding, buildErr := newFinding(r.ID(), ctfkit.LevelError,
		fmt.Sprintf(msgTestsFailed, tests.Failed, tests.Errored, tests.Runs), "", nil, nil, nil)
	if buildErr != nil {
		return nil, buildErr
	}

	return ctfkit.Findings{finding}, nil
}

// start is the opening move of every rule: it honors cancellation and builds
// the shared coverage record. A nil analysis and a nil error mean the stage
// populated no module inventory and the rule has nothing to report.
func start(ctx context.Context, in ctfkit.AnalyzerInput) (*analysis, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("coverage: %w", err)
	}

	return evaluate(in)
}
