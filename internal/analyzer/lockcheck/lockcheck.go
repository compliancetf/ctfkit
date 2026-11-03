// Package lockcheck implements the ctf.lock rules: whether the dependency lock
// file of every deployable root installs the compliance.tf wrapper of each
// wrapped provider type and nothing that bypasses it. ctfkit verify-lock runs
// them; scan --stage pre_plan runs them too when wrapped_providers is set.
//
// The rules read the configuration and the lock files the command loaded
// (ConfigArchive.Lockfiles) and nothing else: no network, no registry, no
// checksum is recomputed. Like the ctf.origin family, every finding is
// framework agnostic: no control ids, no frameworks.
//
// ctf.lock.shape (PM-T32) is not here yet: it compares the wrapper entry with
// the pinned wrapper release, which ctfkit does not carry yet. It registers in
// Register and Descriptors as one more Analyzer value of this package, reading
// the same Lockfiles.
package lockcheck

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/compliancetf/ctfkit/internal/analyzer/origin"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/tfroots"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The rule ids of the family.
const (
	ruleMissing         = "ctf.lock.missing"
	ruleUpstreamPresent = "ctf.lock.upstream_present"
	ruleWrapperMissing  = "ctf.lock.wrapper_missing"
	ruleWrapperUnhashed = "ctf.lock.wrapper_unhashed"
	ruleSourceMismatch  = "ctf.lock.source_mismatch"
	ruleUnwrapped       = "ctf.lock.unwrapped"
)

// Provider addresses the rules compare. Every source is compared lower case.
const (
	wrapperNamespace = "registry.compliance.tf/compliancetf/"
	upstreamNS       = "hashicorp/"
	lockFileName     = ".terraform.lock.hcl"
	zhPrefix         = "zh:"
)

// upstreamHosts serve the upstream hashicorp namespace: Terraform records the
// first in a lock file, OpenTofu the second.
var upstreamHosts = []string{"registry.terraform.io/", "registry.opentofu.org/"}

// unwrappedSiblings are upstream types that manage the resources of a wrapped
// type without passing through its wrapper.
var unwrappedSiblings = map[string][]string{"google": {"google-beta"}}

// Descriptors returns the tool.driver.rules entries of the family.
func Descriptors() []sarif.RuleDescriptor {
	return []sarif.RuleDescriptor{
		{ID: ruleMissing, ShortDescription: "A deployable root has no dependency lock file", Level: ctfkit.LevelError},
		{ID: ruleUpstreamPresent, ShortDescription: "The lock file installs the upstream provider of a wrapped type", Level: ctfkit.LevelError},
		{ID: ruleWrapperMissing, ShortDescription: "The lock file has no compliance.tf wrapper entry for a wrapped type the root uses", Level: ctfkit.LevelError},
		{ID: ruleWrapperUnhashed, ShortDescription: "The compliance.tf wrapper entry of the lock file records no zh: hash", Level: ctfkit.LevelError},
		{ID: ruleSourceMismatch, ShortDescription: "A required_providers entry names, or a missing entry implies, the upstream source of a wrapped type", Level: ctfkit.LevelError},
		{ID: ruleUnwrapped, ShortDescription: "The lock file installs an upstream provider that bypasses a wrapped type", Level: ctfkit.LevelWarning},
	}
}

// Register adds the family to r, in emission order.
func Register(r ctfkit.Registry) {
	ctfkit.MustRegister(r, Missing{}, UpstreamPresent{}, WrapperMissing{}, WrapperUnhashed{}, SourceMismatch{}, Unwrapped{})
}

// Missing is ctf.lock.missing: a deployable root with no lock file.
type Missing struct{}

// ID implements ctfkit.Analyzer.
func (Missing) ID() string { return ruleMissing }

// Stage implements ctfkit.Analyzer.
func (Missing) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (Missing) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return eachRoot(ctx, in, ruleMissing, ctfkit.LevelError, func(r rootLock, _ []string) ([]draft, error) {
		if r.lock != nil {
			return nil, nil
		}
		return []draft{{text: fmt.Sprintf("Root %s has no %s, so terraform init picks the providers it installs", r.dir, lockFileName)}}, nil
	})
}

// UpstreamPresent is ctf.lock.upstream_present: a lock entry for the upstream
// hashicorp provider of a wrapped type. A network mirror serving the wrapper
// under the upstream address fails here too, by design.
type UpstreamPresent struct{}

// ID implements ctfkit.Analyzer.
func (UpstreamPresent) ID() string { return ruleUpstreamPresent }

// Stage implements ctfkit.Analyzer.
func (UpstreamPresent) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (UpstreamPresent) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return eachEntry(ctx, in, ruleUpstreamPresent, ctfkit.LevelError, func(source string, _ ctfkit.LockedProvider, wrapped []string) string {
		if t, ok := upstreamType(source); ok && slices.Contains(wrapped, t) {
			return fmt.Sprintf("Lock entry %s installs the upstream %s provider, which bypasses the compliance.tf wrapper %s%s",
				source, t, wrapperNamespace, t)
		}
		return ""
	})
}

// WrapperMissing is ctf.lock.wrapper_missing: a wrapped type the root uses has
// no wrapper entry. A root uses a type when a lock entry of any source has
// that type, or when a required_providers entry of the root directory names
// it.
type WrapperMissing struct{}

// ID implements ctfkit.Analyzer.
func (WrapperMissing) ID() string { return ruleWrapperMissing }

// Stage implements ctfkit.Analyzer.
func (WrapperMissing) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (WrapperMissing) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if _, ok := ready(ctx, in); !ok {
		return nil, ctx.Err()
	}
	required := origin.RequiredProviders(in.Config)
	return eachRoot(ctx, in, ruleWrapperMissing, ctfkit.LevelError, func(r rootLock, wrapped []string) ([]draft, error) {
		if r.lock == nil {
			return nil, nil // ctf.lock.missing says it
		}
		used := map[string]bool{}
		have := map[string]bool{}
		for _, lp := range r.lock.Providers {
			source := strings.ToLower(lp.Source)
			used[providerType(source)] = true
			if t, ok := strings.CutPrefix(source, wrapperNamespace); ok {
				have[t] = true
			}
		}
		// shortcut: required_providers of the local modules a root calls are not
		// followed; terraform init writes their providers into the root's lock.
		for _, rp := range required {
			if rp.Dir == r.dir {
				used[providerType(rp.Source)] = true
			}
		}
		var out []draft
		for _, t := range wrapped {
			if used[t] && !have[t] {
				out = append(out, draft{
					text:    fmt.Sprintf("Root %s uses the %s provider but %s has no %s%s entry", r.dir, t, lockFileName, wrapperNamespace, t),
					address: providerAddress(wrapperNamespace + t),
				})
			}
		}
		return out, nil
	})
}

// WrapperUnhashed is ctf.lock.wrapper_unhashed: a wrapper entry with no zh:
// hash, so the package Terraform installs is checked against no published
// checksum.
type WrapperUnhashed struct{}

// ID implements ctfkit.Analyzer.
func (WrapperUnhashed) ID() string { return ruleWrapperUnhashed }

// Stage implements ctfkit.Analyzer.
func (WrapperUnhashed) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (WrapperUnhashed) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return eachEntry(ctx, in, ruleWrapperUnhashed, ctfkit.LevelError, func(source string, lp ctfkit.LockedProvider, wrapped []string) string {
		t, ok := strings.CutPrefix(source, wrapperNamespace)
		if !ok || !slices.Contains(wrapped, t) || slices.ContainsFunc(lp.Hashes, isZH) {
			return ""
		}
		return fmt.Sprintf("Lock entry %s records no zh: hash, so the installed package is not checked against the release checksums", source)
	})
}

func isZH(h string) bool { return strings.HasPrefix(h, zhPrefix) }

// SourceMismatch is ctf.lock.source_mismatch: a required_providers entry, in a
// root or a module directory, that names the upstream source of a wrapped
// type. An entry with no source names it implicitly, and so does a resource
// or provider block of the type with no entry at all.
type SourceMismatch struct{}

// ID implements ctfkit.Analyzer.
func (SourceMismatch) ID() string { return ruleSourceMismatch }

// Stage implements ctfkit.Analyzer.
func (SourceMismatch) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (SourceMismatch) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	wrapped, ok := ready(ctx, in)
	if !ok {
		return nil, ctx.Err()
	}
	var out ctfkit.Findings
	for _, rp := range origin.RequiredProviders(in.Config) {
		t, isUpstream := upstreamType(rp.Source)
		if !isUpstream || !slices.Contains(wrapped, t) {
			continue
		}
		f, err := newFinding(ruleSourceMismatch, ctfkit.LevelError,
			fmt.Sprintf("required_providers names %s; use %s%s", rp.Source, wrapperNamespace, t), rp.Location)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	for _, rp := range origin.ImpliedRequirements(in.Config) {
		t, isUpstream := upstreamType(rp.Source)
		if !isUpstream || !slices.Contains(wrapped, t) {
			continue
		}
		f, err := newFinding(ruleSourceMismatch, ctfkit.LevelError,
			fmt.Sprintf("Directory %s has no required_providers entry for %s, so it resolves to %s; add one with source %s%s", rp.Dir, t, rp.Source, wrapperNamespace, t), rp.Location)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// Unwrapped is ctf.lock.unwrapped: a lock entry for an upstream sibling, such
// as google-beta, of a wrapped type. Its resources do not pass through the
// wrapper; it is a warning because no wrapper exists for the sibling.
type Unwrapped struct{}

// ID implements ctfkit.Analyzer.
func (Unwrapped) ID() string { return ruleUnwrapped }

// Stage implements ctfkit.Analyzer.
func (Unwrapped) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (Unwrapped) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return eachEntry(ctx, in, ruleUnwrapped, ctfkit.LevelWarning, func(source string, _ ctfkit.LockedProvider, wrapped []string) string {
		t, ok := upstreamType(source)
		if !ok {
			return ""
		}
		for _, w := range wrapped {
			if slices.Contains(unwrappedSiblings[w], t) {
				return fmt.Sprintf("Lock entry %s manages %s resources outside the compliance.tf wrapper %s%s", source, w, wrapperNamespace, w)
			}
		}
		return ""
	})
}

// rootLock is one deployable root and its lock file, nil when it has none.
type rootLock struct {
	dir  string
	lock *ctfkit.Lockfile
}

// draft is a finding before its location: the message and, for an entry, the
// provider address it is about.
type draft struct {
	text    string
	address string
}

// ready is the wrapped types when the rules have something to check: wrapped
// types are set and the command read the root lock files. An explicit file
// list reads none, and the rules stay silent rather than report every root as
// missing one.
func ready(ctx context.Context, in ctfkit.AnalyzerInput) ([]string, bool) {
	if ctx.Err() != nil || in.Config == nil || in.Config.Lockfiles == nil || len(in.Settings.WrappedProviders) == 0 {
		return nil, false
	}
	return in.Settings.WrappedProviders, true
}

// eachRoot runs check over every deployable root and anchors what it returns
// at the root's lock file path.
func eachRoot(ctx context.Context, in ctfkit.AnalyzerInput, rule, level string, check func(rootLock, []string) ([]draft, error)) (ctfkit.Findings, error) {
	wrapped, ok := ready(ctx, in)
	if !ok {
		return nil, ctx.Err()
	}
	roots, err := tfroots.Roots(in.Config)
	if err != nil {
		return nil, err
	}
	var out ctfkit.Findings
	for _, root := range roots {
		drafts, err := check(rootLock{dir: root.Dir, lock: in.Config.Lockfiles[root.Dir]}, wrapped)
		if err != nil {
			return nil, err
		}
		for _, d := range drafts {
			f, err := newFinding(rule, level, d.text, lockLocation(root.Dir, d.address))
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// eachEntry runs check over every entry of every root lock file and reports
// the entries it returns a message for.
func eachEntry(ctx context.Context, in ctfkit.AnalyzerInput, rule, level string, check func(string, ctfkit.LockedProvider, []string) string) (ctfkit.Findings, error) {
	return eachRoot(ctx, in, rule, level, func(r rootLock, wrapped []string) ([]draft, error) {
		if r.lock == nil {
			return nil, nil
		}
		var out []draft
		for _, lp := range r.lock.Providers {
			source := strings.ToLower(lp.Source)
			if text := check(source, lp, wrapped); text != "" {
				out = append(out, draft{text: text, address: providerAddress(source)})
			}
		}
		return out, nil
	})
}

// upstreamType is the type of a source in the upstream hashicorp namespace of
// a host that serves it, false for any other source.
func upstreamType(source string) (string, bool) {
	for _, host := range upstreamHosts {
		if t, ok := strings.CutPrefix(source, host+upstreamNS); ok && !strings.Contains(t, "/") {
			return t, true
		}
	}
	return "", false
}

// providerType is the last segment of a source, its provider type.
func providerType(source string) string { return path.Base(source) }

func providerAddress(source string) string { return fmt.Sprintf("provider[%q]", source) }

// lockLocation is the lock file path of root, archive relative, and the
// provider address the finding is about, when it is about one entry.
func lockLocation(root, address string) ctfkit.Location {
	loc := ctfkit.Location{PhysicalLocation: &ctfkit.PhysicalLocation{
		ArtifactLocation: ctfkit.ArtifactLocation{URI: path.Join(root, lockFileName)},
	}}
	if address != "" {
		loc.LogicalLocations = []ctfkit.LogicalLocation{{FullyQualifiedName: address, Kind: ctfkit.LogicalLocationProvider}}
	}
	return loc
}

func newFinding(rule, level, text string, loc ctfkit.Location) (ctfkit.Finding, error) {
	return ctfkit.NewFinding(rule, level, ctfkit.KindFail, ctfkit.Message{Text: text}, []ctfkit.Location{loc},
		ctfkit.Properties{
			Schema:     "1.0",
			Stage:      ctfkit.PrePlan,
			ControlIDs: []ctfkit.ControlID{},
			Frameworks: []ctfkit.FrameworkClauses{},
		})
}
