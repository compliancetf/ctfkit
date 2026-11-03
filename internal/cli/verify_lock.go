package cli

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/analyzer/lockcheck"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/config"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/tfroots"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// verifyLockFormats are the --format values verify-lock renders: scan's
// list without spacelift, which has no plan policy to feed here.
var verifyLockFormats = []string{formatSARIF, formatJSON, formatText, formatPretty, formatJUnit}

// defaultWrapped is the wrapped type verify-lock checks when neither
// --provider nor wrapped_providers names one.
var defaultWrapped = []string{"aws"}

// verifyLockCommand builds `ctfkit verify-lock`.
func (c *CLI) verifyLockCommand() *cobra.Command {
	var providers []string
	var out, outDir string
	format := formatPretty

	cmd := &cobra.Command{
		Use:   "verify-lock [flags] [DIR]",
		Short: "Check that lock files install the compliance.tf provider wrappers (preview)",
		Long: `Check the lock files of every deployable root under DIR, the working directory
by default (preview). Each root must install the compliance.tf provider
wrappers: its .terraform.lock.hcl has a hashed
registry.compliance.tf/compliancetf entry for each wrapped type the root uses
and no upstream hashicorp entry for a wrapped type, and its required_providers
blocks do not name the upstream source. It reads the configuration, the lock
files and .ctfkit.yaml in DIR, and writes findings to stdout, --out or
--out-dir. Offline: no network, no credentials; it never runs terraform or tofu.

Wrapped types: --provider, else wrapped_providers in .ctfkit.yaml, else aws.

Exit codes:
  0  no finding
  1  findings
  2  could not run, or refused

On exit 2: stderr names the cause, such as a lock file that does not parse; do
not use the output files of this run. Fix the cause and run again.

Details: docs/analyzers.md`,
		Example: `  ctfkit verify-lock                       # every root under ., wrapped types from .ctfkit.yaml or aws
  ctfkit verify-lock infra --provider aws --provider google
  ctfkit verify-lock -f sarif --out lock.sarif`,
		Args: atMostOne("DIR"),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.verifyLock(cmd, args, providers, format, outputPlan{single: out, dir: outDir})
			var exitErr *ExitError
			if errors.As(err, &exitErr) {
				exitErr.Message = ctfkit.StripUserinfo(exitErr.Message)
			}
			return err
		},
	}
	f := cmd.Flags()
	f.VarP(&onceString{target: &format}, "format", "f", "Comma-separated `LIST` of formats: "+strings.Join(verifyLockFormats, ", "))
	f.StringArrayVar(&providers, "provider", nil, "Wrapped provider `TYPE` to check: "+strings.Join(config.WrappableProviders, ", ")+" (repeatable)")
	f.Var(&onceString{target: &out}, "out", outUsage)
	f.Var(&onceString{target: &outDir}, "out-dir", "Output `DIR` for findings.sarif, findings.json, findings.txt, findings.pretty.txt, findings.junit.xml")
	return cmd
}

func (c *CLI) verifyLock(cmd *cobra.Command, args, providers []string, format string, plan outputPlan) error {
	var err error
	if plan.formats, err = parseFormats(format, verifyLockFormats); err != nil {
		return err
	}
	if err = checkDestinations(plan); err != nil {
		return err
	}
	for _, p := range providers {
		if !slices.Contains(config.WrappableProviders, p) {
			return inputError("unknown --provider %q; use one of %s", p, strings.Join(config.WrappableProviders, ", "))
		}
	}

	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	in, err := c.lockSettings(dir, providers)
	if err != nil {
		return err
	}

	archive, err := loader.LoadConfig(dir)
	if err != nil {
		return environmentError(err)
	}
	archive.ClassifyModules = true
	if len(archive.Files) == 0 {
		// no roots means no findings; an empty directory is a mistyped path, not a pass
		return inputError("no configuration files (.tf, .tf.json, .tofu, .tofu.json) in %s; pass the directory that holds them", dir)
	}
	if err = parseConfig(archive); err != nil {
		return err
	}
	if archive.Lockfiles, err = rootLockfiles(archive); err != nil {
		return err
	}

	findings, err := c.lockFindings(cmd.Context(), archive, in)
	if err != nil {
		return err
	}

	if err = c.writeScan(cmd, plan, scanRun{stage: ctfkit.PrePlan, findings: findings, version: c.version}); err != nil {
		return err
	}
	return exitFor(plan, ctfkit.LevelNote, findings) // any finding is exit 1
}

// rootLockfiles reads the lock file of every deployable root of archive, which
// the ctf.lock rules check. A lock file that does not parse is exit 2.
func rootLockfiles(archive *ctfkit.ConfigArchive) (map[string]*ctfkit.Lockfile, error) {
	roots, err := tfroots.Roots(archive)
	if err != nil {
		return nil, inputError("%v", err)
	}
	dirs := make([]string, 0, len(roots))
	for _, r := range roots {
		dirs = append(dirs, r.Dir)
	}
	locks, err := loader.LoadLockfiles(archive.Root, dirs)
	if err != nil {
		return nil, environmentError(err)
	}
	return locks, nil
}

// lockSettings are the settings of dir with the wrapped types verify-lock
// checks: providers, else wrapped_providers, else defaultWrapped.
func (c *CLI) lockSettings(dir string, providers []string) (ctfkit.Settings, error) {
	settings, err := c.loadSettings(dir)
	if err != nil {
		return ctfkit.Settings{}, err
	}
	in := settings.Settings()
	switch {
	case len(providers) > 0:
		in.WrappedProviders = providers
	case len(in.WrappedProviders) == 0:
		in.WrappedProviders = defaultWrapped
	}
	return in, nil
}

// lockFindings runs the ctf.lock rules over archive, sorted.
func (c *CLI) lockFindings(ctx context.Context, archive *ctfkit.ConfigArchive, in ctfkit.Settings) (ctfkit.Findings, error) {
	r := ctfkit.NewRegistry()
	lockcheck.Register(r)
	// No exception registry: a repository cannot waive its own lock check.
	findings, err := runAnalyzers(ctx, r, ctfkit.AnalyzerInput{
		Stage:    ctfkit.PrePlan,
		Config:   archive,
		Catalog:  catalog.Embedded(),
		Settings: in,
	}, nil, catalog.Embedded(), c.now())
	if err != nil {
		return nil, err
	}
	ctfkit.SortFindings(findings)
	return findings, nil
}

// verifyRootLock is verify-lock on the root terraform runs in, before the
// first terraform call of gate plan and ctfkit apply: the root needs
// a lock file, and any ctf.lock finding refuses the run (exit 2).
// shortcut: ctf.lock.upstream_present is exempt, and only on an exact match
// of registry.terraform.io/hashicorp/aws or registry.opentofu.org/hashicorp/aws
// with kind provider (boundUpstream), because gate sign takes the version of
// provider_versions from that entry; gate sign refusing a governed
// hashicorp/aws resource (A29, TestGateSignBypass) compensates. Drop the
// exemption once that version comes from the wrapper.
func (c *CLI) verifyRootLock(ctx context.Context, dir string) error {
	in, err := c.lockSettings(dir, nil)
	if err != nil {
		return err
	}
	// The gated repository may add wrapped types, never drop a default.
	wrapped := slices.Clone(in.WrappedProviders)
	for _, t := range defaultWrapped {
		if !slices.Contains(wrapped, t) {
			wrapped = append(wrapped, t)
		}
	}
	in.WrappedProviders = wrapped
	archive, err := loader.LoadConfig(dir)
	if err != nil {
		return environmentError(err)
	}
	// Only the root terraform runs in: a root nested under it is another run's.
	archive.Files = slices.DeleteFunc(archive.Files, func(f ctfkit.ConfigFile) bool { return path.Dir(f.Path) != "." })
	archive.ClassifyModules = true
	if err = parseConfig(archive); err != nil {
		return err
	}
	if archive.Lockfiles, err = loader.LoadLockfiles(dir, []string{"."}); err != nil {
		return environmentError(err)
	}
	if archive.Lockfiles["."] == nil {
		return inputError("verify-lock: %s has no .terraform.lock.hcl; terraform did not run", dir)
	}
	findings, err := c.lockFindings(ctx, archive, in)
	if err != nil {
		return err
	}
	var refused []string
	for _, f := range findings {
		if !boundUpstream(f) {
			refused = append(refused, fmt.Sprintf("%s: %s", f.RuleID, f.Message.Text))
		}
	}
	if refused != nil {
		return inputError("verify-lock: %s; terraform did not run", strings.Join(refused, "; "))
	}
	return nil
}

// boundAddresses are the provider addresses ctf.lock.upstream_present gives
// the hashicorp/aws entry gate sign binds, from either registry.
var boundAddresses = []string{`provider["registry.terraform.io/hashicorp/aws"]`, `provider["registry.opentofu.org/hashicorp/aws"]`}

// boundUpstream reports ctf.lock.upstream_present on exactly the
// hashicorp/aws entry gate sign binds, and nothing else. The
// finding carries the entry only as its provider logical location.
func boundUpstream(f ctfkit.Finding) bool {
	if f.RuleID != "ctf.lock.upstream_present" || len(f.Locations) != 1 || len(f.Locations[0].LogicalLocations) != 1 {
		return false
	}
	l := f.Locations[0].LogicalLocations[0]
	return l.Kind == ctfkit.LogicalLocationProvider && slices.Contains(boundAddresses, l.FullyQualifiedName)
}
