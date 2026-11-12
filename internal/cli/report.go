package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/config"
	"github.com/compliancetf/ctfkit/internal/exceptions"
	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/render/markdown"
	"github.com/compliancetf/ctfkit/internal/render/pack"
	"github.com/compliancetf/ctfkit/internal/render/receipt"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/render/spacelift"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Projection names --format accepts.
const (
	formatMarkdown  = "markdown"
	formatReceipt   = "receipt"
	formatSARIF     = "sarif"
	formatSpacelift = "spacelift"
)

// File names --out-dir writes. The Spacelift file is not among them: it always
// lands in the run's working directory, where Spacelift discovers it.
const (
	fileReport  = "report.md"
	fileReceipt = "receipt.json"
	fileSARIF   = "findings.sarif"
)

// failOnEnv is the environment variable of the --fail-on precedence chain:
// flag, then this, then the settings file, then the default.
const failOnEnv = "CTFKIT_FAIL_ON"

// modulesJSONRelPath is the file the receipt digests. The loader reads it too;
// the digest is taken here over the same path so the receipt names the document
// that was analyzed.
const modulesJSONRelPath = ".terraform/modules/modules.json"

// failOnRank orders the --fail-on thresholds. A finding counts when its own
// level ranks at or above the threshold, so "note" widens the gate to
// everything and "never" (absent from this map) closes it.
var failOnRank = map[string]int{
	ctfkit.LevelError:   0,
	ctfkit.LevelWarning: 1,
	ctfkit.LevelNote:    2,
}

// failOnNever disables exit 1 without changing the verdict. Shadow-mode
// rollouts run with it first.
const failOnNever = "never"

// reportOptions are the flags of one `ctfkit report` invocation. They are a
// value rather than fields on CLI so that two invocations in one process, which
// is what the tests do, cannot see each other's flags.
type reportOptions struct {
	paths      []string
	testsJSON  string
	exceptions string
	catalog    string
	formats    string
	out        string
	outDir     string
	readme     string
	markers    string
	failOn     string
	runID      string
	commit     string
	platform   string
	watermark  string
}

// reportCommand builds `ctfkit report`.
//
// Ordering: the report projections list findings by level descending and, within
// a level, in analyzer emission order. That is not the SDK's SortFindings key of
// (ruleId, uri, line, subject), and the difference is deliberate. Every recorded
// case under testdata/fixtures/report was rendered in the level-then-emission
// order, byte parity against those files is the cutover gate for replacing an
// existing report generator, and a reader of a compliance report looks for the
// failures first rather than for the alphabetically first rule id. The
// alternative was to re-record seven fixtures to please a sort key no projection
// wants.
func (c *CLI) reportCommand() *cobra.Command {
	opts := &reportOptions{}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report the controls compliance.tf modules enforce, after init",
		Long: `Report the controls that the compliance.tf modules of a configuration enforce.
Run it after terraform init or tofu init. It reads
.terraform/modules, the module manifests, .ctfkit.yaml and .ctf-exceptions.yaml
in the working directory. It writes the formats --format lists (markdown by
default) to stdout, --out or --out-dir. --readme FILE puts the markdown into the
marked section of FILE instead of stdout; with --out or --out-dir the files are
written as well. Spacelift metadata always goes to ctfkit.custom.spacelift.json
in the working directory. --out-dir also writes evidence-pack.zip, the
evidence pack of the release for readers who do not run ctfkit; it is
unsigned. Offline: no network, no credentials; it never runs terraform or
tofu.

The report says what the modules enforce, what the configuration declares
itself and what the report does not prove, and names code that runs before a
plan is reviewed (ctf.exec.*).

Exit codes:
  0  no unsuppressed finding at or above --fail-on
  1  unsuppressed findings at or above --fail-on
  2  could not run, or refused

With --format spacelift alone, a completed run exits 0 whatever it finds: the
Spacelift plan policy reads the metadata file and decides.

On exit 2: stderr names the cause; do not use the output files of this run, and
check the --readme file, which may already be rewritten. When stderr names a
missing module cache, run terraform init (or tofu init) here first.

Details: docs/commands.md`,
		Example: `  terraform init                                        # first: report reads .terraform/modules
  ctfkit report                                         # markdown to stdout
  ctfkit report --readme README.md                      # rewrite the section between the markers
  ctfkit report -f receipt,sarif,markdown --out-dir out/
  ctfkit report --tests-json tests.json                 # from: tofu test -json > tests.json`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.runReport(cmd, opts)
		},
	}

	// Any invalid, unknown or repeated flag is an input error, exit 2, the rule
	// scan applies. The message is stripped of userinfo because a flag error
	// echoes the value it refused, and a value can carry credentials.

	// Every single-value flag refuses a second use: taking the last value would
	// run a different report than the command line reads as. --path is
	// repeatable by design and keeps its slice.
	f := cmd.Flags()
	once := func(p *string, name, usage string) { f.Var(&onceString{target: p}, name, usage) }
	f.StringSliceVar(&opts.paths, "path", nil, "Module root or example `DIR` (repeatable; default \".\")")
	once(&opts.testsJSON, "tests-json", "Test results `FILE` from tofu test -json or terraform test -json for this root")
	once(&opts.exceptions, "exceptions", "Exception registry `FILE` (default: .ctf-exceptions.yaml in the working directory, when present)")
	once(&opts.catalog, "catalog", catalogUsage)
	// The default is set on the target before binding, so help still shows it.
	opts.formats = formatMarkdown
	f.VarP(&onceString{target: &opts.formats}, "format", "f", "Comma-separated `LIST` of formats: markdown, receipt, sarif, spacelift")
	once(&opts.out, "out", outUsage)
	once(&opts.outDir, "out-dir", "Output `DIR` for report.md, receipt.json, findings.sarif and evidence-pack.zip")
	once(&opts.readme, "readme", "Rewrite the section between the markers in this `FILE`")
	once(&opts.markers, "markers", "Marker `PAIR` START,END (default: "+markdown.DefaultStartMarker+","+markdown.DefaultEndMarker+")")
	once(&opts.failOn, "fail-on", failOnUsage)
	once(&opts.runID, "run-id", runIDUsage)
	once(&opts.commit, "commit", commitUsage)
	once(&opts.platform, "platform", platformUsage)
	once(&opts.watermark, "watermark", bannerUsage)

	return cmd
}

// runReport is the whole pipeline: resolve the flags, load the inputs and the
// policy files, build the coverage record, run the post_init analyzers, order
// the findings, render every requested projection, and choose the exit code.
func (c *CLI) runReport(cmd *cobra.Command, opts *reportOptions) error {
	plan, err := resolveOutputs(opts)
	if err != nil {
		return err
	}

	// The discovery root of report is the process working directory and never
	// a --path root, because --path is repeatable and several roots cannot each
	// carry one policy. The file is read even when --fail-on is given:
	// allowed_endpoints decides ctf.exec.module_endpoint, so a settings file
	// that does not load stops the run rather than falling back to defaults.
	settings, err := c.loadSettings(".")
	if err != nil {
		return err
	}
	threshold, err := resolveFailOn(opts.failOn, func() (*config.Config, error) { return settings, nil })
	if err != nil {
		return err
	}

	root, err := resolveRoot(opts)
	if err != nil {
		return err
	}

	run, err := c.analyze(cmd.Context(), root, opts, settings.Settings())
	if err != nil {
		return err
	}

	if err = c.write(cmd, plan, opts, run); err != nil {
		return err
	}

	return exitFor(plan, threshold, run.findings)
}

// outputPlan is the resolved destination of every requested projection.
type outputPlan struct {
	formats []string
	// single is the one destination --out named, empty when --out-dir or the
	// default stdout applies.
	single string
	dir    string
}

// wants reports whether the projection was requested.
func (p outputPlan) wants(format string) bool {
	for _, f := range p.formats {
		if f == format {
			return true
		}
	}
	return false
}

// spaceliftOnly reports whether the format list is exactly spacelift, the one
// case that returns 0 on findings: the plan policy is the gate there and needs
// the file in order to render the denial.
func (p outputPlan) spaceliftOnly() bool {
	return len(p.formats) == 1 && p.formats[0] == formatSpacelift
}

// resolveOutputs parses --format and checks it against --out and --out-dir.
// Every rejection here is exit 2: a run whose output has nowhere to go has not
// judged the configuration.
func resolveOutputs(opts *reportOptions) (outputPlan, error) {
	formats, err := parseFormats(opts.formats,
		[]string{formatMarkdown, formatReceipt, formatSARIF, formatSpacelift})
	if err != nil {
		return outputPlan{}, err
	}

	plan := outputPlan{formats: formats, single: opts.out, dir: opts.outDir}

	if err = checkDestinations(plan); err != nil {
		return outputPlan{}, err
	}

	switch {
	case !plan.wants(formatMarkdown) && opts.readme != "":
		return outputPlan{}, inputError("--readme has nothing to inject: --format does not name %s", formatMarkdown)
	case !plan.wants(formatMarkdown) && opts.markers != "":
		return outputPlan{}, inputError("--markers has nothing to delimit: --format does not name %s", formatMarkdown)
	}

	return plan, nil
}

// parseFormats splits a --format list and checks every name against known.
// An empty entry, an unknown name and a repeated name are each exit 2.
func parseFormats(value string, known []string) ([]string, error) {
	var formats []string
	seen := map[string]bool{}
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		switch {
		case name == "":
			return nil, inputError("--format has an empty entry: %q", value)
		case !contains(known, name):
			return nil, inputError("unknown --format %q; use one of %s", name, strings.Join(known, ", "))
		case seen[name]:
			return nil, inputError("--format names %s twice", name)
		}
		seen[name] = true
		formats = append(formats, name)
	}

	return formats, nil
}

// oneFormat is parseFormats for a command that renders one document.
func oneFormat(cmd *cobra.Command, value string, known []string) (string, error) {
	formats, err := parseFormats(value, known)
	if err == nil && len(formats) > 1 {
		err = inputError("--format names %d formats, and %q writes one; use one of %s", len(formats), cmd.CommandPath(), strings.Join(known, ", "))
	}
	if err != nil {
		return "", err
	}
	return formats[0], nil
}

// checkDestinations holds --out and --out-dir to the format list.
func checkDestinations(plan outputPlan) error {
	switch {
	case plan.single != "" && plan.dir != "":
		return inputError("--out and --out-dir name two destinations for one document")
	case plan.single != "" && len(plan.formats) > 1:
		return inputError("--out writes one file, and --format names %d formats; use --out-dir to write one file per format", len(plan.formats))
	case plan.single != "" && plan.spaceliftOnly():
		return inputError("--out cannot move the Spacelift file: Spacelift discovers it by name in the working directory")
	case plan.dir != "" && plan.spaceliftOnly():
		// Nothing would be written there. A flag that is quietly a no-op is
		// worse than a refusal: the operator goes looking for a file that was
		// never going to arrive.
		return inputError("--out-dir has nothing to write: the Spacelift file always goes to the working directory")
	}

	// Several documents and nowhere to put them: writing two to stdout would
	// interleave one document with another.
	if plan.single == "" && plan.dir == "" && countWritten(plan.formats) > 1 {
		return inputError("--format names several formats, so --out-dir is required")
	}

	return nil
}

// contains reports whether list holds s.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// countWritten counts the projections that need a destination. The Spacelift
// file has a fixed one of its own and never competes for stdout.
func countWritten(formats []string) int {
	n := 0
	for _, f := range formats {
		if f != formatSpacelift {
			n++
		}
	}
	return n
}

// resolveFailOn applies the precedence chain: the flag, then CTFKIT_FAIL_ON,
// then the settings file, then the default error. settings is called only when
// the first two links are empty, so a malformed settings file does not fail a
// run that never needed it.
func resolveFailOn(flag string, settings func() (*config.Config, error)) (string, error) {
	value := flag
	if value == "" {
		value = os.Getenv(failOnEnv)
	}
	if value == "" {
		cfg, err := settings()
		if err != nil {
			return "", err
		}
		value = cfg.FailOn
	}
	if value == "" {
		return ctfkit.LevelError, nil
	}

	if _, ok := failOnRank[value]; !ok && value != failOnNever {
		return "", inputError("unknown --fail-on %q; use one of error, warning, note, never", value)
	}

	return value, nil
}

// loadSettings loads the .ctfkit.yaml the run is governed by: the file --config
// names, else .ctfkit.yaml in the discovery root when it is there, else the
// defaults.
func (c *CLI) loadSettings(root string) (*config.Config, error) {
	path := c.configPath
	if path == "" {
		path = filepath.Join(root, config.FileName)
		if _, err := os.Stat(path); err != nil {
			return config.Default(), nil
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		return nil, settingsError(path, err, "")
	}

	return cfg, nil
}

// resolveRoot picks the single root this run reports on.
//
// --path is repeatable in the flag surface because a later release reports on
// several roots in one run. This release refuses more than one rather than
// guessing: the receipt names one subject, the Markdown section names one root,
// and --out-dir holds one report.md, so two roots would either collide in the
// output or silently drop one.
func resolveRoot(opts *reportOptions) (string, error) {
	switch len(opts.paths) {
	case 0:
		return ".", nil
	case 1:
		return opts.paths[0], nil
	default:
		return "", inputError("--path was given %d times; this release reports on one root per run", len(opts.paths))
	}
}

// runResult is everything the renderers read, gathered once.
type runResult struct {
	modules  *ctfkit.ModuleInventory
	record   *inventory.Inventory
	findings ctfkit.Findings
	metadata ctfkit.RunMetadata
	digest   string
	tests    *ctfkit.TestRun
	root     string
	// catalog is the version of the catalog the run read, which the SARIF
	// run records and which decides whether it carries a stale-catalog notice.
	catalog ctfkit.CatalogVersion
	// controls is the catalog itself, which the evidence pack reads.
	controls *catalog.FileCatalog
}

// analyze loads every input, runs the post_init analyzers and returns the
// ordered findings.
func (c *CLI) analyze(ctx context.Context, root string, opts *reportOptions, settings ctfkit.Settings) (*runResult, error) {
	cat, version, err := catalog.Resolve(opts.catalog)
	if err != nil {
		return nil, fileError("catalog file ", err, catalogNotFound)
	}

	registry, err := loadExceptions(opts.exceptions, ".")
	if err != nil {
		return nil, err
	}

	modules, err := loader.LoadModules(root)
	if err != nil {
		return nil, environmentError(err)
	}

	if err = requireManifests(root, modules); err != nil {
		return nil, err
	}

	digest, err := digestModulesJSON(root)
	if err != nil {
		return nil, environmentError(err)
	}

	// A root whose configuration cannot be read is an environment error and
	// not "a root that declares no resources": the difference decides whether
	// resource_unattested fires.
	cfg, err := loader.LoadConfig(root)
	if err != nil {
		return nil, environmentError(err)
	}

	var tests *ctfkit.TestRun
	if opts.testsJSON != "" {
		tests, err = loader.ImportTests(opts.testsJSON)
		if err != nil {
			return nil, environmentError(err)
		}
		modules.Tests = tests
	}

	record, err := inventory.Build(modules, cfg)
	if err != nil {
		return nil, environmentError(err)
	}

	metadata := loader.DetectRunMetadata(os.Getenv, c.now(), loader.RunFlags{
		RunID:    opts.runID,
		Commit:   opts.commit,
		Platform: opts.platform,
	})

	in := ctfkit.AnalyzerInput{
		Stage:    ctfkit.PostInit,
		Config:   cfg,
		Modules:  modules,
		Catalog:  cat,
		Settings: settings,
		Metadata: metadata,
	}

	findings, err := runAnalyzers(ctx, ReportAnalyzers(), in, registry, cat, metadata.Now)
	if err != nil {
		return nil, err
	}
	findings = orderFindings(findings)

	return &runResult{
		modules:  modules,
		record:   record,
		findings: findings,
		metadata: metadata,
		digest:   digest,
		tests:    tests,
		root:     root,
		catalog:  version,
		controls: cat,
	}, nil
}

// requireManifests refuses a root that carries no manifest at all.
//
// One instance without a manifest among several is a finding: the report lists
// it as not-evidence and says so. A root where not one instance carries a
// manifest is a different statement. There is no served build to report on, so
// every projection would be an empty coverage document with a pass verdict,
// which reads exactly like a configuration whose modules all enforce nothing.
// It is the "no manifests at all" environment error of the specification, and
// it is usually a stale or partial .terraform tree rather than a compliance
// result.
func requireManifests(root string, modules *ctfkit.ModuleInventory) error {
	for _, instance := range modules.Instances {
		if instance.Manifest != nil {
			return nil
		}
	}

	return inputError(
		"no %s under %s: this configuration instantiates no compliance.tf served module, so there is nothing to report on",
		"compliancetf-manifest.json", filepath.Join(root, filepath.FromSlash(".terraform/modules")))
}

// loadExceptions reads the exception registry: the file --exceptions names, or
// .ctf-exceptions.yaml in root when it is there. A file that exists and does
// not load is an error, because a waiver nobody can read is not a waiver
// nobody wrote.
func loadExceptions(flag, root string) (ctfkit.ExceptionRegistry, error) {
	if flag != "" {
		reg, err := exceptions.Load(flag)
		if err != nil {
			return nil, fileError("exceptions file ", err, "")
		}
		return reg, nil
	}

	reg, err := exceptions.Discover(root)
	if err != nil {
		return nil, fileError("exceptions file ", err, "")
	}

	return reg, nil
}

// runAnalyzers runs every analyzer of the input's stage, validates each finding
// at the emit boundary and applies the exception registry. Ordering is the
// caller's: report and scan order their projections differently.
func runAnalyzers(ctx context.Context, analyzers ctfkit.Registry, in ctfkit.AnalyzerInput,
	reg ctfkit.ExceptionRegistry, cat ctfkit.ControlCatalog, now time.Time,
) (ctfkit.Findings, error) {
	var collected ctfkit.Findings
	for _, a := range analyzers.ByStage(in.Stage) {
		produced, err := a.Analyze(ctx, in)
		if err != nil {
			return nil, categorized(categoryAnalyzer, "%s: %v", a.ID(), err)
		}

		for _, f := range produced {
			// ValidateFor is the emit boundary: it re-strips userinfo, checks
			// the finding against the analyzer that produced it and the stage
			// it ran at, and refuses a finding that granted itself an
			// exception. A failure here is a malfunction, not a finding.
			sanitized, validateErr := f.ValidateFor(a.ID(), in.Stage, cat)
			if validateErr != nil {
				return nil, categorized(categoryFinding, "%s: %v", a.ID(), validateErr)
			}

			if property, _ := ctfkit.Decide(sanitized, reg, now); property != nil {
				sanitized = ctfkit.WithException(sanitized, *property)
			}

			collected = append(collected, sanitized)
		}
	}

	return collected, nil
}

// orderFindings sorts by level descending and keeps analyzer emission order
// within a level. See the note on reportCommand for why this is not
// ctfkit.SortFindings.
func orderFindings(findings ctfkit.Findings) ctfkit.Findings {
	out := make(ctfkit.Findings, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool { return levelRank(out[i].Level) < levelRank(out[j].Level) })

	return out
}

// levelRank orders errors before warnings before notes. An unrecognized level
// sorts last rather than being dropped: a finding a renderer does not know is
// still a finding.
func levelRank(level string) int {
	if rank, ok := failOnRank[level]; ok {
		return rank
	}
	return len(failOnRank)
}

// digestModulesJSON hashes the modules.json the loader just read. The receipt
// names the document that was analyzed, so the digest is over the file on disk
// and not over a re-serialization of the parsed value.
func digestModulesJSON(root string) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(modulesJSONRelPath))

	content, err := os.ReadFile(path) // #nosec G304 -- the loader already read and validated this exact path within the root
	if err != nil {
		return "", fmt.Errorf("%w: reading %s: %w", loader.ErrInput, path, err)
	}

	sum := sha256.Sum256(content)

	return hex.EncodeToString(sum[:]), nil
}

// write renders every requested projection to its destination. SARIF is
// rendered first, as scan does: a finding the renderer refuses stops the run
// before any file is written, so an analyzer defect never leaves a partial set
// of projections.
func (c *CLI) write(cmd *cobra.Command, plan outputPlan, opts *reportOptions, run *runResult) error {
	// --out-dir also writes the evidence pack, which carries the SARIF and the
	// receipt whatever --format named.
	var sarifDoc []byte
	if plan.wants(formatSARIF) || plan.dir != "" {
		var err error
		if sarifDoc, err = renderReportSARIF(c.version, opts, run); err != nil {
			return err
		}
	}

	if plan.wants(formatMarkdown) {
		if err := c.writeMarkdown(cmd, plan, opts, run); err != nil {
			return err
		}
	}

	var receiptDoc []byte
	if plan.wants(formatReceipt) || plan.dir != "" {
		var err error
		receiptDoc, err = receipt.Render(receipt.Input{
			Inventory:         run.record,
			Modules:           run.modules,
			ModulesJSONSHA256: run.digest,
			Findings:          run.findings,
			Metadata:          run.metadata,
			Tests:             run.tests,
			Watermark:         opts.watermark,
			Generator:         receipt.Generator{Name: "ctfkit", Version: c.version},
		})
		if err != nil {
			return inputError("%v", err)
		}
	}
	if plan.wants(formatReceipt) {
		if err := c.emit(cmd, plan, fileReceipt, receiptDoc); err != nil {
			return err
		}
	}

	if plan.wants(formatSpacelift) {
		body, err := spacelift.Render(spacelift.Input{
			Stage:     ctfkit.PostInit,
			Findings:  run.findings,
			Watermark: opts.watermark,
		})
		if err != nil {
			return inputError("%v", err)
		}
		// The destination is not a choice: --out-dir moves every other
		// projection and never this one, because the working directory is
		// where Spacelift looks for a custom metadata input.
		if err = spacelift.Write(".", body); err != nil {
			return inputError("%v", err)
		}
	}

	if plan.wants(formatSARIF) {
		if err := c.emit(cmd, plan, fileSARIF, sarifDoc); err != nil {
			return err
		}
	}

	if plan.dir != "" {
		return c.writePack(cmd, plan, run, receiptDoc, sarifDoc)
	}

	return nil
}

// writePack writes evidence-pack.zip into --out-dir: the pack of the release
// this run reports on, built from the same inputs as the other projections.
func (c *CLI) writePack(cmd *cobra.Command, plan outputPlan, run *runResult, receiptDoc, sarifDoc []byte) error {
	p, attachments, err := pack.Build(pack.Input{
		Modules:              run.modules,
		Catalog:              run.controls,
		CatalogVersion:       run.catalog,
		NotApplicableClauses: run.controls.NotApplicableClauses(),
		Findings:             run.findings,
		Tests:                run.tests,
		Metadata:             run.metadata,
		Root:                 run.root,
		Generator:            pack.Generator{Name: "ctfkit", Version: c.version},
		Receipt:              receiptDoc,
		SARIF:                sarifDoc,
	})
	if err != nil {
		return environmentError(err)
	}
	var zipped bytes.Buffer
	if err = pack.Write(&zipped, p, attachments); err != nil {
		return inputError("%v", err)
	}
	return c.emit(cmd, plan, pack.ZipName, zipped.Bytes())
}

// renderReportSARIF renders the run as SARIF from the same inputs scan hands
// the renderer: the rule descriptors of every family the run registers, the
// catalog version it read, and a ctf.catalog.stale notice when that catalog
// is older than the embedded release.
func renderReportSARIF(version string, opts *reportOptions, run *runResult) ([]byte, error) {
	in := sarif.Input{
		Tool:      sarif.Tool{Name: "ctfkit", Version: version},
		Rules:     reportRules(),
		Findings:  run.findings,
		Metadata:  run.metadata,
		Catalog:   run.catalog,
		Watermark: opts.watermark,
	}
	if stale := staleNotice(run.catalog); stale != "" {
		in.Notifications = []sarif.Notification{{
			DescriptorID: staleDescriptorID,
			Level:        ctfkit.LevelNote,
			Text:         staleText(stale),
		}}
	}

	doc, err := sarif.Render(in)
	if err != nil {
		return nil, categorized(categoryFinding, "%v", err)
	}
	return doc, nil
}

// writeMarkdown renders the Markdown section and puts it where the flags say:
// injected into the README, written to --out or --out-dir, or on stdout.
func (c *CLI) writeMarkdown(cmd *cobra.Command, plan outputPlan, opts *reportOptions, run *runResult) error {
	markers, err := parseMarkers(opts.markers)
	if err != nil {
		return err
	}

	var body strings.Builder
	renderErr := markdown.Render(&body, markdown.Input{
		Inventory:   run.record,
		Findings:    run.findings,
		Obligations: collectObligations(run.modules),
		Metadata:    run.metadata,
		Tests:       run.tests,
		Stage:       ctfkit.PostInit,
		Root:        run.root,
		Watermark:   opts.watermark,
		Markers:     markers,
	})
	if renderErr != nil {
		return inputError("%v", renderErr)
	}

	section := []byte(body.String())

	if opts.readme != "" {
		if err = injectReadme(opts.readme, section, markers); err != nil {
			return err
		}
		// --readme is a destination, not a redirection. A run that also named
		// --out or --out-dir asked for the file too, and writing only one of
		// the two would leave a caller collecting artifacts short by a
		// document with nothing on stderr to say so. With no other
		// destination the README is the whole answer, and stdout stays quiet.
		if plan.single == "" && plan.dir == "" {
			return nil
		}
	}

	return c.emit(cmd, plan, fileReport, section)
}

// injectReadme replaces the marked region of the README. A start marker with no
// end marker after it is an environment error: the command will not guess where
// the region the operator meant ends, and it never appends the section at the
// end of a file instead.
func injectReadme(path string, body []byte, markers markdown.Markers) error {
	// The mode is read before the rewrite and put back after it. A README is
	// a tracked source file somebody else owns; rewriting it at 0600 would
	// make it owner-only on the first run and show up as a permission change
	// in the next diff.
	info, err := os.Stat(path)
	if err != nil {
		return inputError("reading %s: %v", path, err)
	}

	current, err := os.ReadFile(path) // #nosec G304 -- the path is the operator's own --readme value
	if err != nil {
		return inputError("reading %s: %v", path, err)
	}

	merged, err := markdown.Inject(current, body, markers)
	if err != nil {
		return inputError("%s: %v", path, err)
	}

	if err = os.WriteFile(path, merged, info.Mode().Perm()); err != nil { // #nosec G306 G703 -- the file's own mode, preserved; the path is the operator's own --readme value
		return inputError("writing %s: %v", path, err)
	}

	return nil
}

// parseMarkers reads the --markers pair.
func parseMarkers(value string) (markdown.Markers, error) {
	if value == "" {
		return markdown.Markers{}, nil
	}

	start, end, ok := strings.Cut(value, ",")
	if !ok || start == "" || end == "" {
		return markdown.Markers{}, inputError("--markers takes START,END; got %q", value)
	}

	return markdown.Markers{Start: start, End: end}, nil
}

// emit writes one projection: to --out, into --out-dir under its fixed name, or
// to stdout when the run asked for a single document and named no destination.
func (c *CLI) emit(cmd *cobra.Command, plan outputPlan, name string, body []byte) error {
	switch {
	case plan.dir != "":
		if err := ensureOutDir(plan.dir); err != nil {
			return err
		}
		path := filepath.Join(plan.dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return inputError("writing %s: %v", path, err)
		}
		return nil

	case plan.single != "" && plan.single != "-":
		if err := os.WriteFile(plan.single, body, 0o600); err != nil {
			return inputError("writing %s: %v", plan.single, err)
		}
		return nil
	}

	return writeAll(cmd.OutOrStdout(), body)
}

// ensureOutDir creates --out-dir with its parents, as mkdir -p does, so a CI
// hook can name a directory such as .ctfkit without a separate step. report
// and scan both call it. 0755 because the directory holds artifacts a
// pipeline collects, not secrets; the files inside stay 0600. A path that
// exists and is not a directory is an input error.
func ensureOutDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: an artifact directory a pipeline reads, not a secret store
		return inputError("--out-dir %s: %v", dir, err)
	}
	return nil
}

// writeAll reports a short write as the error it is.
func writeAll(w io.Writer, body []byte) error {
	if _, err := w.Write(body); err != nil {
		return inputError("writing output: %v", err)
	}
	return nil
}

// collectObligations gathers the does-not-prove entries of every manifest read.
// The renderer keeps the first prose it sees for a token and never re-cases it,
// so the order here is the order modules.json lists, which is the producer's.
func collectObligations(modules *ctfkit.ModuleInventory) []ctfkit.ManifestObligation {
	var out []ctfkit.ManifestObligation
	for _, instance := range modules.Instances {
		if instance.Manifest == nil {
			continue
		}
		out = append(out, instance.Manifest.Scope.DoesNotProve...)
	}

	return out
}

// exitFor chooses the exit code of a completed run.
func exitFor(plan outputPlan, threshold string, findings ctfkit.Findings) error {
	// A format list of exactly spacelift returns 0 on a completed analysis
	// whatever --fail-on says: the plan policy is the gate there and it needs
	// the run to reach it in order to render the denial. Exit 2 still fails the
	// hook. Any list containing another format keeps the plain contract.
	if plan.spaceliftOnly() {
		return nil
	}

	if threshold == failOnNever {
		return nil
	}

	limit := failOnRank[threshold]
	count := 0
	for _, f := range findings {
		if f.Suppressed() {
			continue
		}
		// A level outside the frozen set counts at every threshold rather than
		// being skipped. Validate constrains Level at the emit boundary, so
		// this is unreachable today; if it ever becomes reachable, a finding
		// nobody can classify must not be a finding nobody exits on.
		rank, known := failOnRank[f.Level]
		if !known || rank <= limit {
			count++
		}
	}

	if count > 0 {
		return findingsError(count, threshold)
	}

	return nil
}
