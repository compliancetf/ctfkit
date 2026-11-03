package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/config"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Formats scan renders, beside sarif and spacelift from report.go.
const (
	formatJSON   = "json"
	formatText   = "text"
	formatPretty = "pretty"
	formatJUnit  = "junit"
)

// scanFormats is the --format list of scan, in the order the help text names
// it.
var scanFormats = []string{formatSARIF, formatJSON, formatText, formatPretty, formatJUnit, formatSpacelift}

// scanFileNames are the names --out-dir writes, the report convention
// findings.<ext>. The Spacelift file is not among them: it always lands in the
// working directory.
var scanFileNames = map[string]string{
	formatSARIF:  "findings.sarif",
	formatJSON:   "findings.json",
	formatText:   "findings.txt",
	formatPretty: "findings.pretty.txt",
	formatJUnit:  "findings.junit.xml",
}

// Stage words --stage accepts. Every other word, post_init included, is exit 2.
const stageAuto = "auto"

// configSuffixes are the file names scan reads as configuration. A positional
// argument with one of them is a pre_plan file list entry; they are checked
// before the plain .json plan rule so that main.tf.json is configuration.
var configSuffixes = []string{".tf", ".tf.json", ".tofu", ".tofu.json"}

// scanOptions are the flags of one scan invocation. Every string flag is a
// onceString, so repeating a flag is exit 2 rather than last-one-wins.
type scanOptions struct {
	plan            string
	chdir           string
	stage           string
	catalog         string
	exceptions      string
	remediationHost string
	out             string
	outDir          string
	failOn          string
	runID           string
	commit          string
	platform        string
	watermark       string
	format          string
}

// scanFormatUsage is the --format usage of scan and of the bare command.
var scanFormatUsage = "Comma-separated `LIST` of formats: " + strings.Join(scanFormats, ", ")

// Flag usage shared by scan, report and verify-lock. The backticked word is
// the value placeholder the help prints.
const (
	catalogUsage = "Control catalog `FILE` (YAML), or embedded for the catalog built into this release " +
		"(default: ~/.ctf/control-requirements.yaml when present, else embedded)"
	failOnUsage   = "Exit 1 at or above this `LEVEL`: error (default), warning, note or never"
	outUsage      = "Output `FILE` for exactly one format; \"-\" is stdout"
	runIDUsage    = "Run `ID` (default: detected from the CI environment)"
	commitUsage   = "Commit `SHA` (default: detected from the CI environment)"
	platformUsage = "Platform `NAME` (default: detected from the CI environment)"
	bannerUsage   = "Banner `TEXT` added to every output"
)

const scanLong = `Check a Terraform or OpenTofu configuration (pre_plan) or its plan JSON
(post_plan) for compliance.tf findings. It reads .tf, .tf.json, .tofu and
.tofu.json files or a plan from terraform show -json or tofu show -json, plus
.ctfkit.yaml and .ctf-exceptions.yaml in the configuration directory. It writes
findings to stdout, --out or --out-dir; Spacelift metadata always goes to
ctfkit-scan.custom.spacelift.json in the working directory. Offline: no network,
no credentials; it never runs terraform or tofu.

A directory argument is the configuration directory, configuration files are a
pre_plan file list, and any other .json file is the plan. --stage auto picks
post_plan when a plan is given, else pre_plan.

Exit codes:
  0  no unsuppressed finding at or above --fail-on
  1  unsuppressed findings at or above --fail-on
  2  could not run, or refused

With --format spacelift alone, a completed run exits 0 whatever it finds: the
Spacelift plan policy reads the metadata file and decides.

On exit 2: stderr names the cause; do not use the output files of this run. Fix
the cause and run again.

Details: docs/commands.md`

const scanExample = `  ctfkit scan ./infra                                   # pre_plan, no init or credentials
  ctfkit scan --stage pre_plan main.tf vpc.tf           # a file list, as the pre-commit hook passes
  ctfkit scan plan.json                                 # post_plan
  ctfkit scan --plan out/plan.json --chdir ./infra      # anchor findings to ./infra
  ctfkit scan plan.json -f sarif,json,junit --out-dir out/
  ctfkit scan plan.json -f json --fail-on never > findings.json   # for OPA`

// scanCommand builds `ctfkit scan`.
func (c *CLI) scanCommand() *cobra.Command {
	opts := &scanOptions{format: formatPretty}

	cmd := &cobra.Command{
		Use:     "scan [flags] [DIR | PLAN.json | FILE.tf ...]",
		Short:   "Check a configuration (pre_plan) or a plan JSON (post_plan)",
		Long:    scanLong,
		Example: scanExample,
		// validate was a hidden alias of scan --stage pre_plan; the bare
		// command points its old callers here.
		SuggestFor: []string{"validate"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runScan(cmd, args, opts)
		},
	}

	f := cmd.Flags()
	once := func(p *string, name, usage string) { f.Var(&onceString{target: p}, name, usage) }
	f.VarP(&onceString{target: &opts.format}, "format", "f", scanFormatUsage)
	once(&opts.plan, "plan", "Plan JSON `FILE` from terraform show -json or tofu show -json; a positional .json file means the same")
	once(&opts.chdir, "chdir", "Configuration `DIR` (default \".\"); a directory argument means the same")
	once(&opts.stage, "stage", "Analysis `STAGE`: auto (default), pre_plan or post_plan")
	once(&opts.catalog, "catalog", catalogUsage)
	once(&opts.exceptions, "exceptions", "Exception registry `FILE` (default: .ctf-exceptions.yaml in the configuration directory)")
	once(&opts.remediationHost, "remediation-host", "Framework `ID` whose host the fix names (default: the catalog default, soc_2 in the embedded catalog)")
	once(&opts.out, "out", outUsage)
	once(&opts.outDir, "out-dir", "Output `DIR` for findings.sarif, findings.json, findings.txt, findings.pretty.txt, findings.junit.xml")
	once(&opts.failOn, "fail-on", failOnUsage)
	once(&opts.runID, "run-id", runIDUsage)
	once(&opts.commit, "commit", commitUsage)
	once(&opts.platform, "platform", platformUsage)
	once(&opts.watermark, "watermark", bannerUsage)

	return cmd
}

// onceString is a string flag that refuses a second value.
type onceString struct {
	target *string
	set    bool
}

func (o *onceString) Set(v string) error {
	if o.set {
		return errGivenTwice
	}
	if v == "" {
		// An empty value would read as "not given" and fall through to a
		// default or a policy file, which is a different run than asked for.
		return errEmptyValue
	}
	o.set = true
	*o.target = v
	return nil
}

func (o *onceString) String() string {
	if o.target == nil {
		return ""
	}
	return *o.target
}

func (o *onceString) Type() string { return "string" }

// onceBool is a boolean flag that refuses a second use. Register it with
// VarPF and NoOptDefVal "true", or a bare --flag demands a value.
type onceBool struct {
	target *bool
	set    bool
}

func (o *onceBool) Set(v string) error {
	if o.set {
		return errGivenTwice
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return err
	}
	o.set = true
	*o.target = b
	return nil
}

func (o *onceBool) String() string {
	if o.target == nil {
		return "false"
	}
	return strconv.FormatBool(*o.target)
}

func (o *onceBool) Type() string { return "bool" }

// scanInputs is what the positionals and path flags resolved to.
type scanInputs struct {
	// dir is the configuration directory, empty when none was named.
	dir string
	// files is the explicit pre_plan file list.
	files []string
	// plan is the plan JSON path, empty when none was named.
	plan string
	// stage is the stage this run analyzes at.
	stage ctfkit.Stage
}

// root is the discovery root of .ctfkit.yaml and .ctf-exceptions.yaml: the
// configuration directory when one was named, else the working directory.
func (in scanInputs) root() string {
	if in.dir != "" {
		return in.dir
	}
	return "."
}

// noteConfigDir prints one stderr line naming the configuration directory when
// the operator named none, so a scan from an unexpected working directory is
// visible: the working directory is walked recursively, and a plan's findings
// depend on the configuration found there. A named directory or an explicit
// file list prints nothing. stdout is untouched, so no projection changes.
func noteConfigDir(cmd *cobra.Command, in scanInputs) {
	if in.dir != "" || len(in.files) > 0 {
		return
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = in.root()
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"ctfkit: configuration directory %s (the working directory; name another with --chdir)\n",
		ctfkit.StripUserinfo(dir))
}

// noteUnpacked prints one stderr line naming the providers of the plan's
// changed resources that no rule pack describes. The sensitive-change rules
// have nothing to say about those resources, and a reader should not take
// that silence for a clean result. It prints one more line for each provider
// whose lock file major has no pack, naming the pack used instead, since
// attribute names differ between majors. stdout is untouched, so no
// projection changes.
func noteUnpacked(cmd *cobra.Command, plan *tfjson.Plan, archive *ctfkit.ConfigArchive) {
	packs := rulepack.Embedded()
	if unpacked := packs.Unpacked(plan); len(unpacked) > 0 {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"ctfkit: no rule pack for %s; the sensitive-change rules do not check their resources\n",
			ctfkit.StripUserinfo(strings.Join(unpacked, ", ")))
	}
	var lock *ctfkit.Lockfile
	if archive != nil {
		lock = archive.Lockfile
	}
	for _, line := range packs.Fallbacks(plan, lock) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ctfkit: %s\n", ctfkit.StripUserinfo(line))
	}
}

// runScan is the whole pipeline: resolve the inputs, flags and policy files,
// load the configuration and the plan, run the stage's analyzers, render every
// requested projection, and choose the exit code.
func (c *CLI) runScan(cmd *cobra.Command, args []string, opts *scanOptions) error {
	err := c.scan(cmd, args, opts)
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		// Every diagnostic passes the userinfo strip: a path or a source the
		// operator typed may carry a credential.
		exitErr.Message = ctfkit.StripUserinfo(exitErr.Message)
	}
	return err
}

func (c *CLI) scan(cmd *cobra.Command, args []string, opts *scanOptions) error {
	formats, err := parseFormats(opts.format, scanFormats)
	if err != nil {
		return err
	}
	plan := outputPlan{formats: formats, single: opts.out, dir: opts.outDir}
	if err = checkDestinations(plan); err != nil {
		return err
	}

	in, err := resolveScanInputs(args, opts)
	if err != nil {
		return err
	}
	if opts.stage == string(ctfkit.PrePlan) && in.plan != "" && in.stage == ctfkit.PrePlan {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ctfkit: --stage pre_plan ignores the plan %s\n", ctfkit.StripUserinfo(in.plan))
		in.plan = ""
	}

	settings, err := c.loadSettings(in.root())
	if err != nil {
		return err
	}
	threshold, err := resolveFailOn(opts.failOn, func() (*config.Config, error) { return settings, nil })
	if err != nil {
		return err
	}

	cat, version, err := catalog.Resolve(opts.catalog)
	if err != nil {
		return fileError("catalog file ", err, catalogNotFound)
	}
	frameworks, err := remediationFrameworks(cat, opts.remediationHost)
	if err != nil {
		return err
	}
	stale := staleNotice(version)
	if stale != "" {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ctfkit: %s\n", stale)
	}

	registry, err := loadExceptions(opts.exceptions, in.root())
	if err != nil {
		return err
	}

	archive, err := loadScanConfig(in)
	if err != nil {
		return err
	}
	// The ctf.lock rules run in a pre_plan directory scan when the settings
	// name wrapped providers; a file list reads no lock files.
	if in.stage == ctfkit.PrePlan && archive.ClassifyModules && len(settings.WrappedProviders) > 0 {
		if archive.Lockfiles, err = rootLockfiles(archive); err != nil {
			return err
		}
	}

	var planJSON *tfjson.Plan
	if in.stage == ctfkit.PostPlan {
		if planJSON, err = loader.LoadPlan(in.plan); err != nil {
			return environmentError(err)
		}
		noteUnpacked(cmd, planJSON, archive)
	}

	metadata := loader.DetectRunMetadata(os.Getenv, c.now(), loader.RunFlags{
		RunID:    opts.runID,
		Commit:   opts.commit,
		Platform: opts.platform,
	})
	if frameworks != nil {
		metadata.Frameworks = frameworks
	}

	input := ctfkit.AnalyzerInput{
		Stage:    in.stage,
		Config:   archive,
		PlanJSON: planJSON,
		Catalog:  cat,
		Settings: settings.Settings(),
		Metadata: metadata,
	}

	findings, err := runAnalyzers(cmd.Context(), newScanRegistry(), input, registry, cat, metadata.Now)
	if err != nil {
		return err
	}
	ctfkit.SortFindings(findings)

	run := scanRun{
		stage:     in.stage,
		findings:  findings,
		metadata:  metadata,
		catalog:   version,
		watermark: ctfkit.StripUserinfo(cleanWatermark(opts.watermark)),
		stale:     stale,
		version:   c.version,
	}
	if err = c.writeScan(cmd, plan, run); err != nil {
		return err
	}
	// Only once the run has succeeded: a run that ends in exit 2 writes its one
	// error line and nothing else.
	noteConfigDir(cmd, in)

	return exitFor(plan, threshold, findings)
}

// newScanRegistry builds the analyzer registry of a run. It is a variable so a
// test can substitute an analyzer that fails.
var newScanRegistry = scanAnalyzers

// resolveScanInputs applies the positional grammar and the stage rule. Every
// rejection is an input error.
func resolveScanInputs(args []string, opts *scanOptions) (scanInputs, error) {
	var dirs, files, plans []string
	for _, arg := range args {
		info, statErr := os.Stat(arg)
		switch {
		case statErr == nil && info.IsDir():
			dirs = append(dirs, arg)
		case hasConfigSuffix(arg):
			files = append(files, arg)
		case strings.HasSuffix(arg, ".json"):
			plans = append(plans, arg)
		case statErr != nil:
			return scanInputs{}, cannotRead("", arg, statErr, "pass a directory, configuration files or a plan .json file")
		default:
			return scanInputs{}, inputError(
				"%s is not a directory, a configuration file (.tf, .tf.json, .tofu, .tofu.json) or a plan .json file", arg)
		}
	}

	if opts.plan != "" {
		plans = append(plans, opts.plan)
	}

	switch {
	case len(dirs) > 1:
		return scanInputs{}, inputError("more than one configuration directory given (%s); scan one per run", strings.Join(dirs, ", "))
	case len(plans) > 1:
		return scanInputs{}, inputError("two plan files given: %s and %s", plans[0], plans[1])
	case opts.chdir != "" && len(dirs) > 0:
		return scanInputs{}, inputError("--chdir and a directory argument both name the configuration directory")
	case len(files) > 0 && (opts.chdir != "" || len(dirs) > 0):
		return scanInputs{}, inputError("a file list is the configuration input and cannot be combined with a directory")
	case len(files) > 0 && len(plans) > 0:
		return scanInputs{}, inputError("a plan file cannot be combined with a configuration file list")
	}

	in := scanInputs{files: files, dir: opts.chdir}
	if len(dirs) == 1 {
		in.dir = dirs[0]
	}
	if len(plans) == 1 {
		in.plan = plans[0]
	}

	switch opts.stage {
	case "", stageAuto:
		in.stage = ctfkit.PrePlan
		if in.plan != "" {
			in.stage = ctfkit.PostPlan
		}
	case string(ctfkit.PrePlan):
		in.stage = ctfkit.PrePlan
	case string(ctfkit.PostPlan):
		if in.plan == "" {
			return scanInputs{}, inputError("--stage post_plan needs a plan; pass --plan FILE or a .json file from terraform show -json (or tofu show -json)")
		}
		in.stage = ctfkit.PostPlan
	case string(ctfkit.PostInit):
		return scanInputs{}, inputError("--stage post_init is not a scan stage; after terraform init (or tofu init), run ctfkit report")
	default:
		return scanInputs{}, inputError("unknown --stage %q; supported: auto, pre_plan, post_plan", opts.stage)
	}

	return in, nil
}

// hasConfigSuffix reports whether name is a configuration file by its suffix.
func hasConfigSuffix(name string) bool {
	for _, s := range configSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// loadScanConfig reads the configuration the stage needs and parses every file
// once, so that a syntax error is an input error before any analyzer runs
// rather than an analyzer error, or worse, a file an analyzer silently skips.
//
// pre_plan needs configuration: an explicit file list, else the configuration
// directory, and a directory holding no configuration file is exit 2.
// post_plan reads the configuration directory when it exists, only to anchor
// findings to file and line; a missing one is not an error.
func loadScanConfig(in scanInputs) (*ctfkit.ConfigArchive, error) {
	var archive *ctfkit.ConfigArchive
	switch {
	case len(in.files) > 0:
		a, err := readFileList(in.files)
		if err != nil {
			return nil, err
		}
		archive = a

	case in.stage == ctfkit.PostPlan:
		if _, err := os.Stat(in.root()); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		fallthrough

	default:
		a, err := loader.LoadConfig(in.root())
		if err != nil {
			return nil, environmentError(err)
		}
		// A whole tree mixes deployable roots with the reusable modules they
		// call; a file list is taken as the operator named it.
		a.ClassifyModules = true
		archive = a
	}

	if in.stage == ctfkit.PrePlan && len(archive.Files) == 0 {
		return nil, inputError("no configuration files (.tf, .tf.json, .tofu, .tofu.json) in %s; pass the directory that holds them", in.root())
	}

	if err := parseConfig(archive); err != nil {
		return nil, err
	}

	// A directory scan at pre_plan also reads the ./ and ../ local modules
	// the configuration calls outside its root, for the ctf.exec rules; a file
	// list is read as the operator named it.
	if in.stage == ctfkit.PrePlan && archive.ClassifyModules {
		modules, calls, err := loader.LoadLocalModules(archive.Root, archive.Files)
		if err != nil {
			return nil, environmentError(err)
		}
		archive.LocalModules, archive.LocalCalls = modules, calls
	}

	return archive, nil
}

// readFileList builds the archive of an explicit file list. Paths are relative
// to the process working directory, as the pre-commit hook passes them, and
// are recorded as given so that findings point at the file the hook named.
func readFileList(files []string) (*ctfkit.ConfigArchive, error) {
	archive := &ctfkit.ConfigArchive{Root: ".", Partial: true}
	for _, name := range files {
		body, err := os.ReadFile(name) // #nosec G304 -- the operator's own file list
		if err != nil {
			return nil, cannotRead("", name, err, "pass a directory, configuration files or a plan .json file")
		}
		archive.Files = append(archive.Files, ctfkit.ConfigFile{Path: filepath.ToSlash(name), Bytes: body})
	}
	return archive, nil
}

// parseConfig parses every configuration file and reports the first syntax
// error. The diagnostic names the file, the line and the parser's summary,
// never its detail: the detail can quote the source, and a source line can
// hold a secret.
func parseConfig(archive *ctfkit.ConfigArchive) error {
	parser := hclparse.NewParser()
	for _, file := range archive.Files {
		var diags hcl.Diagnostics
		if strings.HasSuffix(file.Path, ".json") {
			_, diags = parser.ParseJSON(file.Bytes, file.Path)
		} else {
			_, diags = parser.ParseHCL(file.Bytes, file.Path)
		}
		for _, d := range diags {
			if d.Severity != hcl.DiagError {
				continue
			}
			line := ""
			if d.Subject != nil {
				line = ":" + strconv.Itoa(d.Subject.Start.Line)
			}
			return inputError("%s%s: %s", file.Path, line, d.Summary)
		}
	}
	return nil
}

// remediationFrameworks resolves --remediation-host into the frameworks the
// analyzers read the remediation host from. Empty means the catalog's
// defaultHost.
func remediationFrameworks(cat ctfkit.ControlCatalog, flag string) ([]string, error) {
	if flag == "" {
		return nil, nil
	}
	id := strings.ToLower(flag)
	hosts := cat.Hosts()
	if _, ok := hosts[id]; !ok {
		known := make([]string, 0, len(hosts))
		for k := range hosts {
			known = append(known, k)
		}
		sort.Strings(known)
		return nil, inputError("--remediation-host %q is not a framework id of the catalog; supported: %s",
			flag, strings.Join(known, ", "))
	}
	return []string{id}, nil
}

// staleDescriptorID names the ctf.catalog.stale notice: the prefix of its
// stderr line and the descriptor id of its SARIF notification.
const staleDescriptorID = "ctf.catalog.stale"

// staleNotice is the ctf.catalog.stale notification: a catalog file older than
// the release embedded in this binary may point at a withdrawn module. It is
// never a finding and never changes the exit code. The returned line carries
// the id as a prefix, for stderr, text and pretty; staleText drops it for a
// projection that records the id in a field of its own.
func staleNotice(v ctfkit.CatalogVersion) string {
	embedded := catalog.Embedded().Version().Version
	if v.Provenance == "embedded" || !semverLess(v.Version, embedded) {
		return ""
	}
	return fmt.Sprintf("%s: catalog %s (%s) is older than the embedded release %s",
		staleDescriptorID, v.Version, v.Provenance, embedded)
}

// staleText is the stale notice without its id prefix.
func staleText(notice string) string {
	return strings.TrimPrefix(notice, staleDescriptorID+": ")
}

// semverLess compares major.minor.patch numerically. The catalog loader has
// already refused a version that is not semver; a pre-release sorts before its
// release, and pre-release identifiers are not compared further.
func semverLess(a, b string) bool {
	pa, preA := splitSemver(a)
	pb, preB := splitSemver(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return preA && !preB
}

func splitSemver(v string) ([3]int, bool) {
	v, _, _ = strings.Cut(v, "+")
	core, pre, hasPre := strings.Cut(v, "-")
	var out [3]int
	for i, part := range strings.SplitN(core, ".", 3) {
		out[i], _ = strconv.Atoi(part)
	}
	return out, hasPre && pre != ""
}

// ansiPattern matches CSI escape sequences.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// cleanWatermark keeps --watermark to one printable line: escape sequences and
// control characters, newlines included, are removed.
func cleanWatermark(s string) string {
	s = ansiPattern.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
