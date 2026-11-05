// Package cli provides the command-line interface for ctfkit.
package cli

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/sign"
	"github.com/compliancetf/ctfkit/internal/sink"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The help lists commands in the order they are added, grouped, so the daily
// commands come first rather than alphabetically.
func init() { cobra.EnableCommandSorting = false }

// CLI represents the command-line interface for ctfkit.
type CLI struct {
	rootCmd *cobra.Command
	version string
	// commit and date are what the release build stamped; empty falls back
	// to the VCS stamp of go build (see build).
	commit, date string
	configPath   string
	verbose      bool
	noColor      bool
	// now is the run clock. Every command reads it instead of time.Now, so a
	// run over recorded input renders the same bytes on any day and a test can
	// freeze it without touching the process clock.
	now func() time.Time
	// keyring is the trust anchor gate plan and gate sign verify signed
	// inputs against, and openSigner opens a --signer URI; tests replace
	// both, no flag or env does.
	keyring    []byte
	openSigner func(uri string) (sign.Signer, error)
	// evidenceTime is Evidence API server time, read by ctfkit apply at
	// apply start under floor_mode online; tests replace it.
	evidenceTime func(ctx context.Context) (time.Time, error)
	// runtaskTransport is the base transport of runtask serve's outbound
	// calls; nil uses the adapter's own. Tests replace it to trust a test
	// server's certificate, no flag or env does.
	runtaskTransport http.RoundTripper
	// openS3 opens an evidence sink's S3 client and evidenceAPI is the
	// Evidence API run ingest, both for ctfkit evidence ship; tests replace
	// both.
	openS3      func(ctx context.Context, bucket string) (sink.S3API, error)
	evidenceAPI evidenceIngest
}

// New creates a new CLI instance
func New(version string) *CLI {
	cli := &CLI{
		version:    version,
		now:        time.Now,
		keyring:    releaseKeyring,
		openSigner: sign.Open,

		evidenceTime: noEvidenceAPI,
		openS3:       openS3,
		evidenceAPI:  noIngest{},
	}
	cli.setupCommands()
	cli.SetBuild("", "")
	return cli
}

// SetBuild records the commit and build date the release build stamped into
// main. Empty values fall back to the VCS stamp of go build, else unknown.
func (c *CLI) SetBuild(commit, date string) {
	c.commit, c.date = commit, date
	// --version prints the same text as ctfkit version.
	c.rootCmd.SetVersionTemplate(c.versionText())
}

// Command group ids of the root help, in the order the help lists them.
const (
	groupCheck    = "check"
	groupGoverned = "governed"
	groupRuntask  = "runtask"
	groupSetup    = "setup"
)

const rootLong = `ctfkit by compliance.tf checks Terraform and OpenTofu configurations and plans
and names the compliance.tf module that closes each finding. Results come out as
text, SARIF, JSON, JUnit, markdown or Spacelift metadata for the tools you
already run. scan, report, verify-lock and config are offline: no network, no
credentials, and they never run terraform or tofu.

"ctfkit PATH..." is short for "ctfkit scan --stage pre_plan PATH..." and exits
as scan does. With no PATH, ctfkit prints this help and exits 0.`

const rootExample = `  ctfkit scan ./infra                      # check .tf files before init
  ctfkit scan plan.json                    # check a plan: terraform show -json tfplan > plan.json
  ctfkit scan plan.json -f sarif --out findings.sarif
  ctfkit report                            # after terraform init
  ctfkit config init                       # write a starter .ctfkit.yaml`

// rootUsageLines replaces cobra's usage lines on the root help only: the root
// takes either a command or paths, and cobra would print "ctfkit [command]".
const (
	cobraUsageLines = "Usage:{{if .Runnable}}\n  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}\n  {{.CommandPath}} [command]{{end}}"
	// A command that only groups others runs unknownSubcommand; its usage
	// stays "CMD [command]", without a line of its own.
	rootUsageLines = "Usage:{{if .HasParent}}{{if and .Runnable (not .HasAvailableSubCommands)}}\n  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}\n  {{.CommandPath}} [command]{{end}}" +
		"{{else}}\n  ctfkit COMMAND [flags]\n  ctfkit PATH... [flags]{{end}}"
)

func (c *CLI) setupCommands() {
	// The bare command keeps its static scan of the paths given, through
	// scan and its exit contract; with no path it prints the help.
	rootOpts := &scanOptions{stage: string(ctfkit.PrePlan), format: formatPretty}
	c.rootCmd = &cobra.Command{
		Use:     "ctfkit",
		Short:   "Check Terraform and OpenTofu code for compliance.tf findings",
		Long:    rootLong,
		Example: rootExample,
		Version: c.version,
		// Without ArbitraryArgs cobra reads a path as an unknown subcommand.
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runRoot(cmd, args, rootOpts)
		},
		// main renders every diagnostic, in the one format the recorded
		// fixtures froze. Cobra printing its own copy first would put two
		// lines on stderr for one failure.
		SilenceErrors:              true,
		SilenceUsage:               true,
		SuggestionsMinimumDistance: 2,
	}
	c.rootCmd.SetUsageTemplate(strings.Replace(c.rootCmd.UsageTemplate(), cobraUsageLines, rootUsageLines, 1))
	c.rootCmd.SetFlagErrorFunc(flagError)

	// Global flags
	// Every global flag refuses a second use: with last-one-wins, an adapter
	// that pins --config could be overridden by a later --config.
	pf := c.rootCmd.PersistentFlags()
	pf.Var(&onceString{target: &c.configPath}, "config", "Settings `FILE` to read instead of discovering .ctfkit.yaml")
	pf.VarPF(&onceBool{target: &c.verbose}, "verbose", "v", "Verbose output").NoOptDefVal = "true"
	// Kept so scripts that pass it still run; no command reads it.
	_ = pf.MarkDeprecated("verbose", "it has no effect")
	pf.VarPF(&onceBool{target: &c.noColor}, "no-color", "", "Disable colored output").NoOptDefVal = "true"
	// After flag parsing, so --no-color takes effect and not only NO_COLOR.
	c.rootCmd.PersistentPreRun = func(*cobra.Command, []string) {
		if c.noColor || os.Getenv("NO_COLOR") != "" {
			color.NoColor = true
		}
	}
	// Local to the root, for "ctfkit PATH -f json"; each command that renders
	// output registers its own --format with the formats it accepts.
	c.rootCmd.Flags().VarP(&onceString{target: &rootOpts.format}, "format", "f", scanFormatUsage)

	c.rootCmd.AddGroup(
		&cobra.Group{ID: groupCheck, Title: "Check configurations and plans:"},
		&cobra.Group{ID: groupGoverned, Title: "Governed apply:"},
		&cobra.Group{ID: groupRuntask, Title: "Run tasks:"},
		&cobra.Group{ID: groupSetup, Title: "Settings and help:"},
	)
	for _, g := range []struct {
		id   string
		cmds []*cobra.Command
	}{
		{groupCheck, []*cobra.Command{c.scanCommand(), c.reportCommand(), c.verifyLockCommand()}},
		{groupGoverned, []*cobra.Command{c.gateCommand(), c.verdictCommand(), c.signedSetCommand(true), c.evidenceCommand()}},
		{groupRuntask, []*cobra.Command{c.runtaskCommand()}},
		{groupSetup, []*cobra.Command{c.configCommand(), c.versionCommand()}},
	} {
		for _, cmd := range g.cmds {
			cmd.GroupID = g.id
			c.rootCmd.AddCommand(cmd)
		}
	}
	c.rootCmd.SetHelpCommandGroupID(groupSetup)
	c.rootCmd.SetCompletionCommandGroupID(groupSetup)
	// Added here rather than at Execute so it lists before help, which
	// Execute always moves to the end.
	c.rootCmd.InitDefaultCompletionCmd()
	if completion, _, err := c.rootCmd.Find([]string{"completion"}); err == nil {
		completion.Short = "Print a shell completion script"
		completion.Long = "Print a shell completion script for bash, zsh, fish or powershell.\n" +
			"\"ctfkit completion SHELL --help\" says how to load it."
	}
	for _, cmd := range c.rootCmd.Commands() {
		groupsOnly(cmd)
	}
}

// groupsOnly gives every command under cmd that only groups others, cmd
// included, unknownSubcommand as its RunE.
func groupsOnly(cmd *cobra.Command) {
	if cmd.HasSubCommands() && !cmd.Runnable() {
		cmd.RunE = unknownSubcommand
	}
	for _, sub := range cmd.Commands() {
		groupsOnly(sub)
	}
}

// runRoot is the bare command: the help with no path, else
// "scan --stage pre_plan" over the paths. A path that does not exist and is a
// typo of a command name is refused with the command it was likely meant as.
func (c *CLI) runRoot(cmd *cobra.Command, args []string, opts *scanOptions) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	for _, arg := range args {
		if _, err := os.Stat(arg); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if name := typoOf(cmd, arg); name != "" {
			return inputError("no file or directory %q; did you mean \"ctfkit %s\"?", arg, name)
		}
	}
	return c.runScan(cmd, args, opts)
}

// typoOf is the command name within edit distance 2 of arg, or "".
// SuggestionsFor also offers every name arg is a prefix of; for those the
// edit distance is the length difference, so they are held to it too.
func typoOf(root *cobra.Command, arg string) string {
	for _, name := range root.SuggestionsFor(arg) {
		if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(arg)) || len(name)-len(arg) <= 2 {
			return name
		}
	}
	return ""
}

// Execute runs the CLI. Every error it returns has had URL userinfo stripped
// from its text: this is the one path every command's diagnostic takes on its
// way to stderr, so a credential in a flag value cannot reach a CI log however
// the command that failed quoted it.
func (c *CLI) Execute() error {
	return scrubUserinfo(c.rootCmd.Execute())
}

// scrubUserinfo returns err with URL userinfo stripped from its text, keeping
// the exit code and category the command chose.
//
// An *ExitError comes back as an *ExitError, a copy with its message
// stripped: the command layer returns the value and never a wrapper, and
// callers rely on that. Anything else is wrapped, with Unwrap, so errors.Is and
// errors.As still see through it.
func scrubUserinfo(err error) error {
	if err == nil {
		return nil
	}
	if exit, ok := err.(*ExitError); ok { //nolint:errorlint // the command layer returns the value, never a wrapper
		scrubbed := *exit
		scrubbed.Message = ctfkit.StripUserinfo(exit.Message)
		return &scrubbed
	}
	return scrubbedError{err: err}
}

// scrubbedError is an error whose text has had URL userinfo stripped.
type scrubbedError struct {
	err error
}

func (e scrubbedError) Error() string { return ctfkit.StripUserinfo(e.err.Error()) }

func (e scrubbedError) Unwrap() error { return e.err }
