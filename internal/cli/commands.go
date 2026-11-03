package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/config"
)

// textFormats are the --format values of version and config validate; text
// and pretty print the same lines.
var textFormats = []string{formatText, formatPretty, formatJSON}

// textFormatUsage is the --format usage of version and config validate.
const textFormatUsage = "Output `FORMAT`: text, pretty or json"

func (c *CLI) versionCommand() *cobra.Command {
	format := formatText
	cmd := &cobra.Command{
		Use:     "version",
		Short:   "Print the version, commit, build date and platform",
		Example: "  ctfkit version -f json",
		Args:    noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := oneFormat(cmd, format, textFormats)
			if err != nil {
				return err
			}
			if f != formatJSON {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), c.versionText())
				return nil
			}
			commit, date := c.build()
			// The keys of the earlier output first, then the two it lacked.
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Version   string `json:"version"`
				Commit    string `json:"commit"`
				Date      string `json:"date"`
				GoVersion string `json:"go_version"`
				OS        string `json:"os"`
				Arch      string `json:"arch"`
			}{c.version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH})
		},
	}
	cmd.Flags().VarP(&onceString{target: &format}, "format", "f", textFormatUsage)
	return cmd
}

// versionText is what ctfkit version and ctfkit --version print.
func (c *CLI) versionText() string {
	commit, date := c.build()
	return fmt.Sprintf("ctfkit version %s\n  commit:   %s\n  built:    %s\n  go:       %s\n  platform: %s/%s\n",
		c.version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// unknownBuild stands in for a commit or build date nothing recorded.
const unknownBuild = "unknown"

// build is the commit and build date of this binary: what the release build
// stamped, else for the commit the VCS stamp go build records (with -dirty
// for a modified tree), else unknown.
func (c *CLI) build() (commit, date string) {
	commit, date = c.commit, c.date
	if date == "" {
		date = unknownBuild
	}
	if commit != "" {
		return commit, date
	}
	commit = unknownBuild
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return commit, date
	}
	dirty := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if dirty && commit != unknownBuild {
		commit += "-dirty"
	}
	return commit, date
}

func (c *CLI) configCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Create or check the .ctfkit.yaml settings file",
	}

	// Subcommand: config init
	var force bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter .ctfkit.yaml in the working directory",
		Long: `Write a starter .ctfkit.yaml in the working directory. Every value it sets is
what ctfkit uses with no settings file: allowed_endpoints is commented out,
fail_on is unset, and each key carries a comment. Offline: no network, no
credentials; it never runs terraform or tofu.

Refuses (exit 2, nothing written) when:
  - .ctfkit.yaml exists and --force is not given
  - --config is given: config init writes .ctfkit.yaml only

Exit codes:
  0  file written
  2  could not run, or refused

On exit 2: stderr names the cause. To replace an existing .ctfkit.yaml, run
again with --force. --force replaces the file in one step: a run that fails
leaves the existing .ctfkit.yaml as it was.

Details: docs/configuration.md`,
		Example: `  ctfkit config init
  ctfkit config init --force                # replace an existing .ctfkit.yaml`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if c.configPath != "" {
				return inputError("--config does not apply to config init, which writes .ctfkit.yaml in the working directory; drop --config")
			}
			err := config.GenerateDefault(config.FileName, force)
			if errors.Is(err, fs.ErrExist) {
				return inputError("%s already exists, nothing written; run ctfkit config init --force to replace it", config.FileName)
			}
			if err != nil {
				return environmentError(err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", config.FileName)
			return nil
		},
	}
	initCmd.Flags().VarPF(&onceBool{target: &force}, "force", "", "Replace an existing .ctfkit.yaml").NoOptDefVal = "true"
	cmd.AddCommand(initCmd)

	// Subcommand: config validate
	format := formatText
	validate := &cobra.Command{
		Use:   "validate [FILE]",
		Short: "Check a settings file and print what it sets",
		Long: `Check a settings file and print what it sets; -f json prints every key. It
reads FILE, else the file --config names, else .ctfkit.yaml in the working
directory. It writes to stdout only. Offline: no network, no credentials; it
never runs terraform or tofu.

Exit codes:
  0  the file is valid
  2  could not run, or refused

On exit 2: stderr names the cause, such as a missing file, the key that is not
valid, an unknown --format, or FILE and --config naming two different files;
stdout stays empty.

Details: docs/configuration.md`,
		Example: `  ctfkit config validate
  ctfkit config validate ci/ctfkit.yaml -f json`,
		Args: atMostOne("FILE"),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := oneFormat(cmd, format, textFormats)
			if err != nil {
				return err
			}
			path := config.FileName
			if c.configPath != "" {
				path = c.configPath
			}
			if len(args) == 1 {
				if c.configPath != "" && filepath.Clean(args[0]) != filepath.Clean(c.configPath) {
					return inputError("%s and --config %s name two different settings files; give one of them", args[0], c.configPath)
				}
				path = args[0]
			}
			cfg, err := config.Load(path)
			if err != nil {
				notFound := ""
				if len(args) == 0 && c.configPath == "" {
					notFound = "run ctfkit config init to write one, or name the file"
				}
				return settingsError(path, err, notFound)
			}

			if f == formatJSON {
				// Marshaling the struct rather than a map keeps the key order
				// stable: encoding/json emits struct fields in declaration order.
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				// An absent allowed_endpoints prints null, what the run uses,
				// not the list setDefaults filled in.
				out := *cfg
				if cfg.Settings().Endpoints == nil {
					out.AllowedEndpoints = nil
				}
				if err := enc.Encode(out); err != nil {
					return fmt.Errorf("failed to encode configuration: %w", err)
				}
				return nil
			}

			endpoints := "not set (any host ending in .compliance.tf)"
			if e := cfg.Settings().Endpoints; e != nil {
				endpoints = strings.Join(e, ", ")
			}
			failOn := cfg.FailOn
			if failOn == "" {
				failOn = "not set (error)"
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s is valid\n  allowed_endpoints: %s\n  fail_on:           %s\n",
				path, endpoints, failOn)
			return nil
		},
	}
	validate.Flags().VarP(&onceString{target: &format}, "format", "f", textFormatUsage)
	cmd.AddCommand(validate)

	return cmd
}
