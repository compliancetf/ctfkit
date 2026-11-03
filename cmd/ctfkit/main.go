// Package main provides the entry point for the ctfkit CLI tool.
package main

import (
	"fmt"
	"os"

	"github.com/compliancetf/ctfkit/internal/cli"
)

// version, commit and date are set via ldflags by the release build
// (.goreleaser.yml); make build sets only version.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// main is the one place in ctfkit that ends the process. Commands return an
// error that names the exit code it asks for; nothing else calls os.Exit, so a
// command can be run in process by a test and a renderer cannot end a run
// halfway through writing a document.
//
// The mapping is the 0/1/2 contract: 0 is a clean run, 1 is a completed run
// whose findings reached the threshold, and 2 is everything that stopped the
// run before it could judge the configuration. An error that names no code is
// an environment error, which is the fix for the earlier behavior of reporting
// a missing file or an unparseable flag as though the configuration had failed.
func main() {
	app := cli.New(version)
	app.SetBuild(commit, date)

	err := app.Execute()
	code := cli.ExitCode(err)
	if code == cli.ExitOK {
		return
	}

	// The diagnostic is one line, prefixed with the program name and nothing
	// else: the recorded fixture stderr is compared byte for byte. An error
	// with no message has already said what it had to say in the projections
	// it wrote.
	if msg := err.Error(); msg != "" {
		fmt.Fprintf(os.Stderr, "ctfkit: %s\n", msg)
	}

	os.Exit(code)
}
