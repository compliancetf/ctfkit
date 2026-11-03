// Command fixturepin is the Go half of scripts/record-report-fixtures.sh, the
// maintainer-only recorder of the report fixture pack. It is not part of the
// ctfkit release. Every subcommand is offline; the script runs tofu.
//
//	fixturepin host        <pin>              (prints registry_host)
//	fixturepin cases       <pin> <role>       (prints the case names of a role)
//	fixturepin authored    <live-input> <dest>
//	fixturepin validate    <case-dir> <registry-host>
//	fixturepin assemble    <case-dir> <tf-data-dir> <dest-input> <registry-host>
//	fixturepin synthesize  <report-dir> <pin>
//	fixturepin pin         <report-dir> <prev-pin> <registry-host> <tofu-version> <recorded-on>
//	fixturepin check       <report-dir>
//	fixturepin scan        <dir>              (literal from CTFKIT_SCAN_LITERAL)
//	fixturepin drift       <live-report-dir> <fresh-report-dir>
//
// Exit codes: 0 ok, 1 drift (drift only), 2 tooling error or pattern hit,
// 3 a literal token or a signed URL in the scanned tree.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/compliancetf/ctfkit/internal/fixturepin"
)

// scanLiteralEnv carries the token to look for. It is read from the
// environment, never argv, so it does not show in a process listing.
const scanLiteralEnv = "CTFKIT_SCAN_LITERAL"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// exitError carries an exit code other than 2.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func run(args []string, stdout, stderr io.Writer) int {
	err := dispatch(args, stdout)
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "fixturepin: %v\n", err)
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 2
}

func dispatch(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: fixturepin <host|cases|authored|validate|assemble|synthesize|pin|check|scan|drift> [args]")
	}
	say := func(v any) { _, _ = fmt.Fprintln(stdout, v) }
	need := func(n int) error {
		if len(args)-1 != n {
			return fmt.Errorf("%s takes %d arguments, got %d", args[0], n, len(args)-1)
		}
		return nil
	}
	a := args[1:]
	switch args[0] {
	case "host":
		if err := need(1); err != nil {
			return err
		}
		pin, _, err := fixturepin.ReadPin(a[0])
		if err != nil {
			return err
		}
		if !fixturepin.ValidHost(pin.RegistryHost) {
			return fmt.Errorf("registry_host %q is not a DNS name", pin.RegistryHost)
		}
		say(pin.RegistryHost)
		return nil
	case "cases":
		if err := need(2); err != nil {
			return err
		}
		pin, _, err := fixturepin.ReadPin(a[0])
		if err != nil {
			return err
		}
		names := make([]string, 0, len(pin.Cases))
		for name, c := range pin.Cases {
			if !fixturepin.ValidCaseName(name) {
				return fmt.Errorf("case name %q is not lower-case letters, digits and hyphens", name)
			}
			if c.Role == a[1] {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			say(name)
		}
		return nil
	case "authored":
		if err := need(2); err != nil {
			return err
		}
		files, err := fixturepin.ReadFiles(a[0])
		if err != nil {
			return err
		}
		for p := range files {
			if strings.HasPrefix(p, ".terraform/") {
				delete(files, p)
			}
		}
		return fixturepin.WriteFiles(a[1], files)
	case "validate":
		if err := need(2); err != nil {
			return err
		}
		return fixturepin.ValidateConfig(a[0], a[1])
	case "assemble":
		if err := need(4); err != nil {
			return err
		}
		return fixturepin.Assemble(a[0], a[1], a[2], a[3])
	case "synthesize":
		if err := need(2); err != nil {
			return err
		}
		pin, _, err := fixturepin.ReadPin(a[1])
		if err != nil {
			return err
		}
		return fixturepin.Synthesize(a[0], pin)
	case "pin":
		if err := need(5); err != nil {
			return err
		}
		return writePin(a[0], a[1], a[2], a[3], a[4])
	case "check":
		if err := need(1); err != nil {
			return err
		}
		if errs := fixturepin.Check(a[0]); len(errs) > 0 {
			for _, e := range errs {
				say(e)
			}
			return fmt.Errorf("%s: %d check failure(s)", a[0], len(errs))
		}
		return nil
	case "scan":
		if err := need(1); err != nil {
			return err
		}
		hits, err := fixturepin.Scan(a[0], []string{os.Getenv(scanLiteralEnv)})
		if err != nil {
			return err
		}
		for _, h := range hits {
			say(h)
		}
		if code := fixturepin.ScanExit(hits); code != 0 {
			return &exitError{code: code, msg: fmt.Sprintf("%s: %d scan hit(s)", a[0], len(hits))}
		}
		return nil
	case "drift":
		if err := need(2); err != nil {
			return err
		}
		lines, err := fixturepin.Drift(a[0], a[1])
		if err != nil {
			return err
		}
		for _, l := range lines {
			say(l)
		}
		if len(lines) > 0 {
			return &exitError{code: 1, msg: fmt.Sprintf("%d file(s) drifted", len(lines))}
		}
		return nil
	}
	return fmt.Errorf("unknown subcommand %q", args[0])
}

func writePin(reportDir, prevPin, host, tofuVersion, recordedOn string) error {
	prev, _, err := fixturepin.ReadPin(prevPin)
	if err != nil {
		return err
	}
	pin, err := fixturepin.BuildPin(reportDir, prev, host, tofuVersion, recordedOn)
	if err != nil {
		return err
	}
	raw, err := pin.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(reportDir, fixturepin.PinFile), raw, 0o644) //nolint:gosec // a committed fixture, read by everyone
}
