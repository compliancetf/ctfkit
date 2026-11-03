package conformance

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Run context every recorded projection was rendered with (testdata/fixtures/README.md
// "Run context"). An adapter passes it as flags where its command line allows
// flags, and as the platform environment where it does not.
const (
	FixtureRunID   = "ctfkit-fixture-run"
	FixtureCommit  = "0000000000000000000000000000000000000000"
	FixtureVersion = "1.0.0"
)

// Family names a fixture pack.
const (
	FamilyPlan   = "plan"
	FamilyReport = "report"
)

// Case is one row of the fixture table: how the case runs and which parts of
// its recorded SARIF this build cannot reproduce.
type Case struct {
	// Name is the case directory.
	Name string
	// Stage is the stage the case runs at.
	Stage ctfkit.Stage
	// Argv is the scan specification's argv column, run from the input directory.
	// Report cases leave it empty: their command line is the adapter's.
	Argv []string
	// Exit is the exit code the case implies under the default --fail-on.
	// Report cases read theirs from expected/exit-code.
	Exit int
	// Catalog pins the catalog the case joins against, repository relative;
	// empty means the embedded release catalog.
	Catalog string
	// Deviation says why the recorded SARIF cannot be reproduced byte for
	// byte; Drop is what is removed from the recorded side before comparing,
	// so the rest is still asserted.
	Deviation string
	Drop      []*regexp.Regexp
}

// coverageCatalog is the catalog the report cases run with, pinned by path:
// the release catalog. Plan cases join the same catalog embedded in the binary.
const coverageCatalog = "internal/catalog/data/catalog.yaml"

var (
	scanPlan    = []string{"scan", "plan.json"}
	scanPrePlan = []string{"scan", "--stage", "pre_plan", "."}
)

// PlanCases is the plan fixture table of the scan specification ("Fixtures
// and acceptance"). 10 is the post_apply case the harness keeps: no adapter runs
// it, and `scan --stage post_apply` exiting 2 is its test.
var PlanCases = []Case{
	{Name: "01-raw-s3-no-ctf", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	{Name: "02-ctf-module-intact", Stage: ctfkit.PostPlan, Argv: scanPlan},
	{Name: "03-ctf-module-disabled-control", Stage: ctfkit.PrePlan, Argv: scanPrePlan, Exit: 1},
	{Name: "04-floating-ref", Stage: ctfkit.PrePlan, Argv: scanPrePlan},
	{Name: "05-mixed-origin", Stage: ctfkit.PrePlan, Argv: scanPrePlan, Exit: 1},
	{Name: "06-sentinel-exception", Stage: ctfkit.PostPlan, Argv: scanPlan},
	{Name: "07-expired-exception", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	// 08- and 16- exit 1 on the module_source error of their raw
	// aws_sqs_queue, not on the warning each is named for; see the fixtures
	// README, "Plan pack decisions".
	{Name: "08-missing-tags", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	{Name: "09-unknown-provider", Stage: ctfkit.PrePlan, Argv: scanPrePlan},
	{Name: "10-post-apply-state", Stage: ctfkit.PostApply, Argv: []string{"scan", "--stage", "post_apply", "plan.json"}, Exit: 2},
	{Name: "11-sensitive-public-exposure", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	{Name: "12-sensitive-wildcard-iam", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	{Name: "13-sensitive-audit-log-removal", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	{Name: "14-sensitive-encryption-disablement", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	{Name: "15-sensitive-destructive-stateful", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	{Name: "16-secret-canary", Stage: ctfkit.PostPlan, Argv: scanPlan, Exit: 1},
	// ctf.exec.provisioner and ctf.exec.external_data at pre_plan, over the
	// root and a local module of a configuration with no compliance.tf module.
	{Name: "17-exec-pre-plan", Stage: ctfkit.PrePlan, Argv: scanPrePlan, Exit: 1},
}

// ReportCases are the acceptance fixtures of the report specification, all at
// post_init against the coverage analyzer's fixture catalog.
var ReportCases = []Case{
	{Name: "served-leaf"},
	{Name: "blueprint-wrapper"},
	{Name: "example-multi-instance"},
	{Name: "degraded-build"},
	{Name: "missing-manifest"},
	{Name: "helper-module"},
	{Name: "delegated-with-sibling"},
	{Name: "delegated-without-sibling"},
	{Name: "supporting-clauses"},
	{Name: "schema-4-stub"},
}

// Fixture is a case resolved against a checkout: absolute paths and the
// recorded bytes.
type Fixture struct {
	Case
	// Family is FamilyPlan or FamilyReport.
	Family string
	// Root is the repository root, absolute.
	Root string
	// Input is the case's input directory, absolute.
	Input string
	// Want is expected/findings.sarif, nil when the case renders none.
	Want []byte
	// Stderr is expected/stderr.txt, the diagnostic of an exit-2 case, or nil.
	Stderr []byte
	// CatalogPath, ConfigPath and ExceptionsPath are the policy files the
	// case runs with, absolute; empty means none (the embedded catalog, no
	// settings file, no exception registry).
	CatalogPath, ConfigPath, ExceptionsPath string
	// TestsJSON is the imported test results the case reads, absolute, or
	// empty.
	TestsJSON string
}

// Fixtures loads every plan and report case under root/testdata/fixtures,
// and fails when a case directory has no table row or a row no directory.
func Fixtures(root string) ([]Fixture, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var out []Fixture
	for _, pack := range []struct {
		family string
		cases  []Case
	}{{FamilyPlan, PlanCases}, {FamilyReport, ReportCases}} {
		dir := filepath.Join(root, "testdata", "fixtures", pack.family)
		if namesErr := sameNames(dir, pack.cases); namesErr != nil {
			return nil, namesErr
		}
		for _, c := range pack.cases {
			f, resolveErr := resolve(root, pack.family, c)
			if resolveErr != nil {
				return nil, fmt.Errorf("fixture %s/%s: %w", pack.family, c.Name, resolveErr)
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// sameNames fails when the case table and the directory listing disagree.
func sameNames(dir string, cases []Case) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	rows := map[string]bool{}
	for _, c := range cases {
		rows[c.Name] = true
	}
	for _, e := range entries {
		if e.IsDir() && !rows[e.Name()] {
			return fmt.Errorf("%s/%s has no row in the conformance case table", dir, e.Name())
		}
		delete(rows, e.Name())
	}
	for name := range rows {
		return fmt.Errorf("case %s has no directory under %s", name, dir)
	}
	return nil
}

func resolve(root, family string, c Case) (Fixture, error) {
	caseDir := filepath.Join(root, "testdata", "fixtures", family, c.Name)
	f := Fixture{Case: c, Family: family, Root: root, Input: filepath.Join(caseDir, "input")}

	want, err := os.ReadFile(filepath.Join(caseDir, "expected", "findings.sarif")) //nolint:gosec // a fixture path
	switch {
	case err == nil:
		f.Want = want
	case !errors.Is(err, os.ErrNotExist):
		return f, err
	}

	if f.Stderr, err = os.ReadFile(filepath.Join(caseDir, "expected", "stderr.txt")); err != nil && //nolint:gosec // a fixture path
		!errors.Is(err, os.ErrNotExist) {
		return f, err
	}

	if family == FamilyReport {
		f.Stage = ctfkit.PostInit
		f.Catalog = coverageCatalog
		raw, readErr := os.ReadFile(filepath.Join(caseDir, "expected", "exit-code")) //nolint:gosec // a fixture path
		if readErr != nil {
			return f, readErr
		}
		if f.Exit, err = strconv.Atoi(strings.TrimSpace(string(raw))); err != nil {
			return f, fmt.Errorf("expected/exit-code: %w", err)
		}
		f.TestsJSON = existing(filepath.Join(f.Input, "tests.json"))
	}

	if c.Catalog != "" || family == FamilyReport {
		f.CatalogPath = filepath.Join(root, f.Catalog)
	}
	f.ConfigPath = existing(filepath.Join(f.Input, ".ctfkit.yaml"))
	f.ExceptionsPath = existing(filepath.Join(f.Input, ".ctf-exceptions.yaml"))
	return f, nil
}

func existing(path string) string {
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

// CatalogVersionBlock is the run-level ctf.catalogVersion object. Every run
// object carries it now; the recorded plan SARIF predates it, so the
// normalizer removes it. The CLI tests assert its presence separately. When it
// is the bag's only key, the whole run property bag goes with it; after a
// --watermark banner, only the block itself.
var CatalogVersionBlock = regexp.MustCompile(`\n      "properties": \{\n        "ctf\.catalogVersion": \{\n[^}]*\n        \}\n      \},|,\n        "ctf\.catalogVersion": \{\n[^}]*\n        \}`)

// InvocationsBlock is the run-level invocations array that carries a
// ctf.catalog.stale notification. A case pinned to its analyzer's test catalog
// runs on a catalog older than the embedded release, so the notice is right
// there, but the recorded SARIF predates run-level notifications. The CLI
// tests assert its presence separately.
var InvocationsBlock = regexp.MustCompile(`(?s)\n      "invocations": \[\n.*?\n      \],`)

// runContext matches the run-context values of ctf.evidence.
var runContext = regexp.MustCompile(`("(?:runId|commit)": )"[^"]*"`)

// ttlSeconds matches the remaining life of a waiver in ctf.exception, which
// is counted from the run clock: the recorded value is at the fixture clock,
// a built binary runs at the wall clock.
var ttlSeconds = regexp.MustCompile(`("ttlSeconds": )[0-9]+`)

// Normalize removes what differs between two runs of the same analysis on
// different platforms: the ctf.catalogVersion block, the run id and commit
// in ctf.evidence, a waiver's ttlSeconds, and the stale-catalog invocations
// block. Everything else is compared as rendered.
func Normalize(doc []byte) []byte {
	doc = InvocationsBlock.ReplaceAll(CatalogVersionBlock.ReplaceAll(doc, nil), nil)
	doc = ttlSeconds.ReplaceAll(doc, []byte(`${1}0`))
	return runContext.ReplaceAll(doc, []byte(`$1"<run context>"`))
}

// Recorded is the fixture's expected SARIF with its known deviations dropped.
// It fails when a deviation no longer matches the recorded file, so a
// re-recorded fixture cannot leave a stale row behind.
func (f Fixture) Recorded() ([]byte, error) {
	want := f.Want
	for _, drop := range f.Drop {
		trimmed := drop.ReplaceAll(want, nil)
		if bytes.Equal(trimmed, want) {
			return nil, fmt.Errorf("%s: a known deviation no longer matches the recorded file; remove it: %s", f.Name, f.Deviation)
		}
		want = trimmed
	}
	return want, nil
}
