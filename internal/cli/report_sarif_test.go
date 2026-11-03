package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// report --format sarif renders the same run the other projections do. The
// recorded expected/findings.sarif of every report case is the oracle, byte
// for byte, ctf.catalogVersion included: the cases run on the embedded
// release catalog, which is never stale, so no invocations block is rendered.
func TestReportSARIFParity(t *testing.T) {
	t.Chdir(goldenRoot(t))

	for _, name := range recordedCases(t) {
		want := filepath.Join("testdata/fixtures/report", name, "expected", "findings.sarif")
		if !rerecording() && !exists(want) {
			continue // schema-4-stub stops before it renders anything
		}

		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "findings.sarif")
			args := append([]string{
				"--path", fixturePath(name),
				"--format", "sarif",
				"--out", out,
			}, fixtureContext...)
			if testsJSON := filepath.Join(fixturePath(name), "tests.json"); exists(testsJSON) {
				args = append(args, "--tests-json", testsJSON)
			}

			if _, code := runReport(t, args...); code == ExitEnvironment {
				if rerecording() {
					return // an exit-2 case renders no projection
				}
				t.Fatalf("report --format sarif exited 2")
			}

			// CTFKIT_RERECORD=1 writes the run over the recorded file, the
			// switch that also re-records the plan pack
			// (testdata/fixtures/README.md "Regenerating").
			if rerecording() {
				writeExpected(t, name, "findings.sarif", readFile(t, out))
			}
			assertSameBytes(t, name+"/expected/findings.sarif", readFile(t, want), readFile(t, out))
		})
	}
}

// --out-dir creates its directory, parents included, the way mkdir -p does, so
// a CI hook can name .ctfkit without a separate step. It is 0755: the
// directory holds artifacts a pipeline collects, not secrets.
func TestReportOutDirIsCreated(t *testing.T) {
	t.Chdir(repoRoot)

	dir := filepath.Join(t.TempDir(), "a", "b", ".ctfkit")
	args := append([]string{
		"--path", fixturePath("served-leaf"),
		"--format", "markdown,receipt,sarif",
		"--out-dir", dir,
	}, fixtureContext...)

	if _, code := runReport(t, args...); code == ExitEnvironment {
		t.Fatalf("report --out-dir %s exited 2", dir)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("--out-dir was not created: %v", err)
	}
	// The mode a directory created with 0755 gets under this process's umask,
	// so the comparison holds on a machine whose umask is not 022.
	reference := filepath.Join(t.TempDir(), "reference")
	if err = os.MkdirAll(reference, 0o755); err != nil { //nolint:gosec // G301: the reference mode under test
		t.Fatal(err)
	}
	refInfo, err := os.Stat(reference)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), refInfo.Mode().Perm(); got != want {
		t.Errorf("--out-dir mode = %v, want %v (0755 under this umask)", got, want)
	}
	for _, f := range []string{"report.md", "receipt.json", "findings.sarif"} {
		if !exists(filepath.Join(dir, f)) {
			t.Errorf("--out-dir holds no %s", f)
		}
	}
}
