package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// scan --out-dir creates its directory, parents included, as report does:
// both commands go through ensureOutDir. A path that exists and is not a
// directory is still refused before anything is written.
func TestScanOutDirIsCreated(t *testing.T) {
	input := fixtureInput(t, "01-raw-s3-no-ctf")
	work := t.TempDir()
	dir := filepath.Join(work, "a", "b", ".ctfkit")

	got := runScanIn(t, work, append([]string{
		"scan", filepath.Join(input, "plan.json"),
		"--format", "sarif,json", "--out-dir", dir,
	}, scanRunContext...)...)
	if got.code == ExitEnvironment {
		t.Fatalf("scan --out-dir %s exited 2: %v", dir, got.err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("--out-dir was not created: %v", err)
	}
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
	for _, f := range []string{"findings.sarif", "findings.json"} {
		if _, statErr := os.Stat(filepath.Join(dir, f)); statErr != nil {
			t.Errorf("--out-dir holds no %s", f)
		}
	}

	// A regular file where the directory should be is still an input error,
	// and no projection is written anywhere.
	file := filepath.Join(work, "not-a-dir")
	if err = os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got = runScanIn(t, work, append([]string{
		"scan", filepath.Join(input, "plan.json"),
		"--format", "sarif,json", "--out-dir", file,
	}, scanRunContext...)...)
	var exit *ExitError
	if got.code != ExitEnvironment || !asExitError(got.err, &exit) || exit.Category != categoryInput {
		t.Errorf("--out-dir naming a file: exit %d, err %v; want exit 2, category input", got.code, got.err)
	}
}
