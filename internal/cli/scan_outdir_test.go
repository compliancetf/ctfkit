package cli

import (
	"os"
	"path/filepath"
	"strings"
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

// A destination inside the working directory, which in CI is the analyzed
// checkout, is resolved inside it: a symlink committed there cannot send a
// projection to a file outside it.
func TestScanOutRefusesSymlinkOutOfWorkingDir(t *testing.T) {
	input := fixtureInput(t, "01-raw-s3-no-ctf")
	tests := []struct {
		name  string
		links map[string]string // link path in the work dir -> target relative to the victim dir
		dirs  []string
		args  []string
	}{
		{"out-dir is a symlink", map[string]string{"out": "."}, nil, []string{"--format", "sarif,json", "--out-dir", "out"}},
		{"out-dir parent is a symlink", map[string]string{"a": "."}, nil, []string{"--format", "sarif,json", "--out-dir", "a/out"}},
		{"file in out-dir is a symlink", map[string]string{"out/findings.sarif": "target.txt"}, []string{"out"}, []string{"--format", "sarif,json", "--out-dir", "out"}},
		{"out is a symlink", map[string]string{"lock.sarif": "target.txt"}, nil, []string{"--format", "sarif", "--out", "lock.sarif"}},
		{"absolute out-dir under a symlink", map[string]string{"a": "."}, nil, []string{"--format", "sarif,json", "--out-dir", "{work}/a/out"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			victim, work := t.TempDir(), t.TempDir()
			target := filepath.Join(victim, "target.txt")
			if err := os.WriteFile(target, []byte("ORIGINAL"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, d := range tc.dirs {
				if err := os.Mkdir(filepath.Join(work, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for link, to := range tc.links {
				if err := os.Symlink(filepath.Join(victim, to), filepath.Join(work, link)); err != nil {
					t.Fatal(err)
				}
			}

			args := make([]string, len(tc.args))
			for i, a := range tc.args {
				args[i] = strings.ReplaceAll(a, "{work}", work)
			}
			got := runScanIn(t, work, append(append([]string{"scan", filepath.Join(input, "plan.json")}, args...), scanRunContext...)...)

			if got.code != ExitEnvironment {
				t.Errorf("exit %d, want 2: %v", got.code, got.err)
			}
			if b, _ := os.ReadFile(target); string(b) != "ORIGINAL" {
				t.Errorf("target outside the working directory was overwritten: %.40q", b)
			}
			entries, _ := os.ReadDir(victim)
			if len(entries) != 1 {
				t.Errorf("victim dir holds %d entries, want only target.txt", len(entries))
			}
		})
	}
}
