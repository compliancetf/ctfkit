package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/fixturepin"
)

// testToken stands in for the registry credential. It must never reach the
// pack, the fake tofu's environment or the recorder's output.
const testToken = "fake-registry-token-5d2c9a41"

// fakeTofu answers `version -json` with the mise.toml pin and, for
// `-chdir=<case> init -backend=false ...`, installs the case's modules from a
// stash the way tofu does under TF_DATA_DIR: absolute Dirs in modules.json.
// It fails when the environment carries anything the recorder should have
// dropped, or when the CLI config is not the 0600 credentials file.
const fakeTofu = `#!/bin/sh
stash='@STASH@'
log='@LOG@'
if [ "$1" = version ]; then
  [ -z "${FAKE_TOFU_BROKEN:-}" ] || exit 1
  echo '{"terraform_version":"1.12.6","platform":"test"}'
  exit 0
fi
chdir=${1#-chdir=}
[ "$2 $3" = "init -backend=false" ] || { echo "fake tofu: unexpected arguments: $*" >&2; exit 1; }
c=$(basename "$chdir")
echo "init $c $(env | cut -d= -f1 | sort | tr '\n' ' ')" >>"$log"
[ -n "$(find "$TF_CLI_CONFIG_FILE" -perm 0600)" ] || { echo "fake tofu: CLI config is not 0600" >&2; exit 1; }
grep -q '^credentials "bobthecorp.compliance.tf"' "$TF_CLI_CONFIG_FILE" || { echo "fake tofu: no credentials block" >&2; exit 1; }
mkdir -p "$TF_DATA_DIR"
cp -R "$stash/$c/input/.terraform/modules" "$TF_DATA_DIR/modules"
sed "s#\"Dir\":\".terraform/modules/#\"Dir\":\"$TF_DATA_DIR/modules/#g" \
  "$stash/$c/input/.terraform/modules/modules.json" >"$TF_DATA_DIR/modules/modules.json"
`

// recorderEnv is the recorder under test: a copy of the repository, a stash
// the fake tofu serves modules from, and the environment the script runs in.
type recorderEnv struct {
	repo, stash, tmp, log string
	env                   []string
}

func newRecorderEnv(t *testing.T) *recorderEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the recorder is a bash script")
	}
	for _, tool := range []string{"bash", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}

	r := &recorderEnv{repo: t.TempDir(), stash: t.TempDir(), tmp: t.TempDir()}
	// adapters/hcp is Go the CLI imports (runtask serve).
	for _, p := range []string{"go.mod", "go.sum", "mise.toml", "adapters/hcp", "cmd", "internal", "pkg", "scripts", "testdata/fixtures/report"} {
		copyTree(t, filepath.Join("..", "..", p), filepath.Join(r.repo, p))
	}
	copyTree(t, filepath.Join("..", "..", "testdata/fixtures/report"), r.stash)

	bin := t.TempDir()
	r.log = filepath.Join(t.TempDir(), "tofu.log")
	script := strings.NewReplacer("@STASH@", r.stash, "@LOG@", r.log).Replace(fakeTofu)
	if err := os.WriteFile(filepath.Join(bin, "tofu"), []byte(script), 0o755); err != nil { //nolint:gosec // an executable fake
		t.Fatal(err)
	}

	goBin, _ := exec.LookPath("go")
	r.env = []string{
		"PATH=" + bin + ":" + filepath.Dir(goBin) + ":/usr/bin:/bin",
		"HOME=" + t.TempDir(),
		"TMPDIR=" + r.tmp,
		"GOMODCACHE=" + goEnv(t, "GOMODCACHE"),
		"GOCACHE=" + goEnv(t, "GOCACHE"),
		"TF_TOKEN_bobthecorp_compliance_tf=" + testToken,
	}
	return r
}

func (r *recorderEnv) run(t *testing.T, extra []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(r.repo, "scripts", "record-report-fixtures.sh")}, args...)...) //nolint:gosec // the script under test
	cmd.Env = append(append([]string{}, r.env...), extra...)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), testToken) {
		t.Errorf("the recorder printed the token")
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("run the recorder: %v", err)
	return -1, ""
}

func (r *recorderEnv) live() string { return filepath.Join(r.repo, "testdata", "fixtures", "report") }

// residue fails when a run left its scratch parent, fresh tree or backup.
func (r *recorderEnv) residue(t *testing.T) {
	t.Helper()
	for _, p := range []string{filepath.Join(r.tmp, "ctfkit-report-rerecord"), filepath.Join(r.repo, "testdata", ".report-rerecord")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was left behind", p)
		}
	}
}

// TestRecorderEndToEnd drives scripts/record-report-fixtures.sh against a
// fake tofu that serves exactly the committed modules. Re-recording then must
// reproduce the committed pack: every input and every expected file, which
// the recorder regenerates from nothing through CTFKIT_RERECORD, twice.
func TestRecorderEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the report golden tests in a child process")
	}
	r := newRecorderEnv(t)
	orig := filepath.Join("..", "..", "testdata", "fixtures", "report")

	t.Run("record reproduces the committed pack", func(t *testing.T) {
		if code, out := r.run(t, nil); code != 0 {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		drift, err := fixturepin.Drift(orig, r.live())
		if err != nil {
			t.Fatal(err)
		}
		// PIN.json gains the tofu version; helper-module's hand-assembled
		// modules.json takes tofu's encoding, its receipt hashes it, and its
		// evidence pack lists the receipt's digest.
		want := []string{
			"changed: PIN.json",
			"changed: helper-module/expected/pack.json",
			"changed: helper-module/expected/receipt.json",
			"changed: helper-module/input/.terraform/modules/modules.json",
		}
		if strings.Join(drift, "\n") != strings.Join(want, "\n") {
			t.Errorf("a re-record against the same modules drifted:\n%s\nwant\n%s", strings.Join(drift, "\n"), strings.Join(want, "\n"))
		}
		pin, _, err := fixturepin.ReadPin(filepath.Join(r.live(), fixturepin.PinFile))
		if err != nil {
			t.Fatal(err)
		}
		if pin.TofuVersion != "1.12.6" {
			t.Errorf("tofu_version = %q, want the pinned 1.12.6", pin.TofuVersion)
		}
		for _, e := range fixturepin.Check(r.live()) {
			t.Error(e)
		}
		r.residue(t)

		log, err := os.ReadFile(r.log)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
			for _, name := range strings.Fields(line)[2:] {
				switch name {
				case "PATH", "HOME", "TMPDIR", "TF_DATA_DIR", "TF_CLI_CONFIG_FILE", "TF_IN_AUTOMATION", "PWD", "SHLVL", "_", "OLDPWD":
				default:
					t.Errorf("tofu ran with %s in its environment: %s", name, line)
				}
			}
		}
	})

	t.Run("--check after a re-record finds no drift", func(t *testing.T) {
		if code, out := r.run(t, nil, "--check"); code != 0 {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		r.residue(t)
	})

	t.Run("--check reports a served manifest that moved", func(t *testing.T) {
		m := filepath.Join(r.stash, "served-leaf", "input", ".terraform", "modules", "s3_bucket_notification", "modules", "notification", fixturepin.ManifestName)
		restore := edit(t, m, `"schema_version": "3.3",`, `"schema_version": "3.3", "served": "later",`)
		defer restore()
		before := readAll(t, r.live())

		code, out := r.run(t, nil, "--check")
		if code != 1 || !strings.Contains(out, "changed: served-leaf/input/.terraform/modules/s3_bucket_notification") {
			t.Fatalf("exit %d, want 1 naming the manifest:\n%s", code, out)
		}
		if !sameTree(before, readAll(t, r.live())) {
			t.Error("--check changed the live pack")
		}
		r.residue(t)
	})

	t.Run("the token in a served manifest stops the record with 3", func(t *testing.T) {
		m := filepath.Join(r.stash, "served-leaf", "input", ".terraform", "modules", "s3_bucket_notification", "modules", "notification", fixturepin.ManifestName)
		restore := edit(t, m, `"schema_version": "3.3",`, `"schema_version": "3.3", "leak": "`+testToken+`",`)
		defer restore()
		before := readAll(t, r.live())

		if code, out := r.run(t, nil); code != 3 {
			t.Fatalf("exit %d, want 3:\n%s", code, out)
		}
		if !sameTree(before, readAll(t, r.live())) {
			t.Error("a record that found the token swapped the pack in")
		}
		r.residue(t)
	})

	t.Run("an absolute path in a served manifest is a pattern hit, 2", func(t *testing.T) {
		m := filepath.Join(r.stash, "served-leaf", "input", ".terraform", "modules", "s3_bucket_notification", "modules", "notification", fixturepin.ManifestName)
		restore := edit(t, m, `"schema_version": "3.3",`, `"schema_version": "3.3", "built_in": "/Users/dev/work",`)
		defer restore()
		if code, out := r.run(t, nil, "--check"); code != 2 || strings.Contains(out, "changed:") {
			t.Fatalf("exit %d, want 2 with no diff output:\n%s", code, out)
		}
		r.residue(t)
	})

	t.Run("a module source off the registry is refused before init", func(t *testing.T) {
		mainTF := filepath.Join(r.live(), "served-leaf", "input", "main.tf")
		restore := edit(t, mainTF, "", "module \"extra\" {\n  source = \"git::https://git.bobthecorp.example/x.git\"\n}\n")
		defer restore()
		if code, out := r.run(t, nil, "--check"); code != 2 || !strings.Contains(out, "nothing was fetched") {
			t.Fatalf("exit %d, want 2:\n%s", code, out)
		}
		r.residue(t)
	})

	t.Run("a crash between the two renames restores the live pack", func(t *testing.T) {
		before := readAll(t, r.live())
		if code, out := r.run(t, []string{"CTFKIT_RECORDER_TEST_FAIL_SWAP=1"}); code != 2 || !strings.Contains(out, "restored the live pack") {
			t.Fatalf("exit %d, want 2 after a restore:\n%s", code, out)
		}
		if !sameTree(before, readAll(t, r.live())) {
			t.Error("the live pack was not restored")
		}
		r.residue(t)
	})

	t.Run("the swap test seam is ignored in a git checkout", func(t *testing.T) {
		gitDir := filepath.Join(r.repo, ".git")
		if err := os.Mkdir(gitDir, 0o755); err != nil { //nolint:gosec // a test tree
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(gitDir) }()
		before := readAll(t, r.live())
		if code, out := r.run(t, []string{"CTFKIT_RECORDER_TEST_FAIL_SWAP=1"}); code != 0 {
			t.Fatalf("exit %d, want 0 with the seam ignored:\n%s", code, out)
		}
		if !sameTree(before, readAll(t, r.live())) {
			t.Error("a re-record against the same modules changed the pack")
		}
		r.residue(t)
	})

	t.Run("an unexpected failure is a tooling error, never drift", func(t *testing.T) {
		if code, out := r.run(t, []string{"FAKE_TOFU_BROKEN=1"}, "--check"); code != 2 {
			t.Fatalf("exit %d, want 2 when tofu version fails:\n%s", code, out)
		}
		r.residue(t)
	})

	t.Run("a backup left by an interrupted swap stops the record", func(t *testing.T) {
		backup := filepath.Join(r.repo, "testdata", ".report-rerecord", "backup")
		if err := os.MkdirAll(backup, 0o755); err != nil { //nolint:gosec // a test tree
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(filepath.Dir(backup)) }()
		if code, out := r.run(t, nil); code != 2 || !strings.Contains(out, "interrupted swap") {
			t.Fatalf("exit %d, want 2:\n%s", code, out)
		}
	})

	for _, tc := range []struct {
		name  string
		extra []string
		args  []string
		want  string
	}{
		{"CI is refused", []string{"CI=true"}, nil, "CI set"},
		{"--check with CTFKIT_UPDATE_GOLDEN is refused", []string{"CTFKIT_UPDATE_GOLDEN=1"}, []string{"--check"}, "CTFKIT_UPDATE_GOLDEN"},
		{"a missing token is refused", []string{"TF_TOKEN_bobthecorp_compliance_tf="}, []string{"--check"}, "set TF_TOKEN_bobthecorp_compliance_tf"},
		{"an unknown argument is refused", nil, []string{"--force"}, "usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, out := r.run(t, tc.extra, tc.args...); code != 2 || !strings.Contains(out, tc.want) {
				t.Fatalf("exit %d, want 2 with %q:\n%s", code, tc.want, out)
			}
		})
	}

	t.Run("a tofu other than the mise.toml pin is refused", func(t *testing.T) {
		restore := edit(t, filepath.Join(r.repo, "mise.toml"), `version = "1.12.6"`, `version = "1.12.7"`)
		defer restore()
		if code, out := r.run(t, nil, "--check"); code != 2 || !strings.Contains(out, "mise.toml pins 1.12.7") {
			t.Fatalf("exit %d, want 2:\n%s", code, out)
		}
	})
}

// edit replaces the first old with repl in file (old empty: appends repl) and
// returns the function that puts the original bytes back.
func edit(t *testing.T, file, old, repl string) func() {
	t.Helper()
	orig, err := os.ReadFile(file) //nolint:gosec // a test path
	if err != nil {
		t.Fatal(err)
	}
	next := append(append([]byte{}, orig...), repl...)
	if old != "" {
		if !bytes.Contains(orig, []byte(old)) {
			t.Fatalf("%s does not contain %q", file, old)
		}
		next = bytes.Replace(orig, []byte(old), []byte(repl), 1)
	}
	if err = os.WriteFile(file, next, 0o644); err != nil { //nolint:gosec // a test tree
		t.Fatal(err)
	}
	return func() {
		if err := os.WriteFile(file, orig, 0o644); err != nil { //nolint:gosec // a test tree
			t.Error(err)
		}
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	info, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		raw, readErr := os.ReadFile(src) //nolint:gosec // a repository path
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err = fixturepin.WriteFiles(filepath.Dir(dst), fixturepin.Files{filepath.Base(dst): raw}); err != nil {
			t.Fatal(err)
		}
		return
	}
	files, err := fixturepin.ReadFiles(src)
	if err != nil {
		t.Fatal(err)
	}
	if err = fixturepin.WriteFiles(dst, files); err != nil {
		t.Fatal(err)
	}
}

func readAll(t *testing.T, dir string) fixturepin.Files {
	t.Helper()
	f, err := fixturepin.ReadFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func sameTree(a, b fixturepin.Files) bool {
	if len(a) != len(b) {
		return false
	}
	for p, x := range a {
		if !bytes.Equal(x, b[p]) {
			return false
		}
	}
	return true
}

func goEnv(t *testing.T, key string) string {
	t.Helper()
	out, err := exec.Command("go", "env", key).Output()
	if err != nil {
		t.Fatalf("go env %s: %v", key, err)
	}
	return strings.TrimSpace(string(out))
}
