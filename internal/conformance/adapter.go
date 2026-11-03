package conformance

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Adapter is what the harness needs from an adapter: the stages it runs, a
// run over one fixture that returns the adapter-native output, and the
// adapter's own helper that turns that output back into SARIF.
//
// Run returns nil output and no error when the fixture records no output (an
// exit-2 case) and the adapter stopped the way its platform contract says it
// must. An exit code the contract does not allow is an error.
type Adapter interface {
	Name() string
	Stages() []ctfkit.Stage
	Run(t testing.TB, f Fixture) (native []byte, err error)
	ToSARIF(native []byte) ([]byte, error)
}

// FieldsOnly marks an adapter whose native output carries only the Spacelift
// summary fields, so Check compares Fields rather than whole documents.
type FieldsOnly interface {
	FieldsOnly() bool
}

// Runs reports whether a runs f: the adapter runs f's stage and f is not the
// post_apply case the harness keeps for itself.
func Runs(a Adapter, f Fixture) bool {
	return f.Stage != ctfkit.PostApply && slices.Contains(a.Stages(), f.Stage)
}

// Check runs a over f and returns every field that differs from the recorded
// SARIF after the known deviations are dropped and run context is normalized.
// Empty means the round trip holds.
func Check(t testing.TB, a Adapter, f Fixture) []string {
	t.Helper()
	native, err := a.Run(t, f)
	if err != nil {
		return []string{"run: " + err.Error()}
	}
	switch {
	case f.Want == nil && native == nil:
		return nil
	case f.Want == nil:
		return []string{"the adapter rendered output for a case that records none"}
	case native == nil:
		return []string{"the adapter rendered nothing"}
	}
	got, err := a.ToSARIF(native)
	if err != nil {
		return []string{"to SARIF: " + err.Error()}
	}
	want, err := f.Recorded()
	if err != nil {
		return []string{err.Error()}
	}
	if fo, ok := a.(FieldsOnly); ok && fo.FieldsOnly() {
		wf, wErr := FieldsOf(want)
		gf, gErr := FieldsOf(got)
		if err = errors.Join(wErr, gErr); err != nil {
			return []string{err.Error()}
		}
		return DiffFields(wf, gf)
	}
	return compareSARIF(f, want, got)
}

// compareSARIF is the byte comparison after normalization, reported as the
// fields that differ.
func compareSARIF(f Fixture, want, got []byte) []string {
	want, got = Normalize(want), Normalize(got)
	if bytes.Equal(want, got) {
		return nil
	}
	if diff := Diff(want, got); len(diff) > 0 {
		return diff
	}
	return []string{"equal as JSON but not byte for byte: indentation, key order or trailing newline"}
}

// BuildBinary builds ctfkit from the checkout at root into dir, reporting the
// fixture generator version, and returns its path. It always builds, so a
// stale binary can never answer for the tree under test.
func BuildBinary(root, dir string) (string, error) {
	name := "ctfkit"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-ldflags", "-X main.version="+FixtureVersion, "-o", out, "./cmd/ctfkit") // #nosec G204 -- fixed argv; out is a directory the caller created
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, stderr.String())
	}
	return out, nil
}

// process is one finished subprocess.
type process struct {
	stdout, stderr []byte
	code           int
}

// run executes name with args in dir. env replaces the environment, so a
// developer's HOME catalog or CTFKIT_FAIL_ON cannot leak into a fixture run.
func run(dir string, env []string, name string, args ...string) (process, error) {
	cmd := exec.Command(name, args...) // #nosec G204 -- the harness runs the binary it built, or the adapter's own shell script, with fixture arguments
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	p := process{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		p.code = exitErr.ExitCode()
	default:
		return p, err
	}
	return p, nil
}

// baseEnv is a clean environment: PATH with the binary's directory first,
// and an empty HOME so no home catalog or settings file is found.
func baseEnv(t testing.TB, bin string) []string {
	return []string{
		"PATH=" + filepath.Dir(bin) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
	}
}

// relInput is the input directory relative to the repository root: report
// runs are made from the root, which is how the recorded projections name
// their subject.
func relInput(f Fixture) (string, error) {
	return filepath.Rel(f.Root, f.Input)
}
