package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/tfexec"
)

// runnerFake is a fake terraform that logs "$0 $*" and its env per call;
// init installs a provider package when pkg is set.
type runnerFake struct{ bin, dir, log string }

func newRunnerFake(t *testing.T, pkg string) runnerFake {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake terraform is a shell script")
	}
	d := t.TempDir()
	f := runnerFake{bin: filepath.Join(d, "terraform"), dir: d, log: filepath.Join(d, "argv.log")}
	install := ":"
	if pkg != "" {
		install = fmt.Sprintf(`mkdir -p "$TF_DATA_DIR/providers/%s" && echo build > "$TF_DATA_DIR/providers/%s/terraform-provider-aws"`, pkg, pkg)
	}
	script := fmt.Sprintf(`#!/bin/sh
n=$(wc -l < %[1]q 2>/dev/null || echo 0); n=$((n+0))
printf '%%s %%s\n' "$0" "$*" >> %[1]q
env | sort > %[2]q.$n
case "$1" in version) echo '{"terraform_version":"1.16.3"}'; exit 0 ;; esac
case "$2" in
init) %[3]s ;;
workspace) printf '  default\n* staging\n\n' ;;
plan) for a; do case "$a" in -out=*) printf 'plan' > "${a#-out=}" ;; esac; done; exit 2 ;;
state) [ "$3" = pull ] && echo '{"version":4,"serial":7}' ;;
esac
exit 0
`, f.log, filepath.Join(d, "env"), install)
	if err := os.WriteFile(f.bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: an executable test fake
		t.Fatal(err)
	}
	return f
}

func (f runnerFake) calls(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func (f runnerFake) pin(t *testing.T) Pin {
	t.Helper()
	b, err := os.ReadFile(f.bin)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return Pin{TFBin: f.bin, TFBinSHA256: hex.EncodeToString(s[:])}
}

func noFindings(context.Context, string) error { return nil }

func runnerUnit(t *testing.T) (string, Unit) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, "live"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root, Unit{ID: "live", Kind: "cli", Dir: "live", Backend: "s3", BackendEnv: backendEnv["s3"], Workspaces: []string{"default", "staging"}}
}

func newTestRunner(t *testing.T, pin Pin, root string, u Unit, verify VerifyLock) *Runner {
	t.Helper()
	r, err := NewRunner(context.Background(), pin, root, u, verify)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

// TestRunnerEnv: the child env equals the Phase 3 env table: TF_WORKSPACE
// from the plan file (a parent TF_WORKSPACE never applies), the unit's
// backend_env[] names, and nothing of LD_*, DYLD_*, TF_CLI_ARGS*,
// TF_REATTACH_PROVIDERS, a parent CLI config, CA or proxy variables.
func TestRunnerEnv(t *testing.T) {
	for k, v := range map[string]string{
		"TF_WORKSPACE": "parent", "TF_REATTACH_PROVIDERS": `{"registry.terraform.io/hashicorp/aws":{}}`,
		"TF_CLI_CONFIG_FILE": "/tmp/dev_overrides.tfrc", "TF_CLI_ARGS_plan": "-refresh=false", "LD_PRELOAD": "/tmp/x.so",
		"LD_AUDIT": "/tmp/x.so", "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib", "SSL_CERT_FILE": "/tmp/x.pem", "HTTPS_PROXY": "http://p:3128",
		"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_REGION": "eu-west-1",
	} {
		t.Setenv(k, v)
	}
	f := newRunnerFake(t, "")
	root, u := runnerUnit(t)
	r := newTestRunner(t, f.pin(t), root, u, noFindings)
	if err := r.Init("staging", io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StatePull("staging", io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := r.WorkspaceList("staging", io.Discard); err != nil {
		t.Fatal(err)
	}
	owned := r.s.Owned("")
	for n, ws := range []string{"TF_WORKSPACE=staging", "TF_WORKSPACE=staging", ""} {
		b, err := os.ReadFile(filepath.Join(f.dir, fmt.Sprintf("env.%d", n)))
		if err != nil {
			t.Fatal(err)
		}
		got := slices.DeleteFunc(strings.Split(strings.TrimSpace(string(b)), "\n"), func(kv string) bool {
			return strings.HasPrefix(kv, "PWD=") || strings.HasPrefix(kv, "SHLVL=") || strings.HasPrefix(kv, "_=") || strings.HasPrefix(kv, "OLDPWD=")
		})
		cfg := "mirror.tfrc"
		if n == 0 {
			cfg = "empty.tfrc"
		}
		want := []string{"AWS_ACCESS_KEY_ID=AKIAEXAMPLE", "AWS_REGION=eu-west-1", "HOME=" + filepath.Join(owned, "home"),
			"PATH=/usr/bin:/bin", "TF_CLI_CONFIG_FILE=" + filepath.Join(owned, cfg), "TF_DATA_DIR=" + filepath.Join(owned, "data"),
			"TF_IN_AUTOMATION=1", ws, "TMPDIR=" + filepath.Join(owned, "tmp")}
		want = slices.DeleteFunc(want, func(s string) bool { return s == "" })
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("call %d env\n%q\nwant\n%q", n, got, want)
		}
	}
}

// TestRunnerArgv: every Runner call is a migrate row of the Phase 3 argv
// table (A1, A2, A9-A14), and show and state pull take no lock.
func TestRunnerArgv(t *testing.T) {
	f := newRunnerFake(t, "")
	root, u := runnerUnit(t)
	u.Backend, u.BackendEnv = "local", nil
	u.LocalPaths = &LocalPaths{StatePath: filepath.Join(root, "state", "terraform.tfstate"), WorkspaceDir: filepath.Join(root, "state", "terraform.tfstate.d")}
	r := newTestRunner(t, f.pin(t), root, u, noFindings)
	ctx := context.Background()
	steps := []func() error{
		func() error { _, err := r.Version("default", io.Discard); return err },
		func() error { return r.Init("default", io.Discard) },
		func() error { _, err := r.WorkspaceList("default", io.Discard); return err },
		func() error {
			code, p, err := r.PreflightPlan("staging", io.Discard)
			if err == nil && code != 2 {
				err = fmt.Errorf("detailed exit code %d", code)
			}
			if err == nil {
				_, err = r.Show("staging", p, io.Discard)
			}
			return err
		},
		func() error { _, err := r.StatePull("staging", io.Discard); return err },
		func() error {
			return r.ReplaceProvider("staging", "registry.terraform.io/hashicorp/aws", "registry.compliance.tf/compliancetf/aws", "60s", io.Discard)
		},
		func() error {
			return r.ProvidersLock("staging", "registry.compliance.tf/compliancetf/aws", []string{"linux_amd64", "darwin_arm64"}, io.Discard)
		},
		func() error { return r.Init("staging", io.Discard) },
		func() error { _, _, err := r.ProofPlan(ctx, "staging", io.Discard); return err },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	owned, dir := r.s.Owned(""), filepath.Join(root, "live")
	wantRows := []string{"A1", "A2", "A9", "A10", "A5", "A7", "A13", "A14", "A2", "A10"}
	calls := f.calls(t)
	if len(calls) != len(wantRows) {
		t.Fatalf("calls %q", calls)
	}
	for i, c := range calls {
		argv := strings.Fields(c)
		argv[0] = "<tf>"
		for j := range argv {
			argv[j] = strings.Replace(argv[j], "-chdir="+dir, "-chdir=<dir>", 1)
			argv[j] = strings.Replace(argv[j], owned+"/", "<owned>/", 1)
		}
		row, err := tfexec.Check(argv)
		if err != nil || row != wantRows[i] {
			t.Errorf("call %d %q: row %s %v, want %s", i, argv, row, err, wantRows[i])
		}
		if (row == "A5" || row == "A7") && strings.Contains(c, "-lock") {
			t.Errorf("%s takes a lock: %q", row, c)
		}
		if row == "A2" && !strings.HasSuffix(c, " -backend-config=path="+u.LocalPaths.StatePath+" -backend-config=workspace_dir="+u.LocalPaths.WorkspaceDir) {
			t.Errorf("init without the canonical local paths: %q", c)
		}
	}
}

// TestRunnerRefuses: a relative --tf-bin, a binary swapped after migrate
// plan, a provider package not matching the lock file, a workspace outside
// the plan file and a verify-lock finding each stop before any state
// command runs.
func TestRunnerRefuses(t *testing.T) {
	root, u := runnerUnit(t)
	t.Run("relative tf-bin", func(t *testing.T) {
		if _, err := NewRunner(context.Background(), Pin{TFBin: "terraform", TFBinSHA256: "00"}, root, u, noFindings); err == nil {
			t.Fatal("opened")
		}
	})
	t.Run("no verify-lock", func(t *testing.T) {
		f := newRunnerFake(t, "")
		if _, err := NewRunner(context.Background(), f.pin(t), root, u, nil); err == nil {
			t.Fatal("opened")
		}
	})
	t.Run("binary swapped after migrate plan", func(t *testing.T) {
		f := newRunnerFake(t, "")
		pin := f.pin(t)
		if err := os.WriteFile(f.bin, []byte("#!/bin/sh\ntouch "+filepath.Join(f.dir, "evil")+"\n"), 0o700); err != nil { //nolint:gosec // G306: an executable test fake
			t.Fatal(err)
		}
		r := newTestRunner(t, pin, root, u, noFindings)
		if _, err := r.Version("default", io.Discard); !errors.Is(err, tfexec.ErrNotStarted) {
			t.Fatalf("version: %v", err)
		}
		if err := r.Init("default", io.Discard); err == nil {
			t.Fatal("init ran")
		}
		if _, err := os.Stat(filepath.Join(f.dir, "evil")); err == nil {
			t.Fatal("the swapped binary ran")
		}
	})
	t.Run("provider not in the lock file", func(t *testing.T) {
		f := newRunnerFake(t, "registry.terraform.io/hashicorp/aws/6.0.0/"+runtime.GOOS+"_"+runtime.GOARCH)
		r := newTestRunner(t, f.pin(t), root, u, noFindings)
		if err := r.Init("default", io.Discard); err == nil || !strings.Contains(err.Error(), "lock file") {
			t.Fatalf("init: %v", err)
		}
		if _, err := r.StatePull("default", io.Discard); !errors.Is(err, tfexec.ErrNotStarted) {
			t.Fatalf("state pull: %v", err)
		}
		if c := f.calls(t); len(c) != 1 {
			t.Fatalf("calls %q", c)
		}
	})
	t.Run("unit dir outside the root", func(t *testing.T) {
		f := newRunnerFake(t, "")
		for _, dir := range []string{"..", "../x", "link"} {
			bad := u
			bad.Dir = dir
			if dir == "link" {
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
			}
			if r, err := NewRunner(context.Background(), f.pin(t), root, bad, noFindings); err == nil {
				_ = r.Close()
				t.Errorf("unit dir %q opened", dir)
			}
		}
	})
	t.Run("workspace outside the plan file", func(t *testing.T) {
		f := newRunnerFake(t, "")
		r := newTestRunner(t, f.pin(t), root, u, noFindings)
		if err := r.Init("prod", io.Discard); err == nil {
			t.Fatal("init in prod ran")
		}
		if err := r.Init("", io.Discard); err == nil {
			t.Fatal("init with TF_WORKSPACE unset ran")
		}
		if c := f.calls(t); c != nil {
			t.Fatalf("calls %q", c)
		}
	})
	t.Run("verify-lock finding", func(t *testing.T) {
		f := newRunnerFake(t, "")
		finding := errors.New("ctf.lock.upstream_present")
		var verified string
		r := newTestRunner(t, f.pin(t), root, u, func(_ context.Context, dir string) error { verified = dir; return finding })
		if err := r.Init("default", io.Discard); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.ProofPlan(context.Background(), "default", io.Discard); !errors.Is(err, finding) {
			t.Fatalf("proof plan: %v", err)
		}
		if verified != filepath.Join(root, "live") {
			t.Fatalf("verify-lock ran on %q", verified)
		}
		if _, _, err := r.PreflightPlan("default", io.Discard); err != nil {
			t.Fatalf("the preflight plan runs without verify-lock: %v", err)
		}
		if c := f.calls(t); len(c) != 2 || !strings.Contains(c[1], "-out="+r.s.Owned("pre.tfplan")) {
			t.Fatalf("calls %q: want init and the preflight plan only", c)
		}
	})
}

// TestRunnerPlansPerWorkspace: each workspace of a unit gets its own sealed
// preflight and proof plan in the one session.
func TestRunnerPlansPerWorkspace(t *testing.T) {
	f := newRunnerFake(t, "")
	root, u := runnerUnit(t)
	r := newTestRunner(t, f.pin(t), root, u, noFindings)
	if err := r.Init("default", io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, ws := range u.Workspaces {
		if _, _, err := r.PreflightPlan(ws, io.Discard); err != nil {
			t.Fatalf("preflight %s: %v", ws, err)
		}
		if _, _, err := r.ProofPlan(context.Background(), ws, io.Discard); err != nil {
			t.Fatalf("proof %s: %v", ws, err)
		}
	}
}

// TestBackendEnvNames: every backend_env name migrate plan records passes
// the env table's credential row.
func TestBackendEnvNames(t *testing.T) {
	f := newRunnerFake(t, "")
	root, u := runnerUnit(t)
	for backend, names := range backendEnv {
		u.Backend, u.BackendEnv = backend, names
		r, err := NewRunner(context.Background(), f.pin(t), root, u, noFindings)
		if err != nil {
			t.Fatalf("%s: %v", backend, err)
		}
		_ = r.Close()
	}
}

// TestRunnerRealLocalState runs the Runner with the binary CTFKIT_TEST_TF
// names on a local backend with a non-default workspace: state pull reads
// each workspace's state at the plan file's canonical local_paths, outside
// the owned dirs, and the state is still there after Close. Nothing is
// applied and no provider is installed.
func TestRunnerRealLocalState(t *testing.T) {
	tf := os.Getenv("CTFKIT_TEST_TF")
	if tf == "" {
		t.Skip("CTFKIT_TEST_TF is not set")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "state")
	files := map[string]string{
		"live/main.tf":            "terraform {\n  backend \"local\" {}\n}\n",
		"state/terraform.tfstate": `{"version":4,"terraform_version":"1.5.7","serial":3,"lineage":"6f3c1e9e-0000-4000-8000-000000000001","outputs":{},"resources":[],"check_results":null}`,
		"state/terraform.tfstate.d/staging/terraform.tfstate": `{"version":4,"terraform_version":"1.5.7","serial":9,"lineage":"6f3c1e9e-0000-4000-8000-000000000002","outputs":{},"resources":[],"check_results":null}`,
	}
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(tf) // #nosec G304 -- the test binary
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	u := Unit{ID: "live", Kind: "cli", Dir: "live", Backend: "local", BackendEnv: []string{},
		LocalPaths: &LocalPaths{StatePath: filepath.Join(stateDir, "terraform.tfstate"), WorkspaceDir: filepath.Join(stateDir, "terraform.tfstate.d")},
		Workspaces: []string{"default", "staging"}}
	r, err := NewRunner(context.Background(), Pin{TFBin: tf, TFBinSHA256: hex.EncodeToString(sum[:])}, root, u, noFindings)
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	for _, ws := range []string{"default", "staging"} {
		if err = r.Init(ws, &stderr); err != nil {
			t.Fatalf("init %s: %v\n%s", ws, err, stderr.String())
		}
	}
	list, err := r.WorkspaceList("default", &stderr)
	if err != nil || !strings.Contains(string(list), "staging") {
		t.Fatalf("workspace list %q: %v\n%s", list, err, stderr.String())
	}
	for ws, lineage := range map[string]string{"default": "0001", "staging": "0002"} {
		state, perr := r.StatePull(ws, &stderr)
		if perr != nil || !strings.Contains(string(state), lineage+`"`) {
			t.Fatalf("state pull %s: %s %v\n%s", ws, state, perr, stderr.String())
		}
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"state/terraform.tfstate", "state/terraform.tfstate.d/staging/terraform.tfstate"} {
		if _, err = os.Stat(filepath.Join(root, p)); err != nil {
			t.Fatalf("%s after Close: %v", p, err)
		}
	}
}
