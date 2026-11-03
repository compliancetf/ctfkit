package tfexec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const fakePkg = "registry.terraform.io/bobthecorp/fake/1.0.0/" + runtime.GOOS + "_" + runtime.GOARCH

// fake is a fake terraform: a shell script that logs "$0 $*" and its env per
// call, and on init installs or links the fake provider package the way
// terraform does: a real directory under the empty CLI config, a link into
// the filesystem mirror under the mirror config.
type fake struct {
	bin, dir, log string
}

// fakeOpts: provider installs a package on the first init; mirror is "link",
// "copy" or "" (the mirror init installs nothing).
type fakeOpts struct {
	provider  string
	mirror    string
	onVersion string // shell run during version -json
}

func newFake(t *testing.T, o fakeOpts) fake {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake terraform is a shell script")
	}
	d := t.TempDir()
	f := fake{bin: filepath.Join(d, "terraform"), dir: d, log: filepath.Join(d, "argv.log")}
	install := ""
	if o.provider != "" {
		install = fmt.Sprintf(`p="$TF_DATA_DIR/providers/%[1]s"
  case "$TF_CLI_CONFIG_FILE" in
  */empty.tfrc) mkdir -p "$p"; : > "$p.lock"; printf %%s %[2]q > "$p/terraform-provider-fake_v1.0.0"; chmod 755 "$p/terraform-provider-fake_v1.0.0" ;;
  */mirror.tfrc) m=$(sed -n 's/^ *path *= *"\(.*\)"$/\1/p' "$TF_CLI_CONFIG_FILE"); mkdir -p "$(dirname "$p")"
    case %[3]q in link) ln -s "$m/%[1]s" "$p" ;; copy) cp -R "$m/%[1]s" "$p" ;; esac ;;
  esac`, fakePkg, o.provider, o.mirror)
	}
	script := fmt.Sprintf(`#!/bin/sh
n=$(wc -l < %[1]q 2>/dev/null || echo 0); n=$((n+0))
printf '%%s %%s\n' "$0" "$*" >> %[1]q
env | sort > %[2]q.$n
case "$1" in version) %[3]s
  echo '{"terraform_version":"1.16.3"}'; exit 0 ;; esac
case "$2" in
init) %[4]s ;;
workspace) printf '* default\n\n' ;;
plan) for a; do case "$a" in -out=*) printf 'fake planfile' > "${a#-out=}" ;; esac; done ;;
esac
`, f.log, filepath.Join(d, "env"), strings.NewReplacer("@BIN@", f.bin, "@DIR@", d).Replace(o.onVersion), install)
	if err := os.WriteFile(f.bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: an executable test fake
		t.Fatal(err)
	}
	return f
}

func (f fake) calls(t *testing.T) []string {
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

func (f fake) env(t *testing.T, n int) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, fmt.Sprintf("env.%d", n)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func digestOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func config(t *testing.T, f fake) Config {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return Config{Terraform: f.bin, Digest: digestOf(t, f.bin), Dir: dir, Workspace: "default"}
}

func open(t *testing.T, cfg Config) *Session {
	t.Helper()
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func run(t *testing.T, s *Session, calls ...Call) {
	t.Helper()
	for _, c := range calls {
		if err := s.Run(c, io.Discard, io.Discard); err != nil {
			t.Fatalf("%s: %v", c.Row(), err)
		}
	}
}

// TestArgvTable: every vector of testdata/argv matches its row or is
// refused, and every constructor builds an argv of its own row.
func TestArgvTable(t *testing.T) {
	var doc struct {
		Vectors []struct{ Name, Argv, Want string }
	}
	readJSON(t, "testdata/argv/rows.json", &doc)
	for _, v := range doc.Vectors {
		row, err := Check(strings.Fields(v.Argv))
		if v.Want == "refused" {
			if !errors.Is(err, ErrOffTable) {
				t.Errorf("%s: matched %s, want refused", v.Name, row)
			}
		} else if err != nil || row != v.Want {
			t.Errorf("%s: %s %v, want %s", v.Name, row, err, v.Want)
		}
	}
	sealed := Sealed{"planfile"}
	for _, c := range []Call{Version(), Init(), Plan(), Show(sealed), Apply(sealed), StatePull(), WorkspaceList(),
		MigratePlan("pre"), MigratePlan("post"), ReplaceProvider("registry.terraform.io/hashicorp/aws", "registry.compliance.tf/compliancetf/aws", "60s"),
		ProvidersLock("registry.compliance.tf/compliancetf/aws", "linux_amd64", "darwin_arm64"), WorkspaceNew("prod"), Schema()} {
		if row, err := Check(c.Template()); err != nil || row != c.Row() {
			t.Errorf("%s builds %q: %s %v", c.Row(), c.Template(), row, err)
		}
	}
	// A parameter that is a flag never passes the table, so Run refuses it
	// before terraform starts.
	for _, c := range []Call{MigratePlan("pre -refresh=false"), WorkspaceNew("-state=/tmp/x"),
		ReplaceProvider("-lock=false", "registry.compliance.tf/compliancetf/aws", "60s"), ProvidersLock("x", "-fs-mirror=/tmp")} {
		if _, err := Check(c.Template()); err == nil {
			t.Errorf("%q accepted", c.Template())
		}
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// TestEnvTable: the child env equals the env table for each vector of
// testdata/env, whatever the parent env holds; a name the table never
// passes is refused before anything runs.
func TestEnvTable(t *testing.T) {
	var doc struct {
		Parent map[string]string
		Cases  []struct {
			Name, Call         string
			Credentials, Proxy []string
			Want               json.RawMessage
		}
	}
	readJSON(t, "testdata/env/cases.json", &doc)
	for k, v := range doc.Parent {
		t.Setenv(k, v)
	}
	for _, tc := range doc.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			f := newFake(t, fakeOpts{})
			cfg := config(t, f)
			cfg.Credentials, cfg.Proxy = tc.Credentials, tc.Proxy
			if string(tc.Want) == `"refused"` {
				if s, err := Open(cfg); err == nil {
					_ = s.Close()
					t.Fatal("opened")
				}
				return
			}
			var want []string
			if err := json.Unmarshal(tc.Want, &want); err != nil {
				t.Fatal(err)
			}
			s := open(t, cfg)
			calls := map[string]Call{"A2": Init(), "A9": WorkspaceList(), "A3": Plan()}
			if tc.Call != "A2" {
				run(t, s, Init())
			}
			run(t, s, calls[tc.Call])
			got := f.env(t, len(f.calls(t))-1)
			got = slices.DeleteFunc(got, func(kv string) bool {
				return strings.HasPrefix(kv, "PWD=") || strings.HasPrefix(kv, "SHLVL=") || strings.HasPrefix(kv, "_=") || strings.HasPrefix(kv, "OLDPWD=")
			})
			for i := range got {
				got[i] = strings.ReplaceAll(got[i], s.root+"/", "<owned>/")
			}
			if !slices.Equal(got, want) {
				t.Fatalf("child env\n%q\nwant\n%q", got, want)
			}
		})
	}
}

// TestWorkspace: every call runs with the session's or the call's workspace,
// A9 and A16 with none, and a parent TF_WORKSPACE never applies.
func TestWorkspace(t *testing.T) {
	t.Setenv("TF_WORKSPACE", "parent")
	f := newFake(t, fakeOpts{})
	s := open(t, config(t, f))
	run(t, s, Init(), Plan().In("staging"), WorkspaceList().In("staging"), WorkspaceNew("prod"), StatePull())
	want := []string{"TF_WORKSPACE=default", "TF_WORKSPACE=staging", "", "", "TF_WORKSPACE=default"}
	for i, w := range want {
		ws := ""
		for _, kv := range f.env(t, i) {
			if strings.HasPrefix(kv, "TF_WORKSPACE=") {
				ws = kv
			}
		}
		if ws != w {
			t.Errorf("call %d: %q, want %q", i, ws, w)
		}
	}
}

// TestCallWorkspaceChecked: a call's own workspace passes the same check as
// the session's; a path or a newline never reaches TF_WORKSPACE.
func TestCallWorkspaceChecked(t *testing.T) {
	f := newFake(t, fakeOpts{})
	s := open(t, config(t, f))
	run(t, s, Init())
	for _, ws := range []string{"../x", "a\nTF_LOG=trace", "-x", "a=b"} {
		if err := s.Run(StatePull().In(ws), io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
			t.Errorf("workspace %q: %v", ws, err)
		}
	}
	if _, err := s.Seal("..", nil); err == nil {
		t.Error("a sealed copy named .. was accepted")
	}
	if c := f.calls(t); len(c) != 1 {
		t.Fatalf("calls %q", c)
	}
}

// TestLocalPaths: every init carries the canonical local backend paths.
func TestLocalPaths(t *testing.T) {
	f := newFake(t, fakeOpts{})
	cfg := config(t, f)
	cfg.LocalPaths = &LocalPaths{StatePath: "/srv/bobthecorp/terraform.tfstate", WorkspaceDir: "/srv/bobthecorp/terraform.tfstate.d"}
	s := open(t, cfg)
	run(t, s, Init(), Plan(), Init())
	calls := f.calls(t)
	for _, i := range []int{0, 2} {
		if !strings.HasSuffix(calls[i], " init -input=false -lockfile=readonly -backend-config=path=/srv/bobthecorp/terraform.tfstate -backend-config=workspace_dir=/srv/bobthecorp/terraform.tfstate.d") {
			t.Errorf("init %q", calls[i])
		}
	}
	if strings.Contains(calls[1], "backend-config") {
		t.Errorf("plan %q", calls[1])
	}
	cfg.LocalPaths.StatePath = "terraform.tfstate"
	if _, err := Open(cfg); err == nil {
		t.Fatal("a relative local state path opened")
	}
}

// TestSealedTerraform: every call runs a sealed copy of the pinned binary;
// a binary swapped before the first call never runs, and one replaced after
// hashing changes nothing: the next call refuses and the session stops.
func TestSealedTerraform(t *testing.T) {
	t.Run("sealed copy runs", func(t *testing.T) {
		f := newFake(t, fakeOpts{})
		s := open(t, config(t, f))
		run(t, s, Version(), Init(), Plan())
		for i, c := range f.calls(t) {
			if want := s.Owned(fmt.Sprintf("sealed/terraform-%d", i+1)); !strings.HasPrefix(c, want+" ") {
				t.Errorf("call %d ran %q, want %s", i, c, want)
			}
		}
	})
	t.Run("swapped before the first version", func(t *testing.T) {
		f := newFake(t, fakeOpts{})
		cfg := config(t, f)
		cfg.Digest = "sha256:" + strings.Repeat("0", 64)
		s := open(t, cfg)
		if err := s.Run(Version(), io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
			t.Fatalf("version: %v", err)
		}
		if c := f.calls(t); c != nil {
			t.Fatalf("terraform ran: %q", c)
		}
		if err := s.Run(Init(), io.Discard, io.Discard); err == nil {
			t.Fatal("init ran after a refused binary")
		}
	})
	t.Run("replaced after hashing", func(t *testing.T) {
		// version -json replaces the pinned binary while its sealed copy runs.
		f := newFake(t, fakeOpts{onVersion: `printf '#!/bin/sh\ntouch @DIR@/evil\n' > @BIN@;`})
		s := open(t, config(t, f))
		run(t, s, Version())
		if err := s.Run(Init(), io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
			t.Fatalf("init after the swap: %v", err)
		}
		if _, err := os.Stat(filepath.Join(f.dir, "evil")); err == nil {
			t.Fatal("the replacement binary ran")
		}
		if c := f.calls(t); len(c) != 1 {
			t.Fatalf("calls %q", c)
		}
	})
	t.Run("no workspace", func(t *testing.T) {
		f := newFake(t, fakeOpts{})
		cfg := config(t, f)
		cfg.Workspace = ""
		s := open(t, cfg)
		run(t, s, Version(), Init(), WorkspaceList())
		n := len(f.calls(t))
		for _, c := range []Call{Plan(), StatePull(), Plan().In("")} {
			if err := s.Run(c, io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
				t.Fatalf("%s without a workspace: %v", c.Row(), err)
			}
		}
		if err := open(t, config(t, f)).Run(Version().In(""), io.Discard, io.Discard); err != nil {
			t.Fatalf("version without a workspace: %v", err)
		}
		if len(f.calls(t)) != n+1 {
			t.Fatal("terraform ran a state row without a workspace")
		}
	})
	t.Run("relative path", func(t *testing.T) {
		if _, err := Open(Config{Terraform: "terraform", Digest: "sha256:00", Dir: "/tmp"}); err == nil {
			t.Fatal("relative --tf-bin opened")
		}
	})
}

// TestOwnedPaths: a symlink planted at HOME, TMPDIR or a CLI config path,
// or a wider mode, stops Open.
func TestOwnedPaths(t *testing.T) {
	f := newFake(t, fakeOpts{})
	cfg := config(t, f)
	target := t.TempDir()
	for _, name := range []string{"home", "tmp", "empty.tfrc", "mirror.tfrc", "data", "cwd", "sealed"} {
		t.Run(name, func(t *testing.T) {
			defer func(h func(string)) { BeforeOwned = h }(BeforeOwned)
			var root string
			BeforeOwned = func(r string) {
				root = r
				if err := os.Symlink(target, filepath.Join(r, name)); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := Open(cfg); err == nil {
				_ = s.Close()
				t.Fatal("opened over a planted symlink")
			}
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the owned root was left behind")
			}
		})
	}
	s := open(t, cfg)
	for _, c := range []struct {
		name string
		dir  bool
		mode os.FileMode
	}{{"home", true, 0o700}, {"tmp", true, 0o700}, {"data", true, 0o700}, {"empty.tfrc", false, 0o600}} {
		if err := checkOwned(s.Owned(c.name), c.dir, c.mode); err != nil {
			t.Error(err)
		}
	}
	if err := os.Chmod(s.Owned("home"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkOwned(s.Owned("home"), true, 0o700); err == nil {
		t.Error("a wider mode passed")
	}
}

// TestBeforeInit: no row but version runs before init.
func TestBeforeInit(t *testing.T) {
	f := newFake(t, fakeOpts{})
	s := open(t, config(t, f))
	if err := s.Run(Plan(), io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("plan before init: %v", err)
	}
	if c := f.calls(t); c != nil {
		t.Fatalf("terraform ran: %q", c)
	}
}

// TestSealOwned: the sealed bytes are those read once; a later write to the
// owned file changes neither.
func TestSealOwned(t *testing.T) {
	f := newFake(t, fakeOpts{})
	s := open(t, config(t, f))
	run(t, s, Init(), Plan())
	sl, b, err := s.SealOwned("planfile", "planfile", 1<<20)
	if err != nil || string(b) != "fake planfile" {
		t.Fatalf("%q %v", b, err)
	}
	if err = os.WriteFile(s.Owned("planfile"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(s.Owned("sealed/" + sl.name))
	if err != nil || !bytes.Equal(got, b) {
		t.Fatalf("sealed %q %v", got, err)
	}
	if _, err = s.Seal("planfile", []byte("again")); err == nil {
		t.Fatal("a sealed copy was overwritten")
	}
}

// TestApplyEnv: only ctfkit apply's three COMPLIANCETF_* variables pass,
// and only on A6.
func TestApplyEnv(t *testing.T) {
	f := newFake(t, fakeOpts{})
	s := open(t, config(t, f))
	run(t, s, Init())
	pf, err := s.Seal("planfile", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	run(t, s, Apply(pf, "COMPLIANCETF_VERDICT=/srv/v.json"))
	if !slices.Contains(f.env(t, 1), "COMPLIANCETF_VERDICT=/srv/v.json") {
		t.Fatal("COMPLIANCETF_VERDICT did not reach apply")
	}
	for _, kv := range []string{"COMPLIANCETF_UPSTREAM_PATH=/tmp/x", "LD_PRELOAD=/tmp/x", "COMPLIANCETF_VERDICT=relative"} {
		if err := s.Run(Apply(pf, kv), io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
			t.Errorf("%s: %v", kv, err)
		}
	}
	c := Plan()
	c.extra = []string{"COMPLIANCETF_VERDICT=/srv/v.json"}
	if err := s.Run(c, io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
		t.Errorf("verdict env on plan: %v", err)
	}
}
