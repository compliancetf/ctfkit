package cli

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/compliancetf/ctfkit/internal/tfexec"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The Terraform exec rules (D1, D4, E6, F1, F8) driven through gate
// plan, gate sign and ctfkit apply with the fake terraform; internal/tfexec
// tests the same rules on a bare session.

// fakePkg is the package dir the hook of withFakeProvider installs.
var fakePkg = "registry.terraform.io/bobthecorp/fake/1.0.0/" + runtime.GOOS + "_" + runtime.GOARCH

// linkedPlan is the plan whose signed set ctfkit apply applies.
var linkedPlan = filepath.Join(gateCases, "linked-create", "plan.json")

// hook makes f source body on every call; @BIN@ is the pinned binary.
func (f fakeTF) setHook(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(f.hook, []byte(strings.ReplaceAll(body, "@BIN@", f.bin)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// plantOwned runs fn on the owned root of every session opened until the test ends.
func plantOwned(t *testing.T, fn func(root string)) {
	t.Helper()
	prev := tfexec.BeforeOwned
	tfexec.BeforeOwned = fn
	t.Cleanup(func() { tfexec.BeforeOwned = prev })
}

// copyConfig copies the main.tf and lock file of src into a new directory.
func copyConfig(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	for _, n := range []string{"main.tf", ".terraform.lock.hcl"} {
		if err := os.WriteFile(filepath.Join(dst, n), readFile(t, filepath.Join(src, n)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// withDir replaces the --dir value of args.
func withDir(args []string, dir string) []string {
	args = slices.Clone(args)
	args[slices.Index(args, "--dir")+1] = dir
	return args
}

// withFakeProvider pins the fake provider in dir's lock file with the h1:
// hash of a package holding locked, and makes f install a package holding
// installed on the first init and link the sealed copy on the mirror init,
// as terraform does. plan records where the package link points.
func withFakeProvider(t *testing.T, f fakeTF, dir, locked, installed string) (link string) {
	t.Helper()
	pkg := t.TempDir()
	if err := os.WriteFile(filepath.Join(pkg, "terraform-provider-fake_v1.0.0"), []byte(locked), 0o600); err != nil {
		t.Fatal(err)
	}
	h1, err := dirhash.HashDir(pkg, "", dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, ".terraform.lock.hcl")
	entry := fmt.Sprintf("\nprovider %q {\n  version = \"1.0.0\"\n  hashes = [%q]\n}\n", "registry.terraform.io/bobthecorp/fake", h1)
	if err = os.WriteFile(lock, append(readFile(t, lock), entry...), 0o600); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(t.TempDir(), "link")
	f.setHook(t, fmt.Sprintf(`p="$TF_DATA_DIR/providers/%[1]s"
case "$2" in
init) case "$TF_CLI_CONFIG_FILE" in
  */empty.tfrc) mkdir -p "$p"; printf %%s %[2]q > "$p/terraform-provider-fake_v1.0.0"; chmod 755 "$p/terraform-provider-fake_v1.0.0" ;;
  */mirror.tfrc) m=$(sed -n 's/^ *path *= *"\(.*\)"$/\1/p' "$TF_CLI_CONFIG_FILE"); mkdir -p "$(dirname "$p")"; ln -s "$m/%[1]s" "$p" ;;
  esac ;;
plan) readlink "$p" > %[3]q ;;
esac
`, fakePkg, installed, link))
	return link
}

// noNewCalls asserts that terraform ran no call after the first before.
func noNewCalls(t *testing.T, f fakeTF, before int) {
	t.Helper()
	if calls := f.calls(t); len(calls) != before {
		t.Fatalf("terraform ran: %q", calls[before:])
	}
}

// TestTFExecRejectedFlags: no terraform flag passes through gate plan, gate
// sign or ctfkit apply; each exits 2 before terraform runs and leaves the
// set unconsumed.
func TestTFExecRejectedFlags(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	f, set := signedSet(t, inputs, linkedPlan)
	before := len(f.calls(t))
	for _, flag := range []string{"target=aws_s3_bucket.logs", "exclude=aws_s3_bucket.logs", "replace=aws_s3_bucket.logs",
		"refresh=false", "refresh-only", "destroy", "lock=false", "state=/srv/bobthecorp/x.tfstate",
		"state-out=/srv/bobthecorp/x.tfstate", "plugin-dir=/srv/bobthecorp/plugins"} {
		for _, spelled := range []string{"-" + flag, "--" + flag} {
			t.Run(spelled, func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "candidate")
				for _, args := range [][]string{planArgs(inputs, f.bin, out), signArgs(inputs, f.bin, set), applyArgs(inputs, f.bin, set, "apply")} {
					code, msg := runGate(applyCLI(t, inputs, signNow, signNow), append(args, spelled))
					if code != ExitEnvironment || !strings.Contains(msg, "unknown") {
						t.Fatalf("%s %s: exit %d (%s), want 2", args[0], spelled, code, msg)
					}
				}
				noNewCalls(t, f, before)
				if inSet(out, "") {
					t.Fatal("gate plan wrote --out")
				}
			})
		}
	}
	if _, err := os.Stat(filepath.Join(set, artifactRunKey)); err != nil {
		t.Fatalf("a refused flag consumed the set: %v", err)
	}
}

// TestTFExecSwappedBinary: a terraform binary swapped between gate plan and
// apply, or substituted after ctfkit took its digest but before the first
// version -json, never runs; one replaced while its sealed copy runs
// version -json changes nothing, since the next call (the first init)
// refuses it. Each exits 2.
func TestTFExecSwappedBinary(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	swap := func(t *testing.T, f fakeTF) {
		t.Helper()
		if err := os.WriteFile(f.bin, append(readFile(t, f.bin), "# swapped\n"...), 0o700); err != nil { //nolint:gosec // G306: an executable test fake
			t.Fatal(err)
		}
	}
	t.Run("between gate plan and apply", func(t *testing.T) {
		f, set := signedSet(t, inputs, linkedPlan)
		before := len(f.calls(t))
		swap(t, f)
		code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "apply"))
		if code != ExitEnvironment || !strings.Contains(msg, "not the terraform binary gate plan ran") {
			t.Fatalf("exit %d (%s)", code, msg)
		}
		noNewCalls(t, f, before)
	})
	t.Run("before the first version -json", func(t *testing.T) {
		f := newFakeTF(t, filepath.Join(gateFixtures, "show-companion-delete.json"), 0)
		out := filepath.Join(t.TempDir(), "candidate")
		plantOwned(t, func(string) { swap(t, f) })
		code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out))
		refused(t, code, msg, "not the pinned", f, out)
	})
	t.Run("apply: before the first version -json", func(t *testing.T) {
		f, set := signedSet(t, inputs, linkedPlan)
		before := len(f.calls(t))
		plantOwned(t, func(string) { swap(t, f) })
		code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "apply"))
		if code != ExitEnvironment || !strings.Contains(msg, "not the pinned") {
			t.Fatalf("exit %d (%s)", code, msg)
		}
		noNewCalls(t, f, before)
	})
	for _, cmd := range []string{"gate plan", "apply"} {
		t.Run(cmd+": replaced during version -json", func(t *testing.T) {
			evil := filepath.Join(t.TempDir(), "evil")
			f, set, before := newFakeTF(t, filepath.Join(gateFixtures, "show-companion-delete.json"), 0), "", 0
			args := gateArgs(inputs, f.bin, filepath.Join(t.TempDir(), "candidate"))
			if cmd == "apply" {
				f, set = signedSet(t, inputs, linkedPlan)
				before = len(f.calls(t))
				args = applyArgs(inputs, f.bin, set, "apply")
			}
			f.setHook(t, fmt.Sprintf("case \"$1\" in version) printf '#!/bin/sh\\n: > %s\\n' > @BIN@ ;; esac\n", evil))
			code, msg := runGate(applyCLI(t, inputs, signNow, signNow), args)
			if code != ExitEnvironment || !strings.Contains(msg, "terraform init") || !strings.Contains(msg, "not the pinned") {
				t.Fatalf("exit %d (%s)", code, msg)
			}
			if calls := f.calls(t)[before:]; !slices.Equal(calls, []string{"version -json"}) {
				t.Fatalf("calls %q, want version -json only", calls)
			}
			if _, err := os.Stat(evil); err == nil {
				t.Fatal("the replacement binary ran")
			}
		})
	}
}

// TestTFExecOwnedPaths: a symlink planted at the owned cwd, TF_DATA_DIR,
// HOME, TMPDIR, sealed dir or a CLI config path, before ctfkit creates it,
// exits 2 before terraform runs, in gate plan and in apply.
func TestTFExecOwnedPaths(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	for _, name := range []string{"cwd", "data", "home", "tmp", "sealed", "empty.tfrc", "mirror.tfrc"} {
		t.Run(name, func(t *testing.T) {
			target := t.TempDir()
			plant := func(root string) {
				if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
					t.Fatal(err)
				}
			}
			f := newFakeTF(t, filepath.Join(gateFixtures, "show-companion-delete.json"), 0)
			out := filepath.Join(t.TempDir(), "candidate")
			plantOwned(t, plant)
			code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out))
			refused(t, code, msg, "terraform run directory", f, out)

			tfexec.BeforeOwned = func(string) {}
			af, set := signedSet(t, inputs, linkedPlan)
			before := len(af.calls(t))
			tfexec.BeforeOwned = plant
			code, msg = runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, af.bin, set, "apply"))
			if code != ExitEnvironment || !strings.Contains(msg, "terraform run directory") {
				t.Fatalf("apply: exit %d (%s)", code, msg)
			}
			noNewCalls(t, af, before)
			if entries, _ := os.ReadDir(target); len(entries) != 0 {
				t.Fatalf("ctfkit wrote through the planted link: %v", entries)
			}
		})
	}
}

// TestTFExecEnv: every call of gate plan, gate sign and apply runs with the
// env table and nothing else, whatever the parent sets: no reattached
// provider, no parent CLI config, HOME or data dir (so no ~/.terraformrc
// dev_overrides), no LD_*, DYLD_*, CA or proxy variable (the profile names
// none), and no credential. Version and the first init run under the empty
// owned CLI config, every later call under the sealed-mirror one; neither
// holds a dev_overrides block.
func TestTFExecEnv(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".terraformrc")
	if err := os.WriteFile(rc, []byte("provider_installation {\n  dev_overrides {\n    \"bobthecorp/fake\" = \"/srv/bobthecorp/evil\"\n  }\n  direct {}\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"HOME": home, "TF_CLI_CONFIG_FILE": rc, "TERRAFORM_CONFIG": rc, "TF_DATA_DIR": home, "TF_PLUGIN_CACHE_DIR": home,
		"TF_LOG": "trace", "TF_WORKSPACE": "parent", "LD_PRELOAD": "/srv/bobthecorp/evil.so", "LD_AUDIT": "/srv/bobthecorp/evil.so",
		"DYLD_INSERT_LIBRARIES": "/srv/bobthecorp/evil.dylib", "SSL_CERT_FILE": "/srv/bobthecorp/evil.pem", "SSL_CERT_DIR": home,
		"HTTPS_PROXY": "http://proxy.bobthecorp.example:3128", "no_proxy": "localhost", "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
		"TF_REATTACH_PROVIDERS": `{"registry.terraform.io/bobthecorp/fake":{"Protocol":"grpc","Pid":1,"Test":true,"Addr":{"Network":"unix","String":"/srv/bobthecorp/evil.sock"}}}`,
	} {
		t.Setenv(k, v)
	}
	inputs := filepath.Join(gateInputs, "valid")
	f := newFakeTFSchema(t, linkedPlan, filepath.Join(gateCases, "schema.json"), 0)
	dump := filepath.Join(t.TempDir(), "cli-config")
	f.setHook(t, fmt.Sprintf("cat \"$TF_CLI_CONFIG_FILE\" >> %q\n", dump))
	set := planCandidate(t, inputs, f)
	if code, msg := runGate(signCLI(t, inputs, verdictKeyL), signArgs(inputs, f.bin, set)); code == ExitEnvironment {
		t.Fatalf("gate sign: exit 2: %s", msg)
	}
	if code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "apply")); code != ExitOK {
		t.Fatalf("apply: exit %d: %s", code, msg)
	}

	calls := f.calls(t)
	if len(calls) != 12 { // gate plan 5, gate sign 3, apply 4
		t.Fatalf("calls %q", calls)
	}
	absSet, _ := filepath.Abs(set)
	for i, c := range calls {
		vars := map[string]string{}
		for _, kv := range f.callEnv(t, i) {
			n, v, _ := strings.Cut(kv, "=")
			vars[n] = v
		}
		root := filepath.Dir(vars["TF_DATA_DIR"])
		cfg := "mirror.tfrc"
		if c == "version -json" || strings.Contains(c, " init ") {
			cfg = "empty.tfrc"
		}
		want := map[string]string{"PATH": "/usr/bin:/bin", "HOME": root + "/home", "TMPDIR": root + "/tmp",
			"TF_DATA_DIR": root + "/data", "TF_CLI_CONFIG_FILE": root + "/" + cfg, "TF_IN_AUTOMATION": "1", "TF_WORKSPACE": "default"}
		if strings.Contains(c, " apply ") {
			want[envVerdict] = filepath.Join(absSet, artifactStaged, artifactVerdict)
			want[envVerdictKeyFile] = filepath.Join(absSet, artifactStaged, artifactRunKey)
		}
		if !maps.Equal(vars, want) || !strings.HasPrefix(filepath.Base(root), "ctfkit-tf-") {
			t.Errorf("call %d (%s) env\n%v\nwant\n%v", i, c, vars, want)
		}
	}
	if b := string(readFile(t, dump)); strings.Contains(b, "dev_overrides") || strings.Count(b, "filesystem_mirror") != 6 { // 3 sessions, 2 calls each under the empty config
		t.Errorf("CLI configs the calls ran under:\n%s", b)
	}
}

// TestTFExecProviders: through gate plan, the provider the first init
// installs is sealed against the lock file, the mirror init runs
// -lockfile=readonly under the sealed-mirror CLI config and links the sealed
// copy, and plan runs that copy; a package the lock file does not record
// stops gate plan and apply after init, before any other call (exit 2).
func TestTFExecProviders(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	show := filepath.Join(gateFixtures, "show-companion-delete.json")
	t.Run("sealed and linked", func(t *testing.T) {
		f := newFakeTF(t, show, 0)
		dir := copyConfig(t, filepath.Join(gateFixtures, "config"))
		link := withFakeProvider(t, f, dir, "fake provider v1", "fake provider v1")
		out := filepath.Join(t.TempDir(), "candidate")
		if code, msg := runGate(gateCLI(t, inputs), withDir(gateArgs(inputs, f.bin, out), dir)); code != ExitOK {
			t.Fatalf("exit %d: %s", code, msg)
		}
		calls := f.calls(t)
		init := "-chdir=" + dir + " init -input=false -lockfile=readonly"
		if len(calls) != 6 || calls[1] != init || calls[2] != init {
			t.Fatalf("calls %q: want version, init, mirror init, schema, plan, show", calls)
		}
		for i := range calls {
			want := "mirror.tfrc"
			if i < 2 {
				want = "empty.tfrc"
			}
			if !slices.ContainsFunc(f.callEnv(t, i), func(kv string) bool {
				return strings.HasPrefix(kv, "TF_CLI_CONFIG_FILE=") && strings.HasSuffix(kv, "/"+want)
			}) {
				t.Errorf("call %d (%s) not under %s", i, calls[i], want)
			}
		}
		if target := strings.TrimSpace(string(readFile(t, link))); !strings.HasSuffix(target, "/sealed/providers/"+fakePkg) {
			t.Fatalf("plan ran the provider at %s, not the sealed copy", target)
		}
	})
	t.Run("not in the lock file", func(t *testing.T) {
		f := newFakeTF(t, show, 0)
		dir := copyConfig(t, filepath.Join(gateFixtures, "config"))
		withFakeProvider(t, f, dir, "another build", "fake provider v1")
		out := filepath.Join(t.TempDir(), "candidate")
		code, msg := runGate(gateCLI(t, inputs), withDir(gateArgs(inputs, f.bin, out), dir))
		if code != ExitEnvironment || !strings.Contains(msg, "lock file does not record") {
			t.Fatalf("exit %d (%s)", code, msg)
		}
		if calls := f.calls(t); len(calls) != 2 {
			t.Fatalf("calls %q: want version and init only", calls)
		}
		if inSet(out, "") {
			t.Fatal("--out exists")
		}
	})
	t.Run("apply: not in the lock file", func(t *testing.T) {
		f, set := signedSet(t, inputs, linkedPlan)
		before := len(f.calls(t))
		dir := copyConfig(t, signConfig)
		withFakeProvider(t, f, dir, "another build", "fake provider v1")
		code, msg := runGate(applyCLI(t, inputs, signNow, signNow), withDir(applyArgs(inputs, f.bin, set, "apply"), dir))
		if code != ExitEnvironment || !strings.Contains(msg, "lock file does not record") {
			t.Fatalf("exit %d (%s)", code, msg)
		}
		if calls := f.calls(t)[before:]; len(calls) != 2 {
			t.Fatalf("calls %q: want version and init only", calls)
		}
	})
}

// TestTFExecVerifyLock: verify-lock runs on the root before the first
// terraform call of gate plan and apply; a root without a lock file and each
// ctf.lock finding exit 2 before terraform runs.
func TestTFExecVerifyLock(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	edit := func(t *testing.T, path, from, to string) {
		t.Helper()
		b := readFile(t, path)
		if !strings.Contains(string(b), from) {
			t.Fatalf("%s has no %q", path, from)
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(b), from, to, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, dir string)
		want   string
	}{
		"no lock file": {func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, ".terraform.lock.hcl")); err != nil {
				t.Fatal(err)
			}
		}, "has no .terraform.lock.hcl"},
		"wrapper unhashed": {func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, ".terraform.lock.hcl"), `"zh:`, `"h1:`)
		}, "ctf.lock.wrapper_unhashed"},
		"upstream source": {func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "main.tf"), "registry.compliance.tf/compliancetf/aws", "hashicorp/aws")
		}, "ctf.lock.source_mismatch"},
		"other upstream provider": {func(t *testing.T, dir string) {
			lock := filepath.Join(dir, ".terraform.lock.hcl")
			b := append(readFile(t, lock), "\nprovider \"registry.terraform.io/hashicorp/google\" {\n  version = \"6.0.0\"\n}\n"...)
			if err := os.WriteFile(lock, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ".ctfkit.yaml"), []byte("wrapped_providers: [aws, google]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "ctf.lock.upstream_present"},
		// The gated repository cannot drop aws from the wrapped types it is checked for.
		"repository narrows the wrapped types": {func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "main.tf"), "registry.compliance.tf/compliancetf/aws", "hashicorp/aws")
			if err := os.WriteFile(filepath.Join(dir, ".ctfkit.yaml"), []byte("wrapped_providers: [google]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "ctf.lock.source_mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeTF(t, filepath.Join(gateFixtures, "show-companion-delete.json"), 0)
			dir := copyConfig(t, filepath.Join(gateFixtures, "config"))
			tc.mutate(t, dir)
			out := filepath.Join(t.TempDir(), "candidate")
			code, msg := runGate(gateCLI(t, inputs), withDir(gateArgs(inputs, f.bin, out), dir))
			refused(t, code, msg, tc.want, f, out)

			af, set := signedSet(t, inputs, linkedPlan)
			before := len(af.calls(t))
			dir = copyConfig(t, signConfig)
			tc.mutate(t, dir)
			code, msg = runGate(applyCLI(t, inputs, signNow, signNow), withDir(applyArgs(inputs, af.bin, set, "apply"), dir))
			if code != ExitEnvironment || !strings.Contains(msg, tc.want) {
				t.Fatalf("apply: exit %d (%s), want 2 (%s)", code, msg, tc.want)
			}
			noNewCalls(t, af, before)
		})
	}
}

// TestTFExecBoundUpstream: only ctf.lock.upstream_present on exactly the
// hashicorp/aws address of either registry is exempt; a
// lookalike address, another rule or another kind still refuses.
func TestTFExecBoundUpstream(t *testing.T) {
	finding := func(rule, addr, kind string) ctfkit.Finding {
		return ctfkit.Finding{RuleID: rule, Locations: []ctfkit.Location{{
			LogicalLocations: []ctfkit.LogicalLocation{{FullyQualifiedName: addr, Kind: kind}}}}}
	}
	const up, prov = "ctf.lock.upstream_present", ctfkit.LogicalLocationProvider
	for _, tc := range []struct {
		name string
		f    ctfkit.Finding
		want bool
	}{
		{"terraform registry", finding(up, `provider["registry.terraform.io/hashicorp/aws"]`, prov), true},
		{"opentofu registry", finding(up, `provider["registry.opentofu.org/hashicorp/aws"]`, prov), true},
		{"other host", finding(up, `provider["example.com/hashicorp/aws"]`, prov), false},
		{"lookalike namespace", finding(up, `provider["registry.terraform.io/xhashicorp/aws"]`, prov), false},
		{"lookalike type", finding(up, `provider["registry.terraform.io/hashicorp/aws-extra"]`, prov), false},
		{"nested address", finding(up, `provider["evil/registry.terraform.io/hashicorp/aws"]`, prov), false},
		{"other wrapped type", finding(up, `provider["registry.terraform.io/hashicorp/google"]`, prov), false},
		{"other rule", finding("ctf.lock.unwrapped", `provider["registry.terraform.io/hashicorp/aws"]`, prov), false},
		{"other kind", finding(up, `provider["registry.terraform.io/hashicorp/aws"]`, "resource"), false},
		{"no location", ctfkit.Finding{RuleID: up}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := boundUpstream(tc.f); got != tc.want {
				t.Fatalf("boundUpstream = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTFExecPlanfileWrite:terraform shows and applies only the sealed copy,
// so a write to the original planfile while terraform runs changes neither
// the candidate gate plan writes nor what apply applies.
func TestTFExecPlanfileWrite(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	t.Run("gate plan", func(t *testing.T) {
		f := newFakeTF(t, filepath.Join(gateFixtures, "show-companion-delete.json"), 0)
		mark := filepath.Join(t.TempDir(), "written")
		f.setHook(t, fmt.Sprintf("case \"$2\" in show) printf tampered > \"${4%%/sealed/planfile}/planfile\" && : > %q ;; esac\n", mark))
		out := filepath.Join(t.TempDir(), "candidate")
		if code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out)); code != ExitOK {
			t.Fatalf("exit %d: %s", code, msg)
		}
		if _, err := os.Stat(mark); err != nil {
			t.Fatal("the hook did not write the owned planfile")
		}
		if b := readFile(t, filepath.Join(out, artifactPlanfile)); string(b) != "fake planfile" {
			t.Fatalf("candidate planfile %q", b)
		}
	})
	t.Run("apply", func(t *testing.T) {
		f, set := signedSet(t, inputs, linkedPlan)
		mark := filepath.Join(t.TempDir(), "written")
		f.setHook(t, fmt.Sprintf("case \"$2\" in show) printf tampered > %q && : > %q ;; esac\n", filepath.Join(set, artifactPlanfile), mark))
		code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "apply"))
		if _, err := os.Stat(mark); err != nil {
			t.Fatalf("the hook did not write the set's planfile (exit %d: %s)", code, msg)
		}
		if b := readFile(t, f.applied); string(b) != "fake planfile" {
			t.Fatalf("apply applied %q (exit %d: %s)", b, code, msg)
		}
		if code != ExitOK {
			t.Fatalf("exit %d: %s", code, msg)
		}
	})
}
