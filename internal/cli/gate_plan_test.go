package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
	keyjson "github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
)

const (
	gateInputs   = "../../pkg/verdict/testdata/inputs"
	gateFixtures = "testdata/gate-plan"
	goldenDir    = "../../pkg/verdict/testdata/instancekey"
)

// fakeTF is a fake terraform: it logs each argv line, answers version -json,
// prints schema for providers schema -json (exit 1 when schema is absent),
// writes "fake planfile" to the -out path (or exits planExit), records the
// plan call's env and prints show for show -json. For apply it records
// the child env and the planfile it was given, sleeps after touching
// applyExit.started when applyExit.sleep exists, and exits with the code in
// applyExit when that file exists. Every call also records its sorted env as
// envs.<n> and, when hook exists, sources it with the call's argv first.
type fakeTF struct {
	bin, log, env                string
	applyEnv, applied, applyExit string
	envs, hook                   string
}

func newFakeTF(t *testing.T, show string, planExit int) fakeTF {
	t.Helper()
	return newFakeTFSchema(t, show, filepath.Join(gateFixtures, "schema.json"), planExit)
}

func newFakeTFSchema(t *testing.T, show, schema string, planExit int) fakeTF {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake terraform is a shell script")
	}
	show, err := filepath.Abs(show)
	if err != nil {
		t.Fatal(err)
	}
	if schema, err = filepath.Abs(schema); err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	f := fakeTF{bin: filepath.Join(d, "terraform"), log: filepath.Join(d, "argv.log"), env: filepath.Join(d, "env.log"),
		applyEnv: filepath.Join(d, "apply-env.log"), applied: filepath.Join(d, "applied"), applyExit: filepath.Join(d, "apply.exit"),
		envs: filepath.Join(d, "envs"), hook: filepath.Join(d, "hook.sh")}
	script := fmt.Sprintf(`#!/bin/sh
n=$(wc -l < %[1]q 2>/dev/null || echo 0); n=$((n+0))
printf '%%s\n' "$*" >> %[1]q
env | sort > %[2]q.$n
[ -f %[3]q ] && . %[3]q
`, f.log, f.envs, f.hook) + fmt.Sprintf(`case "$1" in version) echo '{"terraform_version":"1.16.3"}'; exit 0 ;; esac
case "$2" in
plan) env > %q; [ %d -eq 0 ] || exit %d
  for a; do case "$a" in -out=*) printf 'fake planfile' > "${a#-out=}" ;; esac; done ;;
show) cat %q ;;
providers) cat %q ;;
apply) env > %q; cat "$4" > %q; [ -f %q.sleep ] && { : > %q.started; sleep 60; }; [ -f %q ] && exit "$(cat %q)"; exit 0 ;;
esac
`, f.env, planExit, planExit, show, schema, f.applyEnv, f.applied, f.applyExit, f.applyExit, f.applyExit, f.applyExit)
	if err := os.WriteFile(f.bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: an executable test fake
		t.Fatal(err)
	}
	return f
}

// calls is the logged argv lines, none when terraform never ran.
func (f fakeTF) calls(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// callEnv is the sorted env of call i, without the variables the shell sets
// itself (PWD, SHLVL, _, OLDPWD).
func (f fakeTF) callEnv(t *testing.T, i int) []string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("%s.%d", f.envs, i))
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains([]string{"PWD", "SHLVL", "_", "OLDPWD"}, name)
	})
}

func gateCLI(t *testing.T, inputs string) *CLI {
	t.Helper()
	c := New("test")
	kr, err := os.ReadFile(filepath.Join(inputs, "keyring.json"))
	if err != nil {
		t.Fatal(err)
	}
	c.keyring = kr
	c.now = func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) }
	return c
}

// gateContentDigest is the content digest of an inputs case.
func gateContentDigest(t *testing.T, inputs string) string {
	t.Helper()
	in, err := verdict.ReadInputs(os.DirFS(inputs), "bobthecorp", "keyring.json", "profile.dsse.json", "floor.dsse.json", "bundles")
	if err != nil {
		t.Fatal(err)
	}
	v, err := verdict.VerifyInputs(in, time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	d, err := verdict.ContentDigest(v)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func gateArgs(inputs, tf, out string, extra ...string) []string {
	return append([]string{"gate", "plan", "--dir", filepath.Join(gateFixtures, "config"), "--out", out,
		"--workspace", "default", "--environment", "prod", "--tf-bin", tf, "--org", "bobthecorp",
		"--profile", filepath.Join(inputs, "profile.dsse.json"), "--floor", filepath.Join(inputs, "floor.dsse.json"),
		"--bundle-dir", filepath.Join(inputs, "bundles")}, extra...)
}

func runGate(c *CLI, args []string) (int, string) {
	var out bytes.Buffer
	c.rootCmd.SetArgs(args)
	c.rootCmd.SetOut(&out)
	c.rootCmd.SetErr(&out)
	err := c.Execute()
	if err != nil {
		return ExitCode(err), err.Error()
	}
	return ExitOK, ""
}

// refused asserts exit 2 for the reason want names, with terraform never
// run and no artifact dir.
func refused(t *testing.T, code int, msg, want string, f fakeTF, out string) {
	t.Helper()
	if code != ExitEnvironment || !strings.Contains(msg, want) {
		t.Fatalf("exit %d (%s), want 2 (%s)", code, msg, want)
	}
	if calls := f.calls(t); calls != nil {
		t.Fatalf("terraform ran: %q", calls)
	}
	if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("--out %s exists after a refusal", out)
	}
}

// TestGatePlanRejectsFlags: no terraform flag passes through and no caller
// plan JSON is read, so a benign plan JSON next to a companion-deletion
// planfile cannot stand in for it; nothing is consumed, no break-glass flag.
func TestGatePlanRejectsFlags(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	benign := filepath.Join(gateFixtures, "benign.json")
	for name, extra := range map[string][]string{
		"target":        {"-target=aws_s3_bucket.logs"},
		"target-long":   {"--target=aws_s3_bucket.logs"},
		"exclude":       {"--exclude=aws_s3_bucket_public_access_block.logs"},
		"replace":       {"--replace=aws_s3_bucket.logs"},
		"refresh-false": {"--refresh=false"},
		"refresh-only":  {"--refresh-only"},
		"pass-through":  {"--", "-target=aws_s3_bucket.logs"},
		"plan-json":     {"--plan", benign},
		"positional":    {benign},
		"break-glass":   {"--break-glass", benign},
		"schema":        {"--schema", filepath.Join(gateFixtures, "schema.json")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeTF(t, filepath.Join(gateFixtures, "show-companion-delete.json"), 0)
			out := filepath.Join(t.TempDir(), "candidate")
			code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out, extra...))
			want := "unknown"
			if name == "positional" || name == "pass-through" {
				want = "which takes none"
			}
			refused(t, code, msg, want, f, out)
		})
	}
}

func TestGatePlanRejectsTFCLIArgs(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	for _, name := range []string{"TF_CLI_ARGS", "TF_CLI_ARGS_plan"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "-refresh=false")
			f := newFakeTF(t, filepath.Join(gateFixtures, "show-companion-delete.json"), 0)
			out := filepath.Join(t.TempDir(), "candidate")
			code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out))
			refused(t, code, msg, name+" is set", f, out)
		})
	}
}

// TestGatePlanRefusesBeforeTerraform: signed inputs that fail verification
// and an existing --out stop the run before terraform starts.
func TestGatePlanRefusesBeforeTerraform(t *testing.T) {
	show := filepath.Join(gateFixtures, "show-companion-delete.json")
	t.Run("altered-graph-rule", func(t *testing.T) {
		inputs := filepath.Join(gateInputs, "altered-graph-rule")
		f := newFakeTF(t, show, 0)
		out := filepath.Join(t.TempDir(), "candidate")
		code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out))
		refused(t, code, msg, "graph.json: digest mismatch", f, out)
	})
	t.Run("out-exists", func(t *testing.T) {
		inputs := filepath.Join(gateInputs, "valid")
		f := newFakeTF(t, show, 0)
		out := t.TempDir()
		code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out))
		if code != ExitEnvironment || f.calls(t) != nil {
			t.Fatalf("exit %d (%s), calls %q", code, msg, f.calls(t))
		}
	})
}

// TestGatePlanTerraformOutcomes: an unknown plan JSON format_version is
// refused and a failing terraform plan is a gate fail; neither leaves --out.
func TestGatePlanTerraformOutcomes(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	for name, tc := range map[string]struct {
		show     string
		planExit int
		want     int
	}{
		"unknown-format-version": {"show-format-1.3.json", 0, ExitEnvironment},
		"plan-fails":             {"show-companion-delete.json", 1, ExitFindings},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeTF(t, filepath.Join(gateFixtures, tc.show), tc.planExit)
			out := filepath.Join(t.TempDir(), "candidate")
			code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out))
			if code != tc.want {
				t.Fatalf("exit %d (%s), want %d", code, msg, tc.want)
			}
			if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("--out exists")
			}
		})
	}
}

// TestGatePlanArtifactSet: the candidate holds exactly planfile, schema.json,
// ctfkit-run.key, findings.sarif and candidate.json at 0600 in a 0700 dir,
// candidate.json binds their raw digests, the run key parses, terraform ran
// exactly the five argv rows with an env of only what gate plan sets.
func TestGatePlanArtifactSet(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	t.Setenv("CTFKIT_GATE_PARENT_MARK", "1")
	f := newFakeTF(t, filepath.Join(gateFixtures, "show-companion-delete.json"), 0)
	out := filepath.Join(t.TempDir(), "candidate")
	if code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out)); code != ExitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}

	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("--out mode: %v %v", st, err)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, e := range entries {
		info, ierr := e.Info()
		if ierr != nil || info.Mode() != 0o600 {
			t.Fatalf("%s: mode %v (%v), want -rw-------", e.Name(), info, ierr)
		}
		if files[e.Name()], err = os.ReadFile(filepath.Join(out, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	names := slices.Sorted(func(yield func(string) bool) {
		for n := range files {
			if !yield(n) {
				return
			}
		}
	})
	if want := []string{artifactCandidate, artifactRunKey, artifactFindings, artifactPlanfile, artifactSchema}; !slices.Equal(names, want) {
		t.Fatalf("artifact set %q, want %q", names, want)
	}
	if _, err = instancekey.ParseSecret(files[artifactRunKey]); err != nil {
		t.Fatalf("run key: %v", err)
	}
	if !json.Valid(files[artifactFindings]) {
		t.Fatal("findings.sarif is not JSON")
	}

	canon, err := jcs.Transform(files[artifactCandidate])
	if err != nil || !bytes.Equal(canon, files[artifactCandidate]) {
		t.Fatalf("candidate.json is not JCS: %v", err)
	}
	var cand candidate
	if err = json.Unmarshal(canon, &cand); err != nil {
		t.Fatal(err)
	}
	digest := func(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
	wantArtifacts := map[string]string{}
	for _, n := range []string{artifactPlanfile, artifactRunKey, artifactFindings, artifactSchema} {
		wantArtifacts[n] = digest(files[n])
	}
	switch {
	case string(files[artifactPlanfile]) != "fake planfile":
		t.Errorf("planfile %q", files[artifactPlanfile])
	case cand.PlanDigest != digest([]byte("fake planfile")):
		t.Errorf("plan_digest %s", cand.PlanDigest)
	case fmt.Sprint(cand.Artifacts) != fmt.Sprint(wantArtifacts):
		t.Errorf("artifacts %v, want %v", cand.Artifacts, wantArtifacts)
	case cand.Format != candidateFormat || cand.Kind != "plan" || cand.OrgID != "bobthecorp":
		t.Errorf("header %+v", cand)
	case cand.ContentDigest != gateContentDigest(t, filepath.Join(gateInputs, "valid")) || cand.FloorEpoch != "7" || cand.PlanFormatVersion != "1.2":
		t.Errorf("binding %s %s %s", cand.ContentDigest, cand.FloorEpoch, cand.PlanFormatVersion)
	case cand.Workspace != "default" || cand.Environment != "prod" || cand.Provenance.Workspace != "default":
		t.Errorf("scope %s %s %s", cand.Workspace, cand.Environment, cand.Provenance.Workspace)
	case cand.TerraformVersion != "1.16.3" || cand.Provenance.Refresh != "true" || cand.Provenance.Targeted != "false":
		t.Errorf("provenance %+v", cand.Provenance)
	}
	tfBin, _ := os.ReadFile(f.bin)
	if cand.TerraformDigest != digest(tfBin) {
		t.Errorf("terraform_digest %s", cand.TerraformDigest)
	}
	schema, _ := os.ReadFile(filepath.Join(gateFixtures, "schema.json"))
	if !bytes.Equal(files[artifactSchema], schema) || cand.SchemaDigest != digest(schema) {
		t.Errorf("schema.json or schema_digest %s", cand.SchemaDigest)
	}
	// The no-op bucket gets no entry; the deleted access block keys by id.
	if len(cand.Instances) != 1 || cand.Instances[0].Address != "aws_s3_bucket_public_access_block.logs" ||
		len(cand.Instances[0].Keys) != 1 || cand.Instances[0].Keys[0].Field != "delete_key" ||
		cand.Instances[0].Keys[0].PriorIdentityKind != "id" {
		t.Errorf("instances %+v", cand.Instances)
	}
	checkKeys(t, files[artifactRunKey], filepath.Join(gateFixtures, "show-companion-delete.json"),
		filepath.Join(gateFixtures, "schema.json"), cand.Instances)

	calls := f.calls(t)
	dir, _ := filepath.Abs(filepath.Join(gateFixtures, "config"))
	if len(calls) != 5 {
		t.Fatalf("terraform calls %q", calls)
	}
	planOut := strings.TrimPrefix(calls[3], "-chdir="+dir+" plan -input=false -out=")
	root := strings.TrimSuffix(planOut, "/planfile")
	want := []string{
		"version -json",
		"-chdir=" + dir + " init -input=false -lockfile=readonly",
		"-chdir=" + dir + " providers schema -json",
		"-chdir=" + dir + " plan -input=false -out=" + root + "/planfile",
		"-chdir=" + dir + " show -json " + root + "/sealed/planfile",
	}
	if !slices.Equal(calls, want) || root == planOut {
		t.Fatalf("calls %q, want %q", calls, want)
	}
	argv, _ := json.Marshal([]string{"<tf>", "-chdir=<dir>", "plan", "-input=false", "-out=<owned>/planfile"})
	if argv, _ = jcs.Transform(argv); cand.Provenance.ArgvDigest != digest(argv) {
		t.Errorf("argv_digest %s", cand.Provenance.ArgvDigest)
	}
	if _, err = os.Stat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("owned run root %s left behind", root)
	}

	env, err := os.ReadFile(f.env)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{"PATH", "HOME", "TMPDIR", "TF_DATA_DIR", "TF_CLI_CONFIG_FILE", "TF_IN_AUTOMATION", "TF_WORKSPACE", "PWD", "SHLVL", "_", "OLDPWD"}
	for _, line := range strings.Split(strings.TrimSpace(string(env)), "\n") {
		if name, _, _ := strings.Cut(line, "="); !slices.Contains(allowed, name) {
			t.Errorf("child env has %s", name)
		}
	}
	if !strings.Contains(string(env), "TF_WORKSPACE=default\n") {
		t.Error("child env lacks TF_WORKSPACE=default")
	}
}

// checkKeys recomputes every key of show under the run key with the tfjson
// adapter and compares it with the candidate's.
func checkKeys(t *testing.T, runKey []byte, show, schema string, got []candidateEntry) {
	t.Helper()
	secret, err := instancekey.ParseSecret(runKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, _ := instancekey.Keys(secret)
	plan, _ := os.ReadFile(show)
	raw, _ := os.ReadFile(schema)
	schemas, err := keyjson.ParseSchemas(raw)
	if err != nil {
		t.Fatal(err)
	}
	insts, err := keyjson.Instances(leaf, plan, schemas)
	if err != nil || len(insts) != len(got) {
		t.Fatalf("%d instances (%v), candidate has %d", len(insts), err, len(got))
	}
	for i, in := range insts {
		if len(in.Keys) != len(got[i].Keys) {
			t.Fatalf("%s: %d keys, candidate has %d", in.Address, len(in.Keys), len(got[i].Keys))
		}
		for j, k := range in.Keys {
			if got[i].Keys[j].Key != k.Key {
				t.Errorf("%s %s: key %s, want %s", in.Address, k.Field, got[i].Keys[j].Key, k.Key)
			}
		}
	}
}

// TestGatePlanInstanceKeys: on every instance key golden, candidate.json
// lists the golden's entries (address, deposed, actions, action_reason and
// per key field, form, prior_identity_kind and unknown_paths) in plan order,
// each key computed under the run key the set holds.
func TestGatePlanInstanceKeys(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	dirs, err := filepath.Glob(filepath.Join(goldenDir, "aws_*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("goldens: %v", err)
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			show, schema := filepath.Join(dir, "plan.json"), filepath.Join(dir, "schema.json")
			f := newFakeTFSchema(t, show, schema, 0)
			out := filepath.Join(t.TempDir(), "candidate")
			if code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out)); code != ExitOK {
				t.Fatalf("exit %d: %s", code, msg)
			}
			b, err := os.ReadFile(filepath.Join(out, artifactCandidate))
			if err != nil {
				t.Fatal(err)
			}
			var cand struct {
				Format    string            `json:"format"`
				Instances []json.RawMessage `json:"instances"`
			}
			if err = json.Unmarshal(b, &cand); err != nil || cand.Format != candidateFormat {
				t.Fatalf("candidate %s: %v", cand.Format, err)
			}
			var golden struct {
				Entries []map[string]any `json:"entries"`
			}
			g, _ := os.ReadFile(filepath.Join(dir, "expected.json"))
			if err = json.Unmarshal(g, &golden); err != nil {
				t.Fatal(err)
			}
			if len(cand.Instances) != len(golden.Entries) {
				t.Fatalf("%d instances, golden has %d", len(cand.Instances), len(golden.Entries))
			}
			for i, raw := range cand.Instances {
				var got map[string]any
				if err = json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				want := golden.Entries[i]
				for _, m := range []map[string]any{got, want} {
					for _, k := range m["keys"].([]any) {
						delete(k.(map[string]any), "key") // the golden key uses the test secret
					}
				}
				if gj, wj := mustJSON(t, got), mustJSON(t, want); gj != wj {
					t.Errorf("entry %d:\n got %s\nwant %s", i, gj, wj)
				}
			}
			var entries struct {
				Instances []candidateEntry `json:"instances"`
			}
			_ = json.Unmarshal(b, &entries)
			key, _ := os.ReadFile(filepath.Join(out, artifactRunKey))
			checkKeys(t, key, show, schema, entries.Instances)
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestGatePlanRefusesInstance: an instance the key format refuses (here the
// _edge golden's refused entries) is a refusal of the run: exit 2, every
// refused address named, no --out.
func TestGatePlanRefusesInstance(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	dir := filepath.Join(goldenDir, "_edge")
	f := newFakeTFSchema(t, filepath.Join(dir, "plan.json"), filepath.Join(dir, "schema.json"), 0)
	out := filepath.Join(t.TempDir(), "candidate")
	code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out))
	if code != ExitEnvironment || !strings.Contains(msg, "instance keys refused") {
		t.Fatalf("exit %d (%s), want 2", code, msg)
	}
	for _, addr := range []string{"edge_thing.noid", "edge_thing.noschema", "edge_thing.depnoop", "edge_thing.depbad"} {
		if !strings.Contains(msg, addr) {
			t.Errorf("message does not name %s: %s", addr, msg)
		}
	}
	if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("--out exists after a refused instance")
	}
}

// TestGatePlanRefusesSchema: a providers schema -json that fails or prints
// non-strict JSON stops the run before terraform plan, with no --out.
func TestGatePlanRefusesSchema(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	show := filepath.Join(gateFixtures, "show-companion-delete.json")
	dup := filepath.Join(t.TempDir(), "dup.json")
	if err := os.WriteFile(dup, []byte(`{"provider_schemas":{},"provider_schemas":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ schema, want string }{
		"duplicate-key": {dup, "duplicate"},
		"fails":         {filepath.Join(t.TempDir(), "none.json"), "exit status 1"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeTFSchema(t, show, tc.schema, 0)
			out := filepath.Join(t.TempDir(), "candidate")
			code, msg := runGate(gateCLI(t, inputs), gateArgs(inputs, f.bin, out))
			if code != ExitEnvironment || !strings.Contains(msg, "providers schema -json: ") || !strings.Contains(msg, tc.want) {
				t.Fatalf("exit %d (%s), want 2 (%s)", code, msg, tc.want)
			}
			if calls := f.calls(t); len(calls) != 3 || !strings.HasSuffix(calls[2], " providers schema -json") {
				t.Fatalf("terraform calls %q, want plan never run", calls)
			}
			if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("--out exists after a refused schema")
			}
		})
	}
}

// TestGatePlanRealTerraform runs gate plan with the binary CTFKIT_TEST_TF
// names (terraform or tofu) on a provider-free configuration.
func TestGatePlanRealTerraform(t *testing.T) {
	tf := os.Getenv("CTFKIT_TEST_TF")
	if tf == "" {
		t.Skip("CTFKIT_TEST_TF is not set")
	}
	inputs := filepath.Join(gateInputs, "valid")
	cfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg, "main.tf"), []byte(`resource "terraform_data" "a" { input = "x" }`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No provider to lock, but gate plan needs the lock file all the same.
	if err := os.WriteFile(filepath.Join(cfg, ".terraform.lock.hcl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "candidate")
	args := gateArgs(inputs, tf, out)
	args[3] = cfg
	if code, msg := runGate(gateCLI(t, inputs), args); code != ExitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	b, err := os.ReadFile(filepath.Join(out, artifactCandidate))
	if err != nil {
		t.Fatal(err)
	}
	var cand candidate
	if err = json.Unmarshal(b, &cand); err != nil {
		t.Fatal(err)
	}
	// gate plan ran providers schema -json itself: schema.json is its output.
	schema, err := os.ReadFile(filepath.Join(out, artifactSchema))
	if err != nil || !json.Valid(schema) || !bytes.Contains(schema, []byte(`"terraform_data"`)) ||
		cand.SchemaDigest != rawDigest(schema) || cand.Artifacts[artifactSchema] != cand.SchemaDigest {
		t.Fatalf("schema.json (%v): schema_digest %s, artifacts %v", err, cand.SchemaDigest, cand.Artifacts)
	}
	if cand.Format != candidateFormat || len(cand.Instances) != 1 || cand.Instances[0].Address != "terraform_data.a" ||
		len(cand.Instances[0].Keys) != 1 || cand.Instances[0].Keys[0].Form != "create" ||
		!strings.HasPrefix(cand.Instances[0].Keys[0].Key, "sha256:") {
		t.Fatalf("candidate %s: instances %+v", cand.Format, cand.Instances)
	}
}

// TestGatePlanReleaseKeyring: the embedded trust anchor parses, so a release
// gate plan never runs with an empty or broken keyring.
func TestGatePlanReleaseKeyring(t *testing.T) {
	if _, err := verdict.ParseKeyring(releaseKeyring); err != nil {
		t.Fatalf("release keyring: %v", err)
	}
}

// io.Copy, which os/exec uses for a non-file Stdout, prefers ReadFrom over
// Write; capped must not offer it or the output cap is bypassed.
func TestCappedHasNoReadFrom(t *testing.T) {
	if _, ok := any(&capped{}).(io.ReaderFrom); ok {
		t.Fatal("capped implements io.ReaderFrom")
	}
}

// capped refuses a write past its own limit, so the schema cap and the plan
// cap stay separate.
func TestCappedLimit(t *testing.T) {
	c := capped{limit: 4}
	if _, err := c.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("e")); err == nil {
		t.Fatal("write past the limit accepted")
	}
}
