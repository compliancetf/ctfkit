package cli

import (
	"bytes"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// transfer moves an artifact set the way the GitHub template does: upload
// and download keep the bytes and drop the modes, leaving a 0755 directory
// of 0644 files, and the action's permission step (adapters/github/action.yml,
// run as written) restores 0700 and 0600. It returns the new directory.
func transfer(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "ctfkit-artifacts")
	if err := os.Mkdir(dst, 0o755); err != nil { //nolint:gosec // the mode a download leaves
		t.Fatal(err)
	}
	for name, b := range readSet(t, src) {
		if err := os.WriteFile(filepath.Join(dst, name), b, 0o644); err != nil { //nolint:gosec // the mode a download leaves
			t.Fatal(err)
		}
	}
	var action struct {
		Runs struct {
			Steps []struct{ Name, Run string } `yaml:"steps"`
		} `yaml:"runs"`
	}
	raw, err := os.ReadFile("../../adapters/github/action.yml")
	if err == nil {
		err = yaml.Unmarshal(raw, &action)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range action.Runs.Steps {
		if s.Name != "Restore the artifact set permissions" {
			continue
		}
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", s.Run)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "CTFKIT_ARTIFACTS=" + dst}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("permission step: %v\n%s", err, out)
		}
		return dst
	}
	t.Fatal("action.yml has no permission step")
	return ""
}

func readSet(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string][]byte{}
	for _, e := range entries {
		if set[e.Name()], err = os.ReadFile(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

// movedSignedSet runs gate plan, moves the candidate to the sign job, signs
// it there and moves the signed set to the apply job.
func movedSignedSet(t *testing.T, inputs string) (fakeTF, string) {
	t.Helper()
	f := newFakeTFSchema(t, filepath.Join(gateCases, "linked-create", "plan.json"), filepath.Join(gateCases, "schema.json"), 0)
	candidate := transfer(t, planCandidate(t, inputs, f))
	if code, msg := runGate(signCLI(t, inputs, verdictKeyL), signArgs(inputs, f.bin, candidate)); code != ExitOK {
		t.Fatalf("gate sign on the moved candidate: exit %d: %s", code, msg)
	}
	signed := transfer(t, candidate)
	if !maps.EqualFunc(readSet(t, candidate), readSet(t, signed), bytes.Equal) {
		t.Fatal("the signed set changed in transfer")
	}
	return f, signed
}

// TestArtifactSetMovesBetweenJobs: the set gate plan wrote reaches gate sign
// and then ctfkit apply unchanged over two transfers, and applies.
func TestArtifactSetMovesBetweenJobs(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	f, signed := movedSignedSet(t, inputs)
	if code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, signed, "verdict", "verify")); code != ExitOK {
		t.Fatalf("verdict verify: exit %d: %s", code, msg)
	}
	if code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, signed, "apply")); code != ExitOK {
		t.Fatalf("apply: exit %d: %s", code, msg)
	}
	consumed(t, signed, outcomeEnforced)
}

// TestArtifactSetTamperedInTransfer: a set that arrives with one file
// changed, one missing or one extra is refused (exit 2) by verdict verify.
func TestArtifactSetTamperedInTransfer(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	f, signed := movedSignedSet(t, inputs)
	type edit func(t *testing.T, set string)
	cases := map[string]edit{
		"extra file": func(t *testing.T, set string) {
			if err := os.WriteFile(filepath.Join(set, "extra"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"missing file": func(t *testing.T, set string) {
			if err := os.Remove(filepath.Join(set, artifactSchema)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name := range readSet(t, signed) {
		cases["changed "+name] = func(t *testing.T, set string) {
			p := filepath.Join(set, name)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b[len(b)/2] ^= 1
			if err = os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			set := transfer(t, signed)
			tamper(t, set)
			if code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "verdict", "verify")); code != ExitEnvironment {
				t.Fatalf("verdict verify: exit %d (%s), want 2", code, msg)
			}
		})
	}
}
