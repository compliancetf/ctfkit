// Package repo_test holds repository-level guards for CI configuration
// (ported from the terraform-provider-aws workflow pins guard).
package repo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	usesRe     = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
	shaPinRe   = regexp.MustCompile(`@[0-9a-f]{40}$`)
	tagNoteRe  = regexp.MustCompile(`@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$`)
	localUseRe = regexp.MustCompile(`^-?\s*uses:\s*\./[A-Za-z0-9._/-]+$`)
	floatingRe = regexp.MustCompile(`(?m)(@latest\b|^\s*[\w-]*version:\s*["']?latest["']?\s*(#.*)?$)`)
	// Events any workflow may use; anything else needs an owner-approved
	// entry in allowedTriggers.
	anyTrigger = map[string]bool{"workflow_dispatch": true, "schedule": true}
	// The owner-approved triggers as they stand; a new push, pull_request or
	// other event needs an entry here, and this file is a protected path.
	allowedTriggers = map[string]bool{
		".github/workflows/release.yml push":                        true,
		".github/workflows/release-please.yml push":                 true,
		".github/workflows/test.yml push":                           true,
		".github/workflows/test.yml pull_request":                   true,
		".github/workflows/protected-paths.yml pull_request_target": true,
		".github/workflows/protected-paths.yml workflow_run":        true,
		".github/workflows/owner-review.yml pull_request_review":    true,
		".github/workflows/pr-title.yml pull_request":               true,
	}
)

type workflow struct {
	On          yaml.Node              `yaml:"on"`
	Permissions yaml.Node              `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Uses  string `yaml:"uses"` // a reusable workflow call
	Steps []struct {
		Uses string         `yaml:"uses"`
		With map[string]any `yaml:"with"`
	} `yaml:"steps"`
}

// triggers lists the event names of an on: value in any of its forms
// (scalar, sequence or mapping).
func triggers(n yaml.Node) []string {
	switch n.Kind {
	case yaml.AliasNode:
		return triggers(*n.Alias)
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, triggers(*c)...)
		}
		return out
	case yaml.MappingNode:
		var out []string
		for i := 0; i < len(n.Content); i += 2 {
			out = append(out, triggers(*n.Content[i])...)
		}
		return out
	}
	return nil
}

// TestWorkflowPins fails when any workflow uses a remote action by tag or
// without a "# vX.Y.Z" note, checks out with persisted credentials, downloads
// a tool at a floating version, leaves the token scope implicit, or adds a
// trigger the owner has not approved.
func TestWorkflowPins(t *testing.T) {
	files, err := filepath.Glob(".github/workflows/*.y*ml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var wf workflow
		if err := yaml.Unmarshal(b, &wf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			l := strings.TrimSpace(line)
			local := localUseRe.MatchString(l) && !strings.Contains(l, "..")
			if usesRe.MatchString(line) && !tagNoteRe.MatchString(l) && !local {
				t.Errorf("%s: %q is not pinned to a commit SHA with a \"# vX.Y.Z\" note", f, l)
			}
		}
		for name, job := range wf.Jobs {
			if job.Uses != "" && !shaPinRe.MatchString(job.Uses) {
				t.Errorf("%s: job %s: reusable workflow %s is not pinned to a commit SHA", f, name, job.Uses)
			}
			for _, st := range job.Steps {
				local := strings.HasPrefix(st.Uses, "./") && !strings.Contains(st.Uses, "..")
				if st.Uses != "" && !local && !shaPinRe.MatchString(st.Uses) {
					t.Errorf("%s: job %s: %s is not pinned to a commit SHA", f, name, st.Uses)
				}
				if strings.HasPrefix(strings.ToLower(st.Uses), "actions/checkout@") && st.With["persist-credentials"] != false {
					t.Errorf("%s: job %s: actions/checkout without persist-credentials: false", f, name)
				}
				for k, v := range st.With {
					if strings.HasSuffix(k, "version") && v == "latest" {
						t.Errorf("%s: job %s: %s: latest is a floating tool version", f, name, k)
					}
				}
			}
		}
		for _, m := range floatingRe.FindAll(b, -1) {
			t.Errorf("%s: floating tool version %q", f, m)
		}
		if wf.Permissions.Kind == 0 {
			t.Errorf("%s: no top-level permissions block", f)
		}
		ev := triggers(wf.On)
		if len(ev) == 0 {
			t.Errorf("%s: no on: triggers", f)
		}
		for _, e := range ev {
			if !anyTrigger[e] && !allowedTriggers[f+" "+e] {
				t.Errorf("%s: %s trigger is not owner-approved", f, e)
			}
		}
	}
}

// TestActionPins: every remote uses: in a composite action (action.yml)
// is pinned to a commit SHA with a "# vX.Y.Z" note, as in the workflows.
func TestActionPins(t *testing.T) {
	var actions []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if !d.IsDir() && (d.Name() == "action.yml" || d.Name() == "action.yaml") {
			actions = append(actions, path)
		}
		return nil
	})
	if err != nil || len(actions) == 0 {
		t.Fatalf("no composite actions found: %v", err)
	}
	for _, f := range actions {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			l := strings.TrimSpace(line)
			local := localUseRe.MatchString(l) && !strings.Contains(l, "..")
			if usesRe.MatchString(line) && !tagNoteRe.MatchString(l) && !local {
				t.Errorf("%s: %q is not pinned to a commit SHA with a \"# vX.Y.Z\" note", f, l)
			}
		}
	}
}

// TestProtectedPathsSelfTest runs the protected-paths classifier self-test,
// so make test and CI cover the rules file and the script.
func TestProtectedPathsSelfTest(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	out, err := exec.Command("bash", "scripts/protected-paths.sh", "--self-test").CombinedOutput()
	if err != nil {
		t.Fatalf("protected-paths self-test: %v\n%s", err, out)
	}
}

// TestProtectedPathsPinnedToHeadSHA: the gate classifies files and commits
// from a compare pinned to the event head SHA, never the PR's live lists,
// and only against the default branch (A->B->A force-push race).
func TestProtectedPathsPinnedToHeadSHA(t *testing.T) {
	wf, err := os.ReadFile(".github/workflows/protected-paths.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(wf)
	for _, want := range []string{
		`'.base.ref == $ref and .base.repo.full_name == $repo' "$RUNNER_TEMP/pr.json"`,
		`gh api "repos/$REPO/compare/$base...$head" >"$RUNNER_TEMP/compare.json"`,
		`[[ $total =~ ^[0-9]+$ ]]`,
		`scripts/protected-paths.sh --compare "$REPO" "$BASE" "$HEAD"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("protected-paths.yml: missing %q", want)
		}
	}
	for _, live := range []string{"/files?", "/commits?", "--pr "} {
		if strings.Contains(s, live) {
			t.Errorf("protected-paths.yml: reads the PR's live list (%q); classify the head SHA", live)
		}
	}
}
