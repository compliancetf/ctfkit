// Package github checks adapters/github/action.yml against the rest of the
// repository, and runs its install step against a fake release. The rest of
// the action's behavior is exercised by the conformance harness and by the
// action self-test steps in .github/workflows/test.yml.
package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRepositoryDefaultIsTheReleaseTarget pins the action's repository input
// default to the repository .goreleaser.yml publishes releases to. A caller
// that omits the input downloads from that default, so the two must name the
// same repository.
func TestRepositoryDefaultIsTheReleaseTarget(t *testing.T) {
	var action struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
	}
	readYAML(t, "action.yml", &action)

	var release struct {
		Release struct {
			GitHub struct {
				Owner string `yaml:"owner"`
				Name  string `yaml:"name"`
			} `yaml:"github"`
		} `yaml:"release"`
	}
	readYAML(t, "../../.goreleaser.yml", &release)

	target := release.Release.GitHub.Owner + "/" + release.Release.GitHub.Name
	if release.Release.GitHub.Owner == "" || release.Release.GitHub.Name == "" {
		t.Fatalf(".goreleaser.yml release.github is %q; want owner and name", target)
	}
	if got := action.Inputs["repository"].Default; got != target {
		t.Errorf("action.yml repository default = %q, want %q (the .goreleaser.yml release target)", got, target)
	}
}

// TestMarketplaceMetadata pins the listing name and keeps the description
// under the GitHub Marketplace limit: publishing a release fails with
// "Description must be less than 125 characters" otherwise.
func TestMarketplaceMetadata(t *testing.T) {
	var action struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	readYAML(t, "action.yml", &action)

	if action.Name != "ctfkit by compliance.tf" {
		t.Errorf("action.yml name = %q, want %q (the Marketplace listing name)", action.Name, "ctfkit by compliance.tf")
	}
	if n := len(action.Description); n == 0 || n >= 125 {
		t.Errorf("action.yml description is %d characters; the Marketplace needs 1 to 124", n)
	}
}

func readYAML(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // fixed repository paths
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// A gh stand-in: release download copies $FAKE_RELEASE into --dir.
// attestation verify --help lists the binding flags unless $FAKE_GH_OLD is
// set; attestation verify refuses (65) a call not bound to the release
// workflow and the v9.9.9 tag, and otherwise exits $FAKE_ATTEST_EXIT.
const fakeGh = `#!/bin/sh
case "$1 $2" in
  "api repos/compliancetf/ctfkit/releases/latest")
    echo v9.9.9 ;;
  "release download")
    while [ $# -gt 0 ]; do [ "$1" = --dir ] && dir="$2"; shift; done
    cp "$FAKE_RELEASE"/* "$dir"/ ;;
  "attestation verify")
    if [ "$3" = --help ]; then
      echo "      --repo string"
      [ -n "$FAKE_GH_OLD" ] || printf '      --signer-workflow string\n      --source-ref string\n'
      exit 0
    fi
    case " $* " in
      *" --repo compliancetf/ctfkit "*) ;;
      *) exit 65 ;;
    esac
    case " $* " in
      *" --signer-workflow compliancetf/ctfkit/.github/workflows/release.yml "*) ;;
      *) exit 65 ;;
    esac
    case " $* " in
      *" --source-ref refs/tags/v9.9.9 "*) ;;
      *) exit 65 ;;
    esac
    exit "$FAKE_ATTEST_EXIT" ;;
  *) exit 64 ;;
esac
`

// TestInstallStepAuthenticatesTheDownload runs the install step of action.yml
// as written, with a fake gh serving a local release, and checks that inputs
// sha256 and verify-attestation fail the step when the archive does not match.
func TestInstallStepAuthenticatesTheDownload(t *testing.T) {
	osName := map[string]string{"linux": "Linux", "darwin": "Darwin"}[runtime.GOOS]
	arch := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
	if osName == "" || arch == "" {
		t.Skipf("no release archive for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	readYAML(t, "action.yml", &action)
	step := action.Runs.Steps[0]
	if step.Name != "Install the ctfkit binary" || strings.Contains(step.Run, "${{") {
		t.Fatalf("first step is %q; want the install step, reading its inputs from env only", step.Name)
	}
	actionPath, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	// The release: one archive holding a ctfkit file, and its checksums file.
	asset := "ctfkit_9.9.9_" + osName + "_" + arch + ".tar.gz"
	archive := tarGz(t, "ctfkit", "#!/bin/sh\n")
	digest := sha256.Sum256(archive)
	sum := hex.EncodeToString(digest[:])
	release := t.TempDir()
	write(t, filepath.Join(release, asset), string(archive), 0o600)
	write(t, filepath.Join(release, "checksums.txt"), sum+"  "+asset+"\n", 0o600)
	bin := t.TempDir()
	write(t, filepath.Join(bin, "gh"), fakeGh, 0o700)
	script := filepath.Join(t.TempDir(), "install.sh")
	write(t, script, step.Run, 0o600)

	for _, tc := range []struct {
		name, version, sha256, verify, attestExit string
		oldGh                                     bool   // gh without the binding flags
		wantErr                                   string // empty when the step must succeed
	}{
		{name: "no pin, no attestation"},
		{name: "latest resolves to the newest release", version: "latest"},
		{name: "empty version means latest", version: "-"},
		{name: "latest refuses a pinned digest", version: "latest", sha256: sum, wantErr: "input 'sha256' needs a pinned input 'version'"},
		{name: "version not a release", version: "main", wantErr: "is not latest or a release version"},
		{name: "pinned digest matches", sha256: sum},
		{name: "pinned digest in upper case", sha256: strings.ToUpper(sum)},
		{name: "pinned digest differs", sha256: strings.Repeat("0", 64), wantErr: "does not match input 'sha256'"},
		{name: "pinned digest malformed", sha256: sum[:63], wantErr: "is not a SHA-256 digest"},
		{name: "attestation verifies, bound to workflow and tag", verify: "true", attestExit: "0"},
		{name: "gh without the binding flags", verify: "true", attestExit: "0", oldGh: true, wantErr: "has no gh attestation verify --signer-workflow"},
		{name: "attestation does not verify", verify: "true", attestExit: "1", wantErr: "no build provenance attestation"},
		{name: "attestation unchecked when off", verify: "false", attestExit: "1"},
		{name: "verify-attestation not a boolean", verify: "yes", wantErr: "input 'verify-attestation'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, tmp := t.TempDir(), t.TempDir()
			verify := tc.verify
			if verify == "" {
				verify = "false"
			}
			version := tc.version // "" is a pinned v9.9.9, "-" an empty input
			switch version {
			case "":
				version = "v9.9.9"
			case "-":
				version = ""
			}
			oldGh := ""
			if tc.oldGh {
				oldGh = "1"
			}
			cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", script)
			cmd.Env = []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"HOME=" + home, "TMPDIR=" + tmp,
				"GITHUB_ENV=" + filepath.Join(tmp, "env"), "GITHUB_PATH=" + filepath.Join(tmp, "path"),
				"GITHUB_OUTPUT=" + filepath.Join(tmp, "output"),
				"FAKE_RELEASE=" + release, "FAKE_ATTEST_EXIT=" + tc.attestExit, "FAKE_GH_OLD=" + oldGh,
				"CTFKIT_VERSION=" + version, "CTFKIT_COMMAND=report", "CTFKIT_STAGE=", "CTFKIT_PLAN=",
				"CTFKIT_CHDIR=", "CTFKIT_FORMAT=receipt,sarif,markdown", "CTFKIT_CONFIG=",
				"CTFKIT_EXCEPTIONS=", "CTFKIT_CATALOG=embedded", "CTFKIT_TESTS_JSON=",
				"CTFKIT_ACTION_PATH=" + actionPath, "CTFKIT_REPOSITORY=compliancetf/ctfkit",
				"CTFKIT_PR_COMMENT=false", "CTFKIT_RELEASE_ASSETS=false", "CTFKIT_SHA256=" + tc.sha256,
				"CTFKIT_VERIFY_ATTESTATION=" + verify, "GH_TOKEN=unused",
			}
			out, err := cmd.CombinedOutput()
			installed := filepath.Join(home, ".ctfkit", "bin", "ctfkit")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("install failed: %v\n%s", err, out)
				}
				if _, statErr := os.Stat(installed); statErr != nil {
					t.Fatalf("ctfkit not installed: %v\n%s", statErr, out)
				}
				if got, _ := os.ReadFile(filepath.Join(tmp, "output")); !strings.Contains(string(got), "version=v9.9.9\n") {
					t.Fatalf("output ctfkit-version not set to v9.9.9: %q", got)
				}
				return
			}
			if err == nil || !strings.Contains(string(out), tc.wantErr) {
				t.Fatalf("got err %v, want a failure naming %q\n%s", err, tc.wantErr, out)
			}
			if _, statErr := os.Stat(installed); statErr == nil {
				t.Fatal("ctfkit installed although the check failed")
			}
		})
	}
}

func tarGz(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// TestWorkflowTemplatesPassActionlint lints both copyable workflows. CI
// installs actionlint; a machine without it skips.
func TestWorkflowTemplatesPassActionlint(t *testing.T) {
	bin, err := exec.LookPath("actionlint")
	if err != nil {
		t.Skip("actionlint is not on PATH")
	}
	out, err := exec.Command(bin, "workflow-template.yml", "verdict-workflow-template.yml").CombinedOutput() //nolint:gosec // fixed arguments
	if err != nil {
		t.Fatalf("actionlint: %v\n%s", err, out)
	}
}

type templateStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
}

type templateJob struct {
	Needs       string            `yaml:"needs"`
	Environment string            `yaml:"environment"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []templateStep    `yaml:"steps"`
}

// TestVerdictWorkflowTemplate pins the shape of the governed-apply
// template: plan, sign and apply in that order, each granted only contents
// read and an OIDC token, every third-party action pinned by commit SHA, no
// stored AWS key, and each job downloading exactly the artifact the previous
// one uploaded from the directory the action used.
func TestVerdictWorkflowTemplate(t *testing.T) {
	raw, err := os.ReadFile("verdict-workflow-template.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "aws-access-key-id") || strings.Contains(string(raw), "aws-secret-access-key") {
		t.Error("the template stores an AWS access key; assume roles with OIDC")
	}
	var wf struct {
		Permissions map[string]string      `yaml:"permissions"`
		Jobs        map[string]templateJob `yaml:"jobs"`
	}
	readYAML(t, "verdict-workflow-template.yml", &wf)
	if len(wf.Permissions) != 0 {
		t.Errorf("workflow permissions = %v, want {} with grants per job", wf.Permissions)
	}
	sha := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	prev, uploaded := "", ""
	for _, name := range []string{"plan", "sign", "apply"} {
		job, ok := wf.Jobs[name]
		if !ok {
			t.Fatalf("no %s job", name)
		}
		if job.Needs != prev {
			t.Errorf("%s needs %q, want %q", name, job.Needs, prev)
		}
		prev = name
		if want := map[bool]string{true: "production"}[name == "apply"]; job.Environment != want {
			t.Errorf("%s environment = %q, want %q; only apply waits for reviewers", name, job.Environment, want)
		}
		if want := map[string]string{"contents": "read", "id-token": "write"}; !maps.Equal(job.Permissions, want) {
			t.Errorf("%s permissions = %v, want %v", name, job.Permissions, want)
		}
		var ctfkit *templateStep
		downloaded, previous := "", uploaded
		for i, s := range job.Steps {
			switch {
			case strings.HasPrefix(s.Uses, "compliancetf/ctfkit-action@"):
				ctfkit = &job.Steps[i]
			case s.Uses != "" && !sha.MatchString(s.Uses):
				t.Errorf("%s: %s is not pinned by commit SHA", name, s.Uses)
			}
			if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["persist-credentials"] != "false" {
				t.Errorf("%s: checkout leaves git credentials on disk; set persist-credentials: false", name)
			}
			if strings.HasPrefix(s.Uses, "actions/download-artifact@") {
				downloaded = s.With["name"]
			}
			if strings.HasPrefix(s.Uses, "actions/upload-artifact@") {
				if ctfkit == nil || s.With["path"] != ctfkit.With["artifacts"] {
					t.Errorf("%s uploads %q, not the artifact set the action wrote", name, s.With["path"])
				}
				if !strings.Contains(s.With["name"], "github.run_attempt") {
					t.Errorf("%s artifact %q is not named after the run attempt", name, s.With["name"])
				}
				uploaded = s.With["name"]
			}
		}
		if ctfkit == nil || ctfkit.With["command"] != name {
			t.Fatalf("%s job does not run the action with command %s", name, name)
		}
		if name != "plan" && (downloaded == "" || downloaded != previous) {
			t.Errorf("%s downloads %q, want the artifact the previous job uploaded (%q)", name, downloaded, previous)
		}
		// latest is resolved once: sign and apply install the release the previous job used.
		if want := "${{ needs." + job.Needs + ".outputs.ctfkit-version }}"; name != "plan" && ctfkit.With["version"] != want {
			t.Errorf("%s version = %q, want %q", name, ctfkit.With["version"], want)
		}
		if signer := ctfkit.With["signer"]; (name == "sign") != strings.HasPrefix(signer, "awskms:") {
			t.Errorf("%s signer = %q; only sign signs, with awskms", name, signer)
		}
	}
}

// TestRestoreStepRestoresModes runs the permission step of action.yml as
// written on a directory shaped like a downloaded artifact.
func TestRestoreStepRestoresModes(t *testing.T) {
	script := filepath.Join(t.TempDir(), "restore.sh")
	write(t, script, actionStep(t, "Restore the artifact set permissions"), 0o600)
	restore := func(dir string) ([]byte, error) {
		cmd := exec.Command("bash", "--noprofile", "--norc", script)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "CTFKIT_ARTIFACTS=" + dir}
		return cmd.CombinedOutput()
	}

	set := filepath.Join(t.TempDir(), "set")
	if err := os.Mkdir(set, 0o755); err != nil { //nolint:gosec // the mode a download leaves
		t.Fatal(err)
	}
	for _, n := range []string{"planfile", "candidate.json", "ctfkit-run.key"} {
		write(t, filepath.Join(set, n), n, 0o644) //nolint:gosec // the mode a download leaves
	}
	if out, err := restore(set + "/"); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if st, err := os.Stat(set); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("set dir: %v %v, want 0700", st.Mode().Perm(), err)
	}
	for _, n := range []string{"planfile", "candidate.json", "ctfkit-run.key"} {
		if st, err := os.Stat(filepath.Join(set, n)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v, want 0600", n, st.Mode().Perm(), err)
		}
	}

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(set, link); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		link, link + "/", link + "//", link + "/.", link + "/./", ".", "..", "/",
		filepath.Join(set, "missing"), filepath.Join(set, "planfile"),
	} {
		if out, err := restore(dir); err == nil || !strings.Contains(string(out), "is not a directory") {
			t.Errorf("restore %s: %v, want a refusal\n%s", dir, err, out)
		}
	}
}

// TestRunStepGateCommands runs the run step of action.yml as written with a
// ctfkit stand-in that records its argv, and checks the flags each gate
// command receives.
func TestRunStepGateCommands(t *testing.T) {
	bin, tmp := t.TempDir(), t.TempDir()
	write(t, filepath.Join(bin, "ctfkit"), "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$ARGV_FILE\"\n", 0o700)
	script := filepath.Join(tmp, "run.sh")
	write(t, script, actionStep(t, "Run ctfkit"), 0o600)
	common := "--dir infra --workspace default --environment prod --tf-bin /usr/bin/tofu --org bobthecorp " +
		"--profile p.json --floor f.json --bundle-dir b"
	for cmd, want := range map[string]string{
		"plan":  "gate plan --out /a " + common,
		"sign":  "gate sign --candidate /a " + common + " --signer awskms:arn:aws:kms:eu-west-1:111122223333:key/k --fail-on error",
		"apply": "apply --artifacts /a " + common,
	} {
		t.Run(cmd, func(t *testing.T) {
			argv := filepath.Join(t.TempDir(), "argv")
			c := exec.Command("bash", "--noprofile", "--norc", script)
			c.Env = []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "ARGV_FILE=" + argv,
				"RUNNER_TEMP=" + t.TempDir(), "GITHUB_RUN_ID=1", "GITHUB_RUN_ATTEMPT=1",
				"GITHUB_OUTPUT=" + filepath.Join(tmp, "out"), "GITHUB_ENV=" + filepath.Join(tmp, "env"),
				"CTFKIT_COMMAND=" + cmd, "CTFKIT_PATH=.", "CTFKIT_PLAN=", "CTFKIT_CHDIR=infra", "CTFKIT_STAGE=",
				"CTFKIT_FORMAT=", "CTFKIT_FAIL_ON=error", "CTFKIT_CONFIG=", "CTFKIT_EXCEPTIONS=",
				"CTFKIT_CATALOG=embedded", "CTFKIT_TESTS_JSON=", "CTFKIT_ACTION_PATH=.",
				"CTFKIT_ARTIFACTS=/a", "CTFKIT_WORKSPACE=default", "CTFKIT_ENVIRONMENT=prod",
				"CTFKIT_TF_BIN=/usr/bin/tofu", "CTFKIT_ORG=bobthecorp", "CTFKIT_PROFILE=p.json",
				"CTFKIT_FLOOR=f.json", "CTFKIT_BUNDLE_DIR=b",
				"CTFKIT_SIGNER=awskms:arn:aws:kms:eu-west-1:111122223333:key/k",
			}
			if out, err := c.CombinedOutput(); err != nil {
				t.Fatalf("run step: %v\n%s", err, out)
			}
			got, err := os.ReadFile(argv) //nolint:gosec // test temp file
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(got)) != want {
				t.Errorf("ctfkit %s\nwant ctfkit %s", got, want)
			}
		})
	}
}

// actionStep returns the run script of the action.yml step called name.
func actionStep(t *testing.T, name string) string {
	t.Helper()
	var action struct {
		Runs struct {
			Steps []struct{ Name, Run string } `yaml:"steps"`
		} `yaml:"runs"`
	}
	readYAML(t, "action.yml", &action)
	for _, s := range action.Runs.Steps {
		if s.Name == name {
			return s.Run
		}
	}
	t.Fatalf("action.yml has no step %q", name)
	return ""
}

// TestRunStepCatalogPull runs the run step with catalog: pull. The pulled
// catalog lands outside the output directory, is the one scan reads, and is
// deleted when the step ends; a failed pull skips ctfkit and reports exit 2.
func TestRunStepCatalogPull(t *testing.T) {
	bin, tmp := t.TempDir(), t.TempDir()
	// Every call is logged. catalog pull writes its --out file unless
	// $PULL_EXIT is set; scan records whether its --catalog file exists.
	write(t, filepath.Join(bin, "ctfkit"), `#!/bin/sh
printf '%s\n' "$*" >> "$ARGV_FILE"
if [ "$1 $2" = "catalog pull" ]; then
  [ -z "$PULL_EXIT" ] || exit "$PULL_EXIT"
  : > "$4"
  exit 0
fi
while [ $# -gt 0 ]; do [ "$1" = --catalog ] && [ -f "$2" ] && echo present >> "$ARGV_FILE"; shift; done
exit 0
`, 0o700)
	script := filepath.Join(tmp, "run.sh")
	write(t, script, actionStep(t, "Run ctfkit"), 0o600)

	for name, tc := range map[string]struct {
		pullExit, wantCode string
		wantCalls          int
	}{
		"pulled":      {wantCode: "0", wantCalls: 2},
		"pull failed": {pullExit: "2", wantCode: "2", wantCalls: 1},
	} {
		t.Run(name, func(t *testing.T) {
			runnerTemp, argv, outFile := t.TempDir(), filepath.Join(t.TempDir(), "argv"), filepath.Join(t.TempDir(), "out")
			c := exec.Command("bash", "--noprofile", "--norc", script)
			c.Env = []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "ARGV_FILE=" + argv,
				"PULL_EXIT=" + tc.pullExit, "TF_TOKEN_registry_compliance_tf=bobthecorp-token",
				"RUNNER_TEMP=" + runnerTemp, "GITHUB_RUN_ID=1", "GITHUB_RUN_ATTEMPT=1",
				"GITHUB_OUTPUT=" + outFile, "GITHUB_ENV=" + filepath.Join(tmp, "env"),
				"CTFKIT_COMMAND=scan", "CTFKIT_PATH=.", "CTFKIT_PLAN=", "CTFKIT_CHDIR=infra", "CTFKIT_STAGE=pre_plan",
				"CTFKIT_FORMAT=", "CTFKIT_FAIL_ON=error", "CTFKIT_CONFIG=c.yaml", "CTFKIT_EXCEPTIONS=e.yaml",
				"CTFKIT_CATALOG=pull", "CTFKIT_TESTS_JSON=", "CTFKIT_ACTION_PATH=.", "CTFKIT_ARTIFACTS=",
				"CTFKIT_WORKSPACE=", "CTFKIT_ENVIRONMENT=", "CTFKIT_TF_BIN=", "CTFKIT_ORG=", "CTFKIT_PROFILE=",
				"CTFKIT_FLOOR=", "CTFKIT_BUNDLE_DIR=", "CTFKIT_SIGNER=",
			}
			out, _ := c.CombinedOutput()
			raw, err := os.ReadFile(argv) //nolint:gosec // test temp file
			if err != nil {
				t.Fatalf("ctfkit never ran: %v\n%s", err, out)
			}
			calls := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if !strings.HasPrefix(calls[0], "catalog pull --out "+filepath.Join(runnerTemp, "ctfkit", "catalog-")) {
				t.Fatalf("first call = %q, want catalog pull into its own directory", calls[0])
			}
			pulled := strings.TrimPrefix(calls[0], "catalog pull --out ")
			if n := len(calls) - strings.Count(string(raw), "present\n"); n != tc.wantCalls {
				t.Fatalf("ctfkit ran %d times, want %d:\n%s\n%s", n, tc.wantCalls, raw, out)
			}
			if tc.wantCalls == 2 && (!strings.Contains(calls[1], "--catalog "+pulled) || calls[len(calls)-1] != "present") {
				t.Errorf("scan did not read the pulled catalog:\n%s", raw)
			}
			if _, err := os.Stat(filepath.Dir(pulled)); err == nil {
				t.Errorf("pulled catalog directory %s left behind", filepath.Dir(pulled))
			}
			got, _ := os.ReadFile(outFile) //nolint:gosec // test temp file
			if !strings.Contains(string(got), "exit-code="+tc.wantCode+"\n") {
				t.Errorf("outputs = %q, want exit-code=%s\n%s", got, tc.wantCode, out)
			}
		})
	}
}

// TestReleaseAssetsInput pins the release-assets input: off by default, and the
// upload step runs only when it is true.
func TestReleaseAssetsInput(t *testing.T) {
	var action struct {
		Inputs map[string]struct{ Default string } `yaml:"inputs"`
		Runs   struct {
			Steps []struct {
				Name string `yaml:"name"`
				If   string `yaml:"if"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	readYAML(t, "action.yml", &action)
	if got := action.Inputs["release-assets"].Default; got != "false" {
		t.Errorf("release-assets default = %q, want false", got)
	}
	for _, s := range action.Runs.Steps {
		if s.Name == "Upload the evidence pack to the release" {
			if !strings.Contains(s.If, "inputs.release-assets == 'true'") {
				t.Errorf("upload step if = %q, want it conditioned on release-assets", s.If)
			}
			return
		}
	}
	t.Fatal("action.yml has no release upload step")
}

// TestReleaseAssetsStep runs the release upload step with a gh stand-in that
// records its argv and knows one release, v1.0.0.
func TestReleaseAssetsStep(t *testing.T) {
	bin := t.TempDir()
	write(t, filepath.Join(bin, "gh"), `#!/bin/sh
case "$1 $2" in
  "release view") [ "$3" = v1.0.0 ] ;;
  "release upload") printf '%s\n' "$*" > "$ARGV_FILE" ;;
  *) exit 64 ;;
esac
`, 0o700)
	script := filepath.Join(t.TempDir(), "release.sh")
	write(t, script, actionStep(t, "Upload the evidence pack to the release"), 0o600)
	event := filepath.Join(t.TempDir(), "event.json")
	write(t, event, `{"release":{"tag_name":"v1.0.0"}}`, 0o600)

	for name, tc := range map[string]struct {
		event, refType, refName, exit string
		pdf                           bool
		wantErr                       string
	}{
		"release event":      {event: "release", refType: "tag", refName: "v1.0.0", exit: "0", pdf: true},
		"tag with release":   {event: "push", refType: "tag", refName: "v1.0.0", exit: "1"},
		"tag, no release":    {event: "push", refType: "tag", refName: "v2.0.0", exit: "0", pdf: true, wantErr: "is not for a release"},
		"branch push":        {event: "push", refType: "branch", refName: "main", exit: "0", pdf: true, wantErr: "is not for a release"},
		"pull request":       {event: "pull_request", refType: "branch", refName: "1/merge", exit: "0", pdf: true, wantErr: "is not for a release"},
		"ctfkit errored":     {event: "release", refType: "tag", refName: "v1.0.0", exit: "2", pdf: true, wantErr: "did not complete (exit 2)"},
		"ctfkit did not run": {event: "release", refType: "tag", refName: "v1.0.0", pdf: true, wantErr: "did not complete (exit unset)"},
	} {
		t.Run(name, func(t *testing.T) {
			outDir, argv := t.TempDir(), filepath.Join(t.TempDir(), "argv")
			zip, pdf := filepath.Join(outDir, "evidence-pack.zip"), filepath.Join(outDir, "evidence-pack.pdf")
			write(t, zip, "zip", 0o600)
			if tc.pdf {
				write(t, pdf, "pdf", 0o600)
			}
			c := exec.Command("bash", "--noprofile", "--norc", script)
			c.Env = []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "ARGV_FILE=" + argv,
				"GITHUB_EVENT_NAME=" + tc.event, "GITHUB_EVENT_PATH=" + event, "GITHUB_REF_TYPE=" + tc.refType,
				"GITHUB_REF_NAME=" + tc.refName, "GITHUB_REF=refs/x/" + tc.refName,
				"GITHUB_REPOSITORY=bobthecorp/blueprint", "CTFKIT_OUT_DIR=" + outDir,
			}
			if tc.exit != "" {
				c.Env = append(c.Env, "CTFKIT_EXIT="+tc.exit)
			}
			out, err := c.CombinedOutput()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(string(out), tc.wantErr) {
					t.Fatalf("step passed or gave no reason: %v\n%s", err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("step: %v\n%s", err, out)
			}
			want := "release upload v1.0.0 " + zip
			if tc.pdf {
				want += " " + pdf
			} else if !strings.Contains(string(out), "::notice::no evidence-pack.pdf") {
				t.Errorf("missing PDF gave no notice:\n%s", out)
			}
			want += " --clobber --repo bobthecorp/blueprint"
			got, _ := os.ReadFile(argv) //nolint:gosec // test temp file
			if strings.TrimSpace(string(got)) != want {
				t.Errorf("gh %s\nwant gh %s", got, want)
			}
		})
	}
}
