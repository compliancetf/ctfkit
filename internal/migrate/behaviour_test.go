package migrate

// The behavior spike (PM-T01). Each scenario below checks one row B1-B7 of
// the migrate design's "Behavior this design relies on" table. A golden per
// behavior and CLI version, <B#>/<tf>-<version>.golden under behaviorDir,
// is the recorded transcript of a real run; TestBehaviour replays every golden
// through the behavior's check without any CLI installed.
//
// Live mode re-records: set TF_BIN to one or more terraform/tofu binaries
// (os.PathListSeparator-separated) and TF_FAKE_PROVIDER to the fake upstream
// provider (terraform-provider-aws test/fakeupstream, `go build ./v5`), and
// optionally TF_SHA256SUMS to the release SHA256SUMS files the binaries were
// checked against, so each golden records its release archive and sum. Every
// run is local only: the fake is served from a filesystem mirror under the
// three addresses below, state is local, nothing is applied, and the only
// remote backends named (s3, cloud on tfe.invalid) are replaced or rejected
// before any connection.
//
//	TF_BIN=/x/terraform-1.5.7:/x/terraform:/x/tofu TF_FAKE_PROVIDER=/x/fakeupstream \
//	  TF_SHA256SUMS=/x/terraform_1.5.7_SHA256SUMS:/x/terraform_1.16.6_SHA256SUMS:/x/tofu_1.13.1_SHA256SUMS \
//	  go test ./internal/migrate/ -run TestBehaviour

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	behaviorDir  = "../../testdata/fixtures/migrate/behaviour" //nolint:misspell // path named by the migrate spec
	wrapperFQN   = "registry.compliance.tf/compliancetf/aws"
	tfUpstream   = "registry.terraform.io/hashicorp/aws"
	tofuUpstream = "registry.opentofu.org/hashicorp/aws"
)

// mirrored is every provider address the filesystem mirror serves, at the
// version it serves it.
var mirrored = map[string]string{tfUpstream: "6.0.0", tofuUpstream: "6.0.0", wrapperFQN: "2.0.0"}

type golden struct {
	Behavior   string    `json:"behavior"`
	Assumption string    `json:"assumption"`
	CLI        cliInfo   `json:"cli"`
	Provider   string    `json:"fake_provider_sha256"`
	Upstream   string    `json:"upstream"`
	Inputs     string    `json:"inputs_sha256"`
	Steps      []stepRec `json:"steps"`
}

type cliInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	SHA256   string `json:"binary_sha256"`
	Archive  string `json:"release_archive,omitempty"`
	ArchSum  string `json:"release_archive_sha256,omitempty"`
}

type stepRec struct {
	Dir    string   `json:"dir"`
	Run    []string `json:"run,omitempty"`
	Cat    string   `json:"cat,omitempty"`
	Filter string   `json:"filter,omitempty"`
	Exit   int      `json:"exit"`
	Output []string `json:"output"`
}

type step struct {
	dir    string
	run    []string          // CLI arguments; the binary is prepended
	cat    string            // or: a file to record, relative to dir
	filter string            // "plan_providers", "state_providers" or "backend_type"
	write  map[string]string // files written (relative to dir) before the step
}

type scenario struct {
	id, assumption string
	files          map[string]string // relative to the work dir; {{UPSTREAM}} is replaced
	steps          []step
	check          func(g golden) error
}

const (
	wrapperRoot = `terraform {
  required_providers {
    aws = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "fake_thing" "r" {
  provider = aws
  name     = "r"
}
`
	upstreamChild = `terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "fake_thing" "c" {
  provider = aws
  name     = "c"
}
`
	// state4 is a v4 state with one resource per provider address in
	// %s (the {{UPSTREAM}} template is applied after formatting).
	state4 = `{
  "version": 4,
  "terraform_version": "1.5.0",
  "serial": 1,
  "lineage": "00000000-0000-0000-0000-000000000001",
  "outputs": {},
  "resources": [%s]
}
`
)

func stateResource(module, name, provider string) string {
	mod := ""
	if module != "" {
		mod = fmt.Sprintf(`"module": %q, `, module)
	}
	return fmt.Sprintf(`
    {%s"mode": "managed", "type": "fake_thing", "name": %q, "provider": %q,
     "instances": [{"schema_version": 0, "attributes": {"id": %q, "name": %q, "size": 1, "crash": null}}]}`,
		mod, name, provider, name, name)
}

var (
	initCmd = []string{"init", "-input=false", "-no-color"}
	planCmd = []string{"plan", "-input=false", "-no-color", "-lock=false", "-out=p.tfplan"}
	showCmd = []string{"show", "-json", "-no-color", "p.tfplan"}
	lockCat = ".terraform.lock.hcl"
)

var scenarios = []scenario{
	{
		id:         "B1",
		assumption: "A child module whose required_providers names hashicorp/aws cannot receive a compliancetf/aws configuration through providers = {} (type-mismatch error)",
		files: map[string]string{
			"root/main.tf": wrapperRoot + `
module "child" {
  source    = "./child"
  providers = { aws = aws }
}
`,
			"root/child/main.tf": upstreamChild,
		},
		steps: []step{{dir: "root", run: initCmd}},
		check: func(g golden) error {
			s := g.Steps[0]
			if s.Exit == 0 || !contains(s.Output, "Provider type mismatch") {
				return fmt.Errorf("init exit %d, want a Provider type mismatch error", s.Exit)
			}
			return nil
		},
	},
	{
		id:         "B2",
		assumption: "With implicit inheritance, that child module gets its own unconfigured hashicorp/aws instance; its resources bypass the wrapper",
		files: map[string]string{
			"root/main.tf": wrapperRoot + `
module "child" {
  source = "./child"
}
`,
			"root/child/main.tf": upstreamChild,
		},
		steps: []step{
			{dir: "root", run: initCmd},
			{dir: "root", run: []string{"providers", "-no-color"}},
			{dir: "root", run: planCmd},
			{dir: "root", run: showCmd, filter: "plan_providers"},
		},
		check: func(g golden) error {
			if err := exitsZero(g, 0, 1, 2, 3); err != nil {
				return err
			}
			return want(g.Steps[3].Output,
				"resource fake_thing.r provider="+wrapperFQN,
				"resource module.child.fake_thing.c provider="+g.Upstream,
				"provider_config aws full_name="+wrapperFQN+" configured=true",
				"provider_config module.child:aws full_name="+g.Upstream+" configured=false")
		},
	},
	{
		id:         "B3",
		assumption: "terraform init installs providers required by state as well as by config",
		files: map[string]string{
			"root/main.tf":           "terraform {}\n",
			"root/terraform.tfstate": fmt.Sprintf(state4, stateResource("", "gone", `provider["{{UPSTREAM}}"]`)),
		},
		steps: []step{{dir: "root", run: initCmd}, {dir: "root", cat: lockCat}},
		check: func(g golden) error {
			if err := exitsZero(g, 0); err != nil {
				return err
			}
			return want(g.Steps[1].Output, `provider "`+g.Upstream+`" {`)
		},
	},
	{
		id:         "B4",
		assumption: "state replace-provider rewrites aliased (provider[\"...\"].west) and module-scoped resource provider addresses",
		files: map[string]string{
			"root/main.tf": "terraform {}\n",
			"root/terraform.tfstate": fmt.Sprintf(state4, strings.Join([]string{
				stateResource("", "plain", `provider["{{UPSTREAM}}"]`),
				stateResource("", "aliased", `provider["{{UPSTREAM}}"].west`),
				stateResource("module.inherits", "m", `provider["{{UPSTREAM}}"]`),
				stateResource("module.own", "o", `module.own.provider["{{UPSTREAM}}"]`),
				stateResource("module.own", "oa", `module.own.provider["{{UPSTREAM}}"].west`),
			}, ",")),
		},
		steps: []step{
			{dir: "root", run: initCmd},
			{dir: "root", run: []string{"state", "replace-provider", "-auto-approve", "-no-color", "{{UPSTREAM}}", wrapperFQN}},
			{dir: "root", cat: "terraform.tfstate", filter: "state_providers"},
		},
		check: func(g golden) error {
			if err := exitsZero(g, 0, 1); err != nil {
				return err
			}
			return wantExactly(g.Steps[2].Output,
				`fake_thing.aliased provider=provider["`+wrapperFQN+`"].west`,
				`fake_thing.plain provider=provider["`+wrapperFQN+`"]`,
				`module.inherits.fake_thing.m provider=provider["`+wrapperFQN+`"]`,
				`module.own.fake_thing.o provider=module.own.provider["`+wrapperFQN+`"]`,
				`module.own.fake_thing.oa provider=module.own.provider["`+wrapperFQN+`"].west`)
		},
	},
	{
		id:         "B5",
		assumption: "init drops lock entries no longer required by config or state",
		files: map[string]string{
			"root/main.tf": "terraform {\n  required_providers {\n    aws = { source = \"hashicorp/aws\" }\n  }\n}\n",
		},
		steps: []step{
			{dir: "root", run: initCmd},
			{dir: "root", cat: lockCat},
			{dir: "root", run: initCmd, write: map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = { source = \"registry.compliance.tf/compliancetf/aws\" }\n  }\n}\n"}},
			{dir: "root", cat: lockCat},
		},
		check: func(g golden) error {
			if err := exitsZero(g, 0, 2); err != nil {
				return err
			}
			if err := want(g.Steps[1].Output, `provider "`+g.Upstream+`" {`); err != nil {
				return err
			}
			if contains(g.Steps[3].Output, `provider "`+g.Upstream+`" {`) {
				return fmt.Errorf("lock still lists %s after it left the config", g.Upstream)
			}
			return want(g.Steps[3].Output, `provider "`+wrapperFQN+`" {`)
		},
	},
	{
		id: "B6",
		// The design table expected an error for a cloud block; every recorded
		// CLI replaces it like any backend, so the row records what holds.
		assumption: "An override file with backend \"local\" replaces the root's backend for a scratch copy, a cloud block included (the design table expected an error for cloud)",
		files: map[string]string{
			"backend/main.tf":        "terraform {\n  backend \"s3\" {\n    bucket = \"bobthecorp-state\"\n    key    = \"live/terraform.tfstate\"\n    region = \"eu-west-1\"\n  }\n}\n",
			"backend/zz_override.tf": overrideLocal,
			"cloud/main.tf":          "terraform {\n  cloud {\n    hostname     = \"tfe.invalid\"\n    organization = \"bobthecorp\"\n    workspaces {\n      name = \"live\"\n    }\n  }\n}\n",
			"cloud/zz_override.tf":   overrideLocal,
		},
		steps: []step{
			{dir: "backend", run: initCmd},
			{dir: "backend", cat: ".terraform/terraform.tfstate", filter: "backend_type"},
			{dir: "cloud", run: initCmd},
			{dir: "cloud", cat: ".terraform/terraform.tfstate", filter: "backend_type"},
		},
		check: func(g golden) error {
			if err := exitsZero(g, 0, 1, 2, 3); err != nil {
				return err
			}
			for _, i := range []int{1, 3} {
				if err := wantExactly(g.Steps[i].Output, `backend local path="scratch.tfstate"`); err != nil {
					return fmt.Errorf("%s root: %w", g.Steps[i].Dir, err)
				}
			}
			return nil
		},
	},
	{
		id:         "B7",
		assumption: "OpenTofu records implied providers under registry.opentofu.org/hashicorp/<t>",
		files: map[string]string{
			"root/main.tf": "provider \"aws\" {\n  region = \"eu-west-1\"\n}\n\nresource \"fake_thing\" \"x\" {\n  provider = aws\n  name     = \"x\"\n}\n",
		},
		steps: []step{
			{dir: "root", run: initCmd},
			{dir: "root", cat: lockCat},
			{dir: "root", run: planCmd},
			{dir: "root", run: showCmd, filter: "plan_providers"},
		},
		check: func(g golden) error {
			if err := exitsZero(g, 0, 2, 3); err != nil {
				return err
			}
			implied := tfUpstream
			if g.CLI.Name == "tofu" {
				implied = tofuUpstream
			}
			if err := want(g.Steps[1].Output, `provider "`+implied+`" {`); err != nil {
				return err
			}
			return want(g.Steps[3].Output, "resource fake_thing.x provider="+implied)
		},
	},
}

const overrideLocal = "terraform {\n  backend \"local\" {\n    path = \"scratch.tfstate\"\n  }\n}\n"

func TestBehaviour(t *testing.T) {
	if bins := os.Getenv("TF_BIN"); bins != "" {
		record(t, filepath.SplitList(bins), os.Getenv("TF_FAKE_PROVIDER"))
	}
	var clis []string
	for i, sc := range scenarios {
		files, err := filepath.Glob(filepath.Join(behaviorDir, sc.id, "*.golden"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no goldens (%v)", sc.id, err)
		}
		var names []string
		for _, f := range files {
			names = append(names, filepath.Base(f))
			t.Run(sc.id+"/"+filepath.Base(f), func(t *testing.T) {
				g := readGolden(t, f)
				if err := matchScenario(g, sc); err != nil {
					t.Fatalf("golden does not match scenario %s, re-record: %v", sc.id, err)
				}
				if want := fmt.Sprintf("%s-%s.golden", g.CLI.Name, g.CLI.Version); filepath.Base(f) != want {
					t.Fatalf("file name %s, cli says %s", filepath.Base(f), want)
				}
				if err := sc.check(g); err != nil {
					t.Fatalf("%s does not hold on %s %s: %v", sc.id, g.CLI.Name, g.CLI.Version, err)
				}
			})
		}
		if i == 0 {
			clis = names
		} else if !slices.Equal(names, clis) {
			t.Errorf("%s recorded on %v, B1 on %v; every behavior needs the same CLI set", sc.id, names, clis)
		}
	}
	if !slices.ContainsFunc(clis, func(n string) bool { return strings.HasPrefix(n, "terraform-1.5.") }) ||
		!slices.ContainsFunc(clis, func(n string) bool { return strings.HasPrefix(n, "tofu-") }) ||
		!slices.ContainsFunc(clis, func(n string) bool {
			return strings.HasPrefix(n, "terraform-") && !strings.HasPrefix(n, "terraform-1.5.")
		}) {
		t.Errorf("goldens cover %v; want Terraform 1.5, a newer Terraform and OpenTofu", clis)
	}
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// matchScenario checks a golden was recorded from sc as it stands: the same
// steps in the same dirs, the upstream its CLI implies, every file read
// successful, and the CLI and fake provider provenance present.
func matchScenario(g golden, sc scenario) error {
	if g.Behavior != sc.id || g.Assumption != sc.assumption {
		return fmt.Errorf("behavior %q or assumption differs", g.Behavior)
	}
	if g.Upstream != upstreamFor(g.CLI.Name) {
		return fmt.Errorf("upstream %q for cli %q", g.Upstream, g.CLI.Name)
	}
	if !sha256Hex.MatchString(g.CLI.SHA256) || !sha256Hex.MatchString(g.Provider) || !sha256Hex.MatchString(g.CLI.ArchSum) ||
		g.CLI.Platform == "" || g.CLI.Archive != fmt.Sprintf("%s_%s_%s.zip", g.CLI.Name, g.CLI.Version, g.CLI.Platform) {
		return fmt.Errorf("cli or fake provider provenance missing: %+v provider %q", g.CLI, g.Provider)
	}
	if g.Inputs != inputsDigest(sc, g.Upstream) {
		return fmt.Errorf("scenario files, writes or mirror changed since recording (inputs_sha256 %q)", g.Inputs)
	}
	if len(g.Steps) != len(sc.steps) {
		return fmt.Errorf("%d steps, scenario has %d", len(g.Steps), len(sc.steps))
	}
	for i, s := range sc.steps {
		r := g.Steps[i]
		var run []string
		if s.run != nil {
			run = append([]string{g.CLI.Name}, renderArgs(s.run, g.Upstream)...)
		}
		if r.Dir != s.dir || r.Cat != s.cat || r.Filter != s.filter || !slices.Equal(r.Run, run) {
			return fmt.Errorf("step %d recorded %+v", i, r)
		}
		if s.cat != "" && r.Exit != 0 {
			return fmt.Errorf("step %d could not read %s", i, s.cat)
		}
	}
	return nil
}

// inputsDigest hashes everything a scenario feeds the CLI besides its
// steps: the rendered files, each step's writes and the mirrored versions.
func inputsDigest(sc scenario, upstream string) string {
	h := sha256.New()
	put := func(kind, name, body string) { fmt.Fprintf(h, "%s\x00%s\x00%d\x00%s", kind, name, len(body), body) }
	for _, rel := range slices.Sorted(maps.Keys(sc.files)) {
		put("file", rel, strings.ReplaceAll(sc.files[rel], "{{UPSTREAM}}", upstream))
	}
	for i, st := range sc.steps {
		for _, rel := range slices.Sorted(maps.Keys(st.write)) {
			put("write", fmt.Sprintf("%d/%s", i, rel), st.write[rel])
		}
	}
	for _, addr := range slices.Sorted(maps.Keys(mirrored)) {
		put("mirror", addr, mirrored[addr])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func upstreamFor(cli string) string {
	if cli == "tofu" {
		return tofuUpstream
	}
	return tfUpstream
}

func renderArgs(args []string, upstream string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.ReplaceAll(a, "{{UPSTREAM}}", upstream)
	}
	return out
}

func readGolden(t *testing.T, path string) golden {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return g
}

// record runs every scenario on every binary and rewrites its golden.
func record(t *testing.T, bins []string, provider string) {
	t.Helper()
	if provider == "" || os.Getenv("TF_SHA256SUMS") == "" {
		t.Fatal("TF_BIN is set; TF_FAKE_PROVIDER must name the fake upstream provider binary and TF_SHA256SUMS the release SHA256SUMS files")
	}
	provSum := fileSHA256(t, provider)
	for _, bin := range bins {
		cli := describeCLI(t, bin)
		upstream := upstreamFor(cli.Name)
		for _, sc := range scenarios {
			g := golden{Behavior: sc.id, Assumption: sc.assumption, CLI: cli, Provider: provSum, Upstream: upstream,
				Inputs: inputsDigest(sc, upstream)}
			runScenario(t, sc, bin, provider, upstream, &g)
			err := matchScenario(g, sc)
			if err == nil {
				err = sc.check(g)
			}
			if err != nil {
				// keep the previous golden; a failed run is not a recording
				t.Errorf("live %s on %s %s: %v (golden not written)", sc.id, cli.Name, cli.Version, err)
				continue
			}
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(g); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(behaviorDir, sc.id)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("%s-%s.golden", cli.Name, cli.Version)
			if err := os.WriteFile(filepath.Join(dir, name), b.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func describeCLI(t *testing.T, bin string) cliInfo {
	t.Helper()
	out, err := exec.Command(bin, "version", "-json").Output()
	if err != nil {
		t.Fatalf("%s version -json: %v", bin, err)
	}
	var v struct {
		Version  string `json:"terraform_version"`
		Platform string `json:"platform"`
	}
	if err := json.Unmarshal(out, &v); err != nil || v.Version == "" {
		t.Fatalf("%s version -json: %q (%v)", bin, out, err)
	}
	name := "terraform"
	if strings.Contains(filepath.Base(bin), "tofu") {
		name = "tofu"
	}
	cli := cliInfo{Name: name, Version: v.Version, Platform: v.Platform, SHA256: fileSHA256(t, bin)}
	if sums := os.Getenv("TF_SHA256SUMS"); sums != "" {
		cli.Archive = fmt.Sprintf("%s_%s_%s.zip", name, v.Version, v.Platform)
		for _, f := range filepath.SplitList(sums) {
			for _, l := range strings.Split(string(mustRead(t, f)), "\n") {
				if sum, file, ok := strings.Cut(l, "  "); ok && file == cli.Archive {
					cli.ArchSum = sum
				}
			}
		}
		if cli.ArchSum == "" {
			t.Fatalf("TF_SHA256SUMS lists no %s", cli.Archive)
		}
	}
	return cli
}

func runScenario(t *testing.T, sc scenario, bin, provider, upstream string, g *golden) {
	t.Helper()
	work := t.TempDir()
	if real, err := filepath.EvalSymlinks(work); err == nil {
		work = real
	}
	mirror := filepath.Join(work, "mirror")
	platform := runtime.GOOS + "_" + runtime.GOARCH
	for addr, ver := range mirrored {
		typ := addr[strings.LastIndex(addr, "/")+1:]
		writeFile(t, filepath.Join(mirror, addr, ver, platform, "terraform-provider-"+typ+"_v"+ver), mustRead(t, provider), 0o755)
	}
	cliConfig := filepath.Join(work, "cli.tfrc")
	writeFile(t, cliConfig, []byte(fmt.Sprintf("provider_installation {\n  filesystem_mirror {\n    path = %q\n  }\n}\n", mirror)), 0o644)
	for rel, body := range sc.files {
		writeFile(t, filepath.Join(work, rel), []byte(strings.ReplaceAll(body, "{{UPSTREAM}}", upstream)), 0o644)
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + work, "TMPDIR=" + os.TempDir(),
		"TF_CLI_CONFIG_FILE=" + cliConfig, "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1",
		"AWS_EC2_METADATA_DISABLED=true",
	}
	for _, s := range sc.steps {
		dir := filepath.Join(work, s.dir)
		for rel, body := range s.write {
			writeFile(t, filepath.Join(dir, rel), []byte(body), 0o644)
		}
		rec := stepRec{Dir: s.dir, Cat: s.cat, Filter: s.filter}
		var out []byte
		if s.cat != "" {
			b, err := os.ReadFile(filepath.Join(dir, s.cat))
			if err != nil {
				rec.Exit = 1
			}
			out = b
		} else {
			args := renderArgs(s.run, upstream)
			rec.Run = append([]string{g.CLI.Name}, args...)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir, cmd.Env = dir, env
			var err error
			if s.filter != "" {
				out, err = cmd.Output() // a filtered step records stdout only
			} else {
				out, err = cmd.CombinedOutput()
			}
			timedOut := ctx.Err() != nil
			cancel()
			if cmd.ProcessState == nil || timedOut {
				t.Fatalf("%s %v: %v", bin, args, err)
			}
			rec.Exit = cmd.ProcessState.ExitCode()
		}
		rec.Output = normalise(t, out, s.filter, work)
		g.Steps = append(g.Steps, rec)
	}
}

var h1Hash = regexp.MustCompile(`"(h1|zh):[^"]*"`)

// normalise makes a step's output stable across runs: the work dir becomes
// $WORK, package hashes (they hash the locally built fake) become <hash>,
// and a filter reduces JSON to the provider facts the checks read.
func normalise(t *testing.T, out []byte, filter, work string) []string {
	t.Helper()
	var lines []string
	switch filter {
	case "plan_providers":
		lines = planProviders(t, out)
	case "state_providers":
		lines = stateProviders(t, out)
	case "backend_type":
		lines = backendType(t, out)
	default:
		s := strings.ReplaceAll(string(out), work, "$WORK")
		s = h1Hash.ReplaceAllString(s, `"$1:<hash>"`)
		for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
			lines = append(lines, strings.TrimRight(l, " \t"))
		}
	}
	if lines == nil {
		lines = []string{}
	}
	return lines
}

func planProviders(t *testing.T, out []byte) []string {
	t.Helper()
	var p struct {
		ResourceChanges []struct {
			Address  string `json:"address"`
			Provider string `json:"provider_name"`
		} `json:"resource_changes"`
		Configuration struct {
			ProviderConfig map[string]struct {
				FullName    string         `json:"full_name"`
				Expressions map[string]any `json:"expressions"`
			} `json:"provider_config"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatalf("show -json: %v: %q", err, out)
	}
	var lines []string
	for _, rc := range p.ResourceChanges {
		lines = append(lines, fmt.Sprintf("resource %s provider=%s", rc.Address, rc.Provider))
	}
	for k, pc := range p.Configuration.ProviderConfig {
		lines = append(lines, fmt.Sprintf("provider_config %s full_name=%s configured=%t", k, pc.FullName, len(pc.Expressions) > 0))
	}
	sort.Strings(lines)
	return lines
}

func stateProviders(t *testing.T, out []byte) []string {
	t.Helper()
	var s struct {
		Resources []struct {
			Module, Type, Name, Provider string
		} `json:"resources"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("state: %v: %q", err, out)
	}
	var lines []string
	for _, r := range s.Resources {
		addr := r.Type + "." + r.Name
		if r.Module != "" {
			addr = r.Module + "." + addr
		}
		lines = append(lines, addr+" provider="+r.Provider)
	}
	sort.Strings(lines)
	return lines
}

func backendType(t *testing.T, out []byte) []string {
	t.Helper()
	var s struct {
		Backend struct {
			Type   string `json:"type"`
			Config struct {
				Path string `json:"path"`
			} `json:"config"`
		} `json:"backend"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("backend state: %v: %q", err, out)
	}
	return []string{fmt.Sprintf("backend %s path=%q", s.Backend.Type, s.Backend.Config.Path)}
}

func exitsZero(g golden, idx ...int) error {
	for _, i := range idx {
		if s := g.Steps[i]; s.Exit != 0 {
			return fmt.Errorf("step %d (%s%s) exit %d", i, strings.Join(s.Run, " "), s.Cat, s.Exit)
		}
	}
	return nil
}

func contains(lines []string, sub string) bool {
	return slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, sub) })
}

func want(lines []string, subs ...string) error {
	for _, s := range subs {
		if !contains(lines, s) {
			return fmt.Errorf("no line contains %q in %q", s, lines)
		}
	}
	return nil
}

func wantExactly(lines []string, exp ...string) error {
	if !slices.Equal(lines, exp) {
		return fmt.Errorf("got %q, want %q", lines, exp)
	}
	return nil
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	sum := sha256.Sum256(mustRead(t, path))
	return hex.EncodeToString(sum[:])
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
}
