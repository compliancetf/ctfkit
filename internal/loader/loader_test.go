package loader_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// fixtureRoot is the repository's fixture pack, reached from this package.
const fixtureRoot = "../../testdata/fixtures"

// planCases are the F1 plan fixtures. Every one of them holds input/plan.json.
var planCases = []string{
	"01-raw-s3-no-ctf",
	"02-ctf-module-intact",
	"03-ctf-module-disabled-control",
	"04-floating-ref",
	"05-mixed-origin",
	"06-sentinel-exception",
	"07-expired-exception",
	"08-missing-tags",
	"09-unknown-provider",
	"10-post-apply-state",
}

func TestLoadPlan(t *testing.T) {
	for _, name := range planCases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(fixtureRoot, "plan", name, "input", "plan.json")

			plan, err := loader.LoadPlan(path)
			if err != nil {
				t.Fatalf("LoadPlan(%s) returned an error: %v", path, err)
			}
			if plan == nil {
				t.Fatal("LoadPlan returned a nil plan and a nil error")
			}
			if major, _, _ := strings.Cut(plan.FormatVersion, "."); major != "1" {
				t.Fatalf("format version %q does not have major 1", plan.FormatVersion)
			}
		})
	}
}

func TestLoadPlanTruncatedIsAnInputError(t *testing.T) {
	source := filepath.Join(fixtureRoot, "plan", "01-raw-s3-no-ctf", "input", "plan.json")
	whole, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("reading the fixture plan: %v", err)
	}

	path := filepath.Join(t.TempDir(), "plan.json")
	if writeErr := os.WriteFile(path, whole[:len(whole)/2], 0o600); writeErr != nil {
		t.Fatalf("writing the truncated plan: %v", writeErr)
	}

	plan, err := loader.LoadPlan(path)
	if err == nil {
		t.Fatal("a truncated plan file loaded without an error")
	}
	if plan != nil {
		t.Fatalf("a truncated plan file returned a plan: %+v", plan)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadPlanRejectsAnotherFormatMajor(t *testing.T) {
	// terraform-json validates as it decodes and refuses anything outside
	// ">= 0.1, < 2.0" itself, so a 2.x case alone never reaches this
	// package's own major check. 0.9 satisfies the library and still has a
	// major that is not 1, which is what pins the check here.
	for _, version := range []string{"0.9", "2.0", "10.0"} {
		t.Run(version, func(t *testing.T) {
			path := planWithFormatVersion(t, version)

			plan, err := loader.LoadPlan(path)
			if err == nil {
				t.Fatalf("a plan with format version %s loaded without an error", version)
			}
			if plan != nil {
				t.Fatalf("a plan with format version %s returned a plan: %+v", version, plan)
			}
			if !errors.Is(err, loader.ErrInput) {
				t.Fatalf("error %v is not an ErrInput", err)
			}
			if !strings.Contains(err.Error(), version) {
				t.Fatalf("error %v does not name the format version it refused", err)
			}
		})
	}
}

// planWithFormatVersion writes a copy of the first plan fixture whose
// format_version is version, and returns its path.
func planWithFormatVersion(t *testing.T, version string) string {
	t.Helper()

	source := filepath.Join(fixtureRoot, "plan", "01-raw-s3-no-ctf", "input", "plan.json")
	whole, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("reading the fixture plan: %v", err)
	}

	var raw map[string]json.RawMessage
	if decodeErr := json.Unmarshal(whole, &raw); decodeErr != nil {
		t.Fatalf("decoding the fixture plan: %v", decodeErr)
	}
	encoded, err := json.Marshal(version)
	if err != nil {
		t.Fatalf("encoding the format version: %v", err)
	}
	raw["format_version"] = encoded

	bumped, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("encoding the bumped plan: %v", err)
	}

	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, bumped, 0o600); err != nil {
		t.Fatalf("writing the bumped plan: %v", err)
	}

	return path
}

func TestLoadPlanAcceptsEveryMajorOneFormatVersion(t *testing.T) {
	for _, version := range []string{"1", "1.2", "1.99"} {
		t.Run(version, func(t *testing.T) {
			plan, err := loader.LoadPlan(planWithFormatVersion(t, version))
			if err != nil {
				t.Fatalf("format version %s was refused: %v", version, err)
			}
			if plan.FormatVersion != version {
				t.Fatalf("format version is %q, want %q", plan.FormatVersion, version)
			}
		})
	}
}

func TestLoadPlanWithoutAFormatVersionIsAnInputError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(`{"terraform_version": "1.12.6"}`), 0o600); err != nil {
		t.Fatalf("writing the plan: %v", err)
	}

	plan, err := loader.LoadPlan(path)
	if err == nil {
		t.Fatal("a JSON document that is not a plan loaded without an error")
	}
	if plan != nil {
		t.Fatalf("a JSON document that is not a plan returned a plan: %+v", plan)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadPlanMissingFileIsAnInputError(t *testing.T) {
	plan, err := loader.LoadPlan(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("a missing plan file loaded without an error")
	}
	if plan != nil {
		t.Fatalf("a missing plan file returned a plan: %+v", plan)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadConfig(t *testing.T) {
	cases := []struct {
		name  string
		root  string
		files []string
	}{
		{
			name:  "served-leaf",
			root:  filepath.Join(fixtureRoot, "report", "served-leaf", "input"),
			files: []string{"main.tf"},
		},
		{
			name:  "blueprint-wrapper",
			root:  filepath.Join(fixtureRoot, "report", "blueprint-wrapper", "input"),
			files: []string{"main.tf"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive, err := loader.LoadConfig(tc.root)
			if err != nil {
				t.Fatalf("LoadConfig(%s) returned an error: %v", tc.root, err)
			}
			if archive.Root != tc.root {
				t.Fatalf("Root is %q, want %q", archive.Root, tc.root)
			}
			if got := paths(archive.Files); !equal(got, tc.files) {
				t.Fatalf("files are %v, want %v", got, tc.files)
			}
			if archive.Lockfile != nil {
				t.Fatalf("a fixture with no lock file got one: %+v", archive.Lockfile)
			}

			// The bytes are the file as it is on disk, not a re-render of it.
			want, err := os.ReadFile(filepath.Join(tc.root, archive.Files[0].Path))
			if err != nil {
				t.Fatalf("reading the fixture file: %v", err)
			}
			if string(archive.Files[0].Bytes) != string(want) {
				t.Fatal("the archived bytes differ from the bytes on disk")
			}
		})
	}
}

func TestLoadConfigOrdersFilesAndSkipsTerraformDirectories(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("creating %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", rel, err)
		}
	}

	// A directory sorts before a sibling file when the tree is walked, so an
	// archive that just appends what the walk yields is not in path order.
	write("modules/vpc/main.tf", "# vpc\n")
	write("modules.tf", "# calls\n")
	write("main.tf", "# root\n")
	write("override.tofu", "# tofu\n")
	write("generated.tf.json", `{"resource": {}}`)
	write("outputs.tofu.json", `{"output": {}}`)
	write("README.md", "not configuration\n")
	// A name that is exactly a suffix is a dotfile, not a configuration file.
	write(".tf", "not configuration\n")
	write(".tofu.json", "not configuration\n")
	write("terraform.tfvars", "not configuration\n")
	write(".terraform/modules/s3/main.tf", "# vendored\n")
	write(".terraform.d/plugin-cache/main.tf", "# cached\n")

	archive, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}

	want := []string{
		"generated.tf.json",
		"main.tf",
		"modules.tf",
		"modules/vpc/main.tf",
		"outputs.tofu.json",
		"override.tofu",
	}
	if got := paths(archive.Files); !equal(got, want) {
		t.Fatalf("files are %v, want %v", got, want)
	}

	// Ordering alone would not catch an archive that mangled the bytes of any
	// file after the first, so every file is compared against its own source.
	for _, file := range archive.Files {
		onDisk, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatalf("reading %s: %v", file.Path, err)
		}
		if string(file.Bytes) != string(onDisk) {
			t.Fatalf("the archived bytes of %s differ from the bytes on disk", file.Path)
		}
	}
}

func TestLoadConfigIgnoresASymlinkedDirectory(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "hidden.tf"), []byte("# hidden\n"), 0o600); err != nil {
		t.Fatalf("writing the outside file: %v", err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("# root\n"), 0o600); err != nil {
		t.Fatalf("writing main.tf: %v", err)
	}
	// A walk does not descend into a symlinked directory. The name has no
	// configuration suffix, so the link is not a file candidate either, and
	// nothing under it reaches the archive.
	if err := os.Symlink(outside, filepath.Join(root, "vendored")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	archive, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}
	if got := paths(archive.Files); !equal(got, []string{"main.tf"}) {
		t.Fatalf("files are %v, want [main.tf]", got)
	}
}

// A root given as a symlink to the configuration directory is walked where it
// points: WalkDir does not follow a symlinked root,
// so without resolving it first `report --path <link>` would read no root
// file. Paths stay relative to the root.
func TestLoadConfigFollowsASymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "main.tf"), []byte("# root\n"), 0o600); err != nil {
		t.Fatalf("writing main.tf: %v", err)
	}
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	archive, err := loader.LoadConfig(link)
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}
	if got := paths(archive.Files); !equal(got, []string{"main.tf"}) {
		t.Fatalf("files are %v, want [main.tf]", got)
	}
}

func TestLoadConfigParsesTheLockFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("# root\n"), 0o600); err != nil {
		t.Fatalf("writing main.tf: %v", err)
	}
	lock := `provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.100.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:aaaa",
    "zh:bbbb",
  ]
}

provider "registry.terraform.io/hashicorp/random" {
  version = "3.7.2"
}
`
	if err := os.WriteFile(filepath.Join(root, ".terraform.lock.hcl"), []byte(lock), 0o600); err != nil {
		t.Fatalf("writing the lock file: %v", err)
	}

	archive, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}
	if got := paths(archive.Files); !equal(got, []string{"main.tf"}) {
		t.Fatalf("the lock file is not a configuration file, got %v", got)
	}
	if archive.Lockfile == nil {
		t.Fatal("the lock file was not parsed")
	}
	if len(archive.Lockfile.Providers) != 2 {
		t.Fatalf("got %d providers, want 2", len(archive.Lockfile.Providers))
	}

	aws := archive.Lockfile.Providers[0]
	if aws.Source != "registry.terraform.io/hashicorp/aws" {
		t.Fatalf("source is %q", aws.Source)
	}
	if aws.Version != "5.100.0" || aws.Constraints != "~> 5.0" {
		t.Fatalf("version %q constraints %q", aws.Version, aws.Constraints)
	}
	if !equal(aws.Hashes, []string{"h1:aaaa", "zh:bbbb"}) {
		t.Fatalf("hashes are %v", aws.Hashes)
	}

	random := archive.Lockfile.Providers[1]
	if random.Version != "3.7.2" || random.Constraints != "" || len(random.Hashes) != 0 {
		t.Fatalf("the second provider is %+v", random)
	}
}

func TestLoadConfigBrokenLockFileIsAnInputError(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".terraform.lock.hcl"), []byte("provider {\n"), 0o600); err != nil {
		t.Fatalf("writing the lock file: %v", err)
	}

	archive, err := loader.LoadConfig(root)
	if err == nil {
		t.Fatal("a broken lock file loaded without an error")
	}
	if archive != nil {
		t.Fatalf("a broken lock file returned an archive: %+v", archive)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadConfigMissingRootIsAnInputError(t *testing.T) {
	archive, err := loader.LoadConfig(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("a missing configuration directory loaded without an error")
	}
	if archive != nil {
		t.Fatalf("a missing configuration directory returned an archive: %+v", archive)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadConfigDanglingSymlinkIsAnInputError(t *testing.T) {
	root := t.TempDir()
	// The target of a symlink is written by the repository under analysis, so
	// it is input text and must not reach the diagnostic.
	const canary = "SECRET_CANARY_TARGET"
	if err := os.Symlink(filepath.Join(root, canary, "gone.tf"), filepath.Join(root, "link.tf")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	archive, err := loader.LoadConfig(root)
	if err == nil {
		t.Fatal("a dangling symlink loaded without an error")
	}
	if archive != nil {
		t.Fatalf("a dangling symlink returned an archive: %+v", archive)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("the diagnostic echoes the symlink target from the file under analysis: %v", err)
	}
}

func TestLoadConfigDanglingLockFileSymlinkIsAnInputError(t *testing.T) {
	root := t.TempDir()
	// A broken link where the lock file should be is not the same as having
	// no lock file, so it is an error and not a silent nil.
	if err := os.Symlink(filepath.Join(root, "gone.hcl"), filepath.Join(root, ".terraform.lock.hcl")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	archive, err := loader.LoadConfig(root)
	if err == nil {
		t.Fatalf("a dangling lock file link was treated as no lock file: %+v", archive.Lockfile)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadConfigEmptyRoot(t *testing.T) {
	archive, err := loader.LoadConfig(t.TempDir())
	if err != nil {
		t.Fatalf("an empty configuration directory is not an error, got %v", err)
	}
	if len(archive.Files) != 0 {
		t.Fatalf("an empty configuration directory produced files: %v", paths(archive.Files))
	}
	if archive.Lockfile != nil {
		t.Fatal("an empty configuration directory produced a lock file")
	}
}

func TestLoadConfigReadsASymlinkInsideTheRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "shared.tf"), []byte("# shared\n"), 0o600); err != nil {
		t.Fatalf("writing the target: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "shared.tf"), filepath.Join(root, "link.tf")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	archive, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}
	if got := paths(archive.Files); !equal(got, []string{"link.tf", "shared.tf"}) {
		t.Fatalf("files are %v, want [link.tf shared.tf]", got)
	}
	if string(archive.Files[0].Bytes) != "# shared\n" {
		t.Fatalf("the link was not read as its target: %q", archive.Files[0].Bytes)
	}
}

func TestLoadConfigRefusesASymlinkOutOfTheRoot(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "outside.tf")
	if err := os.WriteFile(secret, []byte("# not part of the repository\n"), 0o600); err != nil {
		t.Fatalf("writing the outside file: %v", err)
	}

	root := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(root, "escape.tf")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	archive, err := loader.LoadConfig(root)
	if err == nil {
		t.Fatal("a symlink pointing out of the root loaded without an error")
	}
	if archive != nil {
		t.Fatalf("a symlink pointing out of the root returned an archive: %+v", archive)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
	if strings.Contains(err.Error(), "not part of the repository") {
		t.Fatalf("the error carries the content of the file it refused: %v", err)
	}
}

func TestLoadConfigRefusesALockFileSymlinkedOutOfTheRoot(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "outside.hcl")
	lock := `provider "registry.terraform.io/hashicorp/aws" {
  version = "OUTSIDE-ROOT-SECRET"
}
`
	if err := os.WriteFile(secret, []byte(lock), 0o600); err != nil {
		t.Fatalf("writing the outside lock file: %v", err)
	}

	root := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(root, ".terraform.lock.hcl")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	archive, err := loader.LoadConfig(root)
	if err == nil {
		t.Fatalf("a lock file symlinked out of the root loaded without an error: %+v", archive.Lockfile)
	}
	if archive != nil {
		t.Fatalf("a lock file symlinked out of the root returned an archive: %+v", archive)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
	if strings.Contains(err.Error(), "OUTSIDE-ROOT-SECRET") {
		t.Fatalf("the error carries the content of the file it refused: %v", err)
	}
}

func TestLoadConfigRefusesARelativeSymlinkOutOfTheRoot(t *testing.T) {
	parent := t.TempDir()
	secret := filepath.Join(parent, "outside.tf")
	if err := os.WriteFile(secret, []byte("# outside\n"), 0o600); err != nil {
		t.Fatalf("writing the outside file: %v", err)
	}

	root := filepath.Join(parent, "repo")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("creating the root: %v", err)
	}
	if err := os.Symlink(filepath.Join("..", "outside.tf"), filepath.Join(root, "escape.tf")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	if _, err := loader.LoadConfig(root); err == nil {
		t.Fatal("a relative symlink out of the root loaded without an error")
	} else if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadConfigLockFileErrorCarriesNoInputText(t *testing.T) {
	root := t.TempDir()
	// The block type is attacker-authored text. HCL quotes it in its own
	// diagnostic, and the specification says a diagnostic names the file and
	// the reason, never input text.
	const canary = "SECRET_CANARY_BLOCK_NAME"
	body := canary + ` "x" {
  version = "1.0"
}
`
	if err := os.WriteFile(filepath.Join(root, ".terraform.lock.hcl"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing the lock file: %v", err)
	}

	_, err := loader.LoadConfig(root)
	if err == nil {
		t.Fatal("an unexpected block in the lock file loaded without an error")
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("the diagnostic echoes text from the file under analysis: %v", err)
	}
}

func TestLoadConfigRootIsAFileIsAnInputError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.tf")
	if err := os.WriteFile(path, []byte("# root\n"), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}

	archive, err := loader.LoadConfig(path)
	if err == nil {
		t.Fatal("a file used as a configuration directory loaded without an error")
	}
	if archive != nil {
		t.Fatalf("a file used as a configuration directory returned an archive: %+v", archive)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func paths(files []ctfkit.ConfigFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// LoadPlanBytes returns the exact bytes on disk next to the parsed plan.
func TestLoadPlanBytesReturnsTheFileBytes(t *testing.T) {
	path := filepath.Join(fixtureRoot, "plan", planCases[0], "input", "plan.json")
	plan, raw, err := loader.LoadPlanBytes(path)
	if err != nil || plan == nil {
		t.Fatalf("LoadPlanBytes(%s): %v", path, err)
	}
	want, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("returned bytes differ from the file (%v)", err)
	}
}

// beyondFloat64 are numbers the instance_key format accepts (FORMAT.md
// Numbers) and float64 cannot hold: 1e1000, and the 1001-digit text cty
// writes for the same value.
var beyondFloat64 = map[string]string{
	"exponent":    "1e1000",
	"cty decimal": "1" + strings.Repeat("0", 1000),
}

// numbersPlan is a plan that carries n in a planned value, a change, the
// prior state and a configuration constant, next to the in-range number 5.
func numbersPlan(n string) string {
	return `{"format_version":"1.2","terraform_version":"1.12.6",
"planned_values":{"root_module":{"resources":[{"address":"edge_thing.a","mode":"managed","type":"edge_thing","name":"a","values":{"n":` + n + `,"m":5}}]}},
"resource_changes":[{"address":"edge_thing.a","mode":"managed","type":"edge_thing","name":"a","change":{"actions":["update"],"before":{"n":-` + n + `,"m":5},"after":{"n":` + n + `,"m":5}}}],
"prior_state":{"format_version":"1.0","values":{"root_module":{"resources":[{"address":"edge_thing.a","mode":"managed","type":"edge_thing","name":"a","values":{"n":-` + n + `}}]}}},
"configuration":{"root_module":{"resources":[{"address":"edge_thing.a","mode":"managed","type":"edge_thing","name":"a","expressions":{"n":{"constant_value":` + n + `}}}]}}}`
}

func writePlan(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing the plan: %v", err)
	}
	return path
}

// A number beyond float64 loads as +-1e308 wherever the plan holds it, and an
// in-range number is unchanged.
func TestLoadPlanSaturatesNumbersBeyondFloat64(t *testing.T) {
	for name, n := range beyondFloat64 {
		t.Run(name, func(t *testing.T) {
			plan, err := loader.LoadPlan(writePlan(t, numbersPlan(n)))
			if err != nil {
				t.Fatalf("LoadPlan: %v", err)
			}
			change := plan.ResourceChanges[0].Change
			after, _ := change.After.(map[string]any)
			before, _ := change.Before.(map[string]any)
			planned := plan.PlannedValues.RootModule.Resources[0].AttributeValues
			prior := plan.PriorState.Values.RootModule.Resources[0].AttributeValues
			constant := plan.Config.RootModule.Resources[0].Expressions["n"].ConstantValue
			got := []any{after["n"], before["n"], planned["n"], prior["n"], constant, after["m"]}
			want := []any{1e308, -1e308, 1e308, -1e308, 1e308, 5.0}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("value %d is %v, want %v", i, got[i], want[i])
				}
			}
		})
	}
}

// Underflow is not out of range: ParseFloat rounds 1e-1000 to 0 without an
// error, so such a number reads as zero, never saturated to +-1e308.
func TestLoadPlanUnderflowReadsAsZero(t *testing.T) {
	plan, err := loader.LoadPlan(writePlan(t, numbersPlan("1e-1000")))
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	after, _ := plan.ResourceChanges[0].Change.After.(map[string]any)
	before, _ := plan.ResourceChanges[0].Change.Before.(map[string]any)
	if after["n"] != 0.0 || before["n"] != 0.0 {
		t.Fatalf("after %v, before %v; want 0", after["n"], before["n"])
	}
}

// A plan that does not decode reports where, never the value it holds.
func TestLoadPlanErrorNeverQuotesANumber(t *testing.T) {
	for name, n := range beyondFloat64 {
		for shape, content := range map[string]string{
			"wrong type": `{"format_version":"1.2","terraform_version":` + n + `}`,
			"truncated":  `{"format_version":"1.2","variables":{"v":{"value":` + n,
			"bad syntax": `{"format_version":"1.2","variables":{"v":{"value":` + n + `x}}}`,
		} {
			t.Run(name+"/"+shape, func(t *testing.T) {
				plan, err := loader.LoadPlan(writePlan(t, content))
				if err == nil || plan != nil {
					t.Fatalf("LoadPlan = %v, %v; want an error", plan, err)
				}
				if !errors.Is(err, loader.ErrInput) {
					t.Fatalf("error %v is not an ErrInput", err)
				}
				for _, value := range []string{n, "1e+1000", "1e308", "10000000000"} {
					if strings.Contains(err.Error(), value) {
						t.Fatalf("error %q quotes %.20s", err, value)
					}
				}
			})
		}
	}
}
