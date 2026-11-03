package loader_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// manifestFileName is the file LoadModules looks for in each instance
// directory. The test names it itself rather than importing it, so a rename
// in the package under test has to be defended here too.
const manifestFileName = "compliancetf-manifest.json"

// moduleCase is one report fixture and what its module inventory must hold.
// Keys and directories are in the order modules.json lists them; a directory
// is the value the file records, POSIX separated.
type moduleCase struct {
	name string
	keys []string
	dirs []string
	// withoutManifest are the keys whose instance directory holds no
	// manifest. Every other key must have one.
	withoutManifest []string
}

var moduleCases = []moduleCase{
	{
		name: "blueprint-wrapper",
		keys: []string{"s3_bucket"},
		dirs: []string{".terraform/modules/s3_bucket"},
	},
	{
		name: "degraded-build",
		keys: []string{"s3_bucket"},
		dirs: []string{".terraform/modules/s3_bucket"},
	},
	{
		name: "delegated-with-sibling",
		keys: []string{"s3_account_public_access", "s3_bucket", "s3_bucket_notification"},
		dirs: []string{
			".terraform/modules/s3_account_public_access/modules/account-public-access",
			".terraform/modules/s3_bucket",
			".terraform/modules/s3_bucket_notification/modules/notification",
		},
	},
	{
		name: "delegated-without-sibling",
		keys: []string{"s3_bucket"},
		dirs: []string{".terraform/modules/s3_bucket"},
	},
	{
		name: "example-multi-instance",
		keys: []string{"archive", "artifacts", "data"},
		dirs: []string{
			".terraform/modules/archive",
			".terraform/modules/artifacts",
			".terraform/modules/data",
		},
	},
	{
		name: "helper-module",
		keys: []string{"naming", "s3_bucket"},
		dirs: []string{"modules/naming", ".terraform/modules/s3_bucket"},
		// A local helper of data, locals and outputs has no manifest either.
		withoutManifest: []string{"naming"},
	},
	{
		name: "missing-manifest",
		keys: []string{"replication_role", "s3_bucket"},
		dirs: []string{"modules/replication_role", ".terraform/modules/s3_bucket"},
		// A local module was never served, so it has no manifest. That is a
		// finding for the analyzer to make, not an error for the loader.
		withoutManifest: []string{"replication_role"},
	},
	{
		name: "served-leaf",
		keys: []string{"s3_bucket_notification"},
		dirs: []string{".terraform/modules/s3_bucket_notification/modules/notification"},
	},
	{
		name: "supporting-clauses",
		keys: []string{"s3_bucket"},
		dirs: []string{".terraform/modules/s3_bucket"},
	},
}

func TestLoadModules(t *testing.T) {
	for _, tc := range moduleCases {
		t.Run(tc.name, func(t *testing.T) {
			root := reportFixtureRoot(tc.name)

			inventory, err := loader.LoadModules(root)
			if err != nil {
				t.Fatalf("LoadModules(%s) returned an error: %v", root, err)
			}
			if inventory.Root != root {
				t.Fatalf("Root is %q, want %q", inventory.Root, root)
			}
			if got := instanceKeys(inventory); !equal(got, tc.keys) {
				t.Fatalf("keys are %v, want %v", got, tc.keys)
			}
			if got := instanceDirs(inventory); !equal(got, tc.dirs) {
				t.Fatalf("directories are %v, want %v", got, tc.dirs)
			}

			absent := make(map[string]bool, len(tc.withoutManifest))
			for _, key := range tc.withoutManifest {
				absent[key] = true
			}

			for _, instance := range inventory.Instances {
				if instance.Source == "" {
					t.Errorf("instance %s has no source", instance.Key)
				}
				if instance.Provenance != ctfkit.ProvenanceLocalUnverified {
					t.Errorf("instance %s has provenance %q, want %q",
						instance.Key, instance.Provenance, ctfkit.ProvenanceLocalUnverified)
				}

				if absent[instance.Key] {
					if instance.Manifest != nil {
						t.Errorf("instance %s has a manifest and should have none", instance.Key)
					}
					if instance.ManifestSHA256 != "" {
						t.Errorf("instance %s has no manifest but carries digest %q",
							instance.Key, instance.ManifestSHA256)
					}
					continue
				}

				if instance.Manifest == nil {
					t.Errorf("instance %s has no manifest and should have one", instance.Key)
					continue
				}
				if major, _, _ := strings.Cut(instance.Manifest.SchemaVersion, "."); major != "3" {
					t.Errorf("instance %s has schema version %q, want major 3",
						instance.Key, instance.Manifest.SchemaVersion)
				}
				// The digest is over the bytes on disk, so it is compared
				// against those bytes and never against a re-serialization
				// of the parsed value.
				want := digestOnDisk(t, filepath.Join(root, filepath.FromSlash(instance.Dir), manifestFileName))
				if instance.ManifestSHA256 != want {
					t.Errorf("instance %s has digest %q, want %q",
						instance.Key, instance.ManifestSHA256, want)
				}
			}
		})
	}
}

// TestLoadModulesRecordsModulesThatDeclareNoResources records the loader's
// reading of each instance's own directory: a helper with only data, locals
// and outputs declares no resources, a module with a resource block does, and
// a directory the loader cannot judge (no configuration files, a JSON file,
// a file that does not parse, a directory above the root) is never marked
// resource-free.
func TestLoadModulesRecordsModulesThatDeclareNoResources(t *testing.T) {
	cases := []struct {
		fixture string
		want    map[string]bool
	}{
		{fixture: "helper-module", want: map[string]bool{"naming": true, "s3_bucket": false}},
		{fixture: "missing-manifest", want: map[string]bool{"replication_role": false, "s3_bucket": false}},
	}
	for _, tc := range cases {
		inventory, err := loader.LoadModules(reportFixtureRoot(tc.fixture))
		if err != nil {
			t.Fatalf("LoadModules(%s): %v", tc.fixture, err)
		}
		for _, instance := range inventory.Instances {
			if got := instance.DeclaresNoResources; got != tc.want[instance.Key] {
				t.Errorf("%s: instance %s DeclaresNoResources = %v, want %v",
					tc.fixture, instance.Key, got, tc.want[instance.Key])
			}
		}
	}

	// Each row is one module directory, judged alone. Every row but the
	// resource-free ones must keep the finding (false).
	rows := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{name: "locals only", files: map[string]string{"main.tf": `locals {}`}, want: true},
		{name: "no configuration file", files: map[string]string{"README.md": `helper`}},
		{name: "parse error", files: map[string]string{"main.tf": `locals {`}},
		{name: "json without a resource", files: map[string]string{"main.tf.json": `{"locals": {}}`}, want: true},
		{name: "tofu json without a resource", files: map[string]string{"main.tofu.json": `{"locals": [{}]}`}, want: true},
		{name: "json parse error", files: map[string]string{"main.tf.json": `{"locals": `}},
		{name: "json with a resource", files: map[string]string{
			"main.tf.json": `{"resource": {"null_resource": {"this": {}}}}`,
		}},
		{name: "override file with a resource", files: map[string]string{
			"main.tf":       `locals {}`,
			"x_override.tf": `resource "null_resource" "this" {}`,
		}},
		{name: "tofu file with a resource", files: map[string]string{
			"main.tf":   `locals {}`,
			"main.tofu": `resource "null_resource" "this" {}`,
		}},
		{name: "resource in a second file", files: map[string]string{
			"main.tf":      `locals {}`,
			"resources.tf": `resource "null_resource" "this" {}`,
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			for name, body := range row.files {
				writeModuleFile(t, root, "modules/m/"+name, body)
			}
			writeModulesJSON(t, root, `{"Modules":[{"Key":"m","Source":"./modules/m","Dir":"modules/m"}]}`)

			if got := loadOne(t, root)["m"]; got != row.want {
				t.Errorf("DeclaresNoResources = %v, want %v", got, row.want)
			}
		})
	}

	// A wrapper whose only block is a module call is resource-free; its child
	// is a separate instance judged on its own directory.
	t.Run("nested", func(t *testing.T) {
		root := t.TempDir()
		writeModuleFile(t, root, "modules/nested/main.tf",
			"module \"child\" {\n  source   = \"./child\"\n  for_each = {}\n}\n")
		writeModuleFile(t, root, "modules/nested/child/main.tf", `resource "null_resource" "this" {}`)
		writeModulesJSON(t, root, `{"Modules":[`+
			`{"Key":"nested","Source":"./modules/nested","Dir":"modules/nested"},`+
			`{"Key":"nested.child","Source":"./child","Dir":"modules/nested/child"}]}`)

		got := loadOne(t, root)
		if !got["nested"] || got["nested.child"] {
			t.Errorf("DeclaresNoResources = %v, want nested true and nested.child false", got)
		}
	})

	// A served instance has a manifest, so the directory is never judged.
	t.Run("manifest present", func(t *testing.T) {
		root := t.TempDir()
		writeModuleFile(t, root, "modules/served/main.tf", `locals {}`)
		writeManifest(t, root, "modules/served", `{"schema_version": "3.3"}`)
		writeModulesJSON(t, root, `{"Modules":[{"Key":"served","Source":"./modules/served","Dir":"modules/served"}]}`)

		if loadOne(t, root)["served"] {
			t.Error("an instance with a manifest was judged resource-free")
		}
	})
}

// TestLoadModulesReadsInstanceFiles: every instance, served or not, carries
// the configuration files directly in its directory, all four suffixes and
// override files included, in path order with root-relative paths and their
// exact bytes. Subdirectories and other files are not read.
func TestLoadModulesReadsInstanceFiles(t *testing.T) {
	root := t.TempDir()
	dir := ".terraform/modules/app"
	for _, name := range []string{"main.tf", "main.tofu", "x.tf.json", "y.tofu.json", "z_override.tf", "README.md", "sub/child.tf"} {
		writeModuleFile(t, root, dir+"/"+name, "# "+name)
	}
	writeManifest(t, root, dir, `{"schema_version": "3.3"}`)
	writeModulesJSON(t, root, `{"Modules":[`+
		`{"Key":"app","Source":"bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws","Dir":"`+dir+`"}]}`)

	inventory, err := loader.LoadModules(root)
	if err != nil {
		t.Fatalf("LoadModules: %v", err)
	}
	var got []string
	for _, f := range inventory.Instances[0].Files {
		got = append(got, f.Path)
		if want := "# " + strings.TrimPrefix(f.Path, dir+"/"); string(f.Bytes) != want {
			t.Errorf("%s holds %q, want %q", f.Path, f.Bytes, want)
		}
	}
	want := []string{dir + "/main.tf", dir + "/main.tofu", dir + "/x.tf.json", dir + "/y.tofu.json", dir + "/z_override.tf"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Files = %q, want %q", got, want)
	}
}

// TestLoadModulesLocalModuleDirectories pins where a module directory may be
// and what happens when it is not there.
//
// modules.json is written as terraform init and tofu init write it: a local
// module's Dir is filepath.Join(parent.Dir, source) with symlinks resolved
// (installLocalModule, internal/initwd/module_install.go, Terraform v1.17.0
// and OpenTofu v1.13.1; testdata/loader/tofu-local-layout is a recording).
//
// The containment matrix, for a root repo with a sibling repo-evil:
//
//   - an explicit ../repo-evil source: read, like any ./ or ../ source,
//     manifest included; the source names it and terraform runs it.
//   - repo-evil reached by a ./ source through a symlink, or recorded for a
//     remote module: exit 2. Paths are compared by component after resolving,
//     so repo-evil is never "inside" repo by string prefix either.
//   - a child source is joined to its parent's resolved directory, as init
//     joins it: a ../alias resolving to ../libs/pkg that calls ../hook reads
//     ../libs/hook, and a record naming the decoy ../hook instead is exit 2.
//   - a directory that does not resolve, or resolves and cannot be listed:
//     exit 2. Every exit-2 message prints a directory or source through
//     ctfkit.RedactSource, never a token or query from it.
func TestLoadModulesLocalModuleDirectories(t *testing.T) {
	const rootRecord = `{"Key":"","Source":"","Dir":"."},`
	block := func(name, source string) string {
		return "module \"" + name + "\" {\n  source = \"" + source + "\"\n}\n"
	}
	rootCalls := block("shared", "../shared") + block("lib", "../lib") + block("evil", "../repo-evil") +
		block("alias", "../alias") + block("leak", "../CANARY-u:CANARY-t@gone?sshkey=CANARY-k")
	hookCall := block("hook", "../hook")
	type layout struct{ parent, root string }
	setup := func(t *testing.T) layout {
		t.Helper()
		parent := t.TempDir()
		writeModuleFile(t, parent, "shared/main.tf", `resource "terraform_data" "x" {}`)
		writeModuleFile(t, parent, "outside/main.tf", `locals {}`)
		writeModuleFile(t, parent, "repo-evil/main.tf", `locals {}`)
		root := filepath.Join(parent, "repo")
		// The calls the records below make from the root: a ../ record is
		// read only when a module block of its caller declares it.
		writeModuleFile(t, root, "main.tf", rootCalls)
		return layout{parent: parent, root: root}
	}
	link := func(t *testing.T, target, at string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(at), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, at); err != nil {
			t.Skipf("this filesystem does not support symlinks: %v", err)
		}
	}

	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, l layout) string // returns the records after the root's
		key     string                              // instance whose files must be read; empty means exit 2
		want    string                              // a file path the instance must carry, or the error text
	}{
		{
			name:    "root calls ../shared",
			prepare: func(*testing.T, layout) string { return `{"Key":"shared","Source":"../shared","Dir":"../shared"}` },
			key:     "shared", want: "../shared/main.tf",
		},
		{
			name: "remote module calls a path out of the root",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.root, ".terraform/modules/app/main.tf", "module \"up\" {\n  source = \"../../../../shared\"\n}\n")
				return `{"Key":"app","Source":"git::https://example.com/bobthecorp/app.git","Dir":".terraform/modules/app"},` +
					`{"Key":"app.up","Source":"../../../../shared","Dir":"../shared"}`
			},
			key: "app.up", want: "../shared/main.tf",
		},
		{
			// A nested ../ record its parent's files do not
			// declare is not a call the configuration makes.
			name: "remote module whose files declare no such call",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.root, ".terraform/modules/app/main.tf", `locals {}`)
				return `{"Key":"app","Source":"git::https://example.com/bobthecorp/app.git","Dir":".terraform/modules/app"},` +
					`{"Key":"app.up","Source":"../../../../shared","Dir":"../shared"}`
			},
			want: "no module block of its caller declares",
		},
		{
			// modules.json alone never authorizes a read
			// outside the root. No root block is named planted.
			name:    "../ record no root module block declares",
			prepare: func(*testing.T, layout) string { return `{"Key":"planted","Source":"../outside","Dir":"../outside"}` },
			want:    "no module block of its caller declares",
		},
		{
			// The block named shared calls ../shared, not ../outside.
			name:    "../ record whose block names another source",
			prepare: func(*testing.T, layout) string { return `{"Key":"shared","Source":"../outside","Dir":"../outside"}` },
			want:    "no module block of its caller declares",
		},
		{
			// A ../ child of a ../ module is authorized by that module's files,
			// and ../shared declares nothing.
			name: "nested ../ record its ../ parent does not declare",
			prepare: func(*testing.T, layout) string {
				return `{"Key":"shared","Source":"../shared","Dir":"../shared"},` +
					`{"Key":"shared.up","Source":"../outside","Dir":"../outside"}`
			},
			want: "no module block of its caller declares",
		},
		{
			// init records a cleaned source: "./sub/" in the block is
			// "./sub" in modules.json, and the two still match.
			name: "nested ./ record declared in an uncleaned form",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.parent, "lib/main.tf", "module \"sub\" {\n  source = \".//sub/\"\n}\n")
				writeModuleFile(t, l.parent, "lib/sub/main.tf", `locals {}`)
				return `{"Key":"lib","Source":"../lib","Dir":"../lib"},{"Key":"lib.sub","Source":"./sub","Dir":"../lib/sub"}`
			},
			key: "lib.sub", want: "../lib/sub/main.tf",
		},
		{
			// init reads "..\outside" as "../outside" on every platform
			// and records it so; the block still declares the record.
			name: "nested ../ record declared with backslashes",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.parent, "lib/main.tf", "module \"up\" {\n  source = \"..\\\\outside\"\n}\n")
				return `{"Key":"lib","Source":"../lib","Dir":"../lib"},{"Key":"lib.up","Source":"../outside","Dir":"../outside"}`
			},
			key: "lib.up", want: "../outside/main.tf",
		},
		{
			// init trims nothing, so "../outside " names a
			// directory whose name ends in a space, never ../outside.
			name: "nested ../ record whose block adds a trailing space",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.parent, "lib/main.tf", "module \"up\" {\n  source = \"../outside \"\n}\n")
				return `{"Key":"lib","Source":"../lib","Dir":"../lib"},{"Key":"lib.up","Source":"../outside","Dir":"../outside"}`
			},
			want: "no module block of its caller declares",
		},
		{
			name: "./x symlinked onto the target of an explicit ../ source",
			prepare: func(t *testing.T, l layout) string {
				link(t, filepath.Join(l.parent, "shared"), filepath.Join(l.root, "x"))
				return `{"Key":"shared","Source":"../shared","Dir":"../shared"},{"Key":"x","Source":"./x","Dir":"x"}`
			},
			key: "x", want: "x/main.tf",
		},
		{
			name: "./x symlinked out of the root",
			prepare: func(t *testing.T, l layout) string {
				link(t, filepath.Join(l.parent, "outside"), filepath.Join(l.root, "x"))
				return `{"Key":"x","Source":"./x","Dir":"x"}`
			},
			want: "leaves the configuration directory",
		},
		{
			name: "./x symlinked out of the root, recorded resolved and relative",
			prepare: func(t *testing.T, l layout) string {
				link(t, filepath.Join(l.parent, "outside"), filepath.Join(l.root, "x"))
				return `{"Key":"x","Source":"./x","Dir":"../outside"}`
			},
			want: "leaves the configuration directory",
		},
		{
			name: "./x symlinked out of the root, recorded resolved and absolute",
			prepare: func(t *testing.T, l layout) string {
				link(t, filepath.Join(l.parent, "outside"), filepath.Join(l.root, "x"))
				return `{"Key":"x","Source":"./x","Dir":"` + filepath.ToSlash(filepath.Join(l.parent, "outside")) + `"}`
			},
			want: "leaves the configuration directory",
		},
		{
			name: "./x symlinked into a sibling whose name extends the root's",
			prepare: func(t *testing.T, l layout) string {
				link(t, filepath.Join(l.parent, "repo-evil"), filepath.Join(l.root, "x"))
				return `{"Key":"x","Source":"./x","Dir":"x"}`
			},
			want: "leaves the configuration directory",
		},
		{
			name: "remote module recorded out of the root",
			prepare: func(*testing.T, layout) string {
				return `{"Key":"app","Source":"git::https://example.com/bobthecorp/app.git","Dir":"../outside"}`
			},
			want: "leaves the configuration directory",
		},
		{
			name: "file symlinked out of the root",
			prepare: func(t *testing.T, l layout) string {
				link(t, filepath.Join(l.parent, "outside", "main.tf"), filepath.Join(l.root, "modules", "m", "main.tf"))
				return `{"Key":"m","Source":"./modules/m","Dir":"modules/m"}`
			},
			want: "leaves the configuration directory",
		},
		{
			// A file symlink in a module directory that resolves inside the
			// root is read: terraform reads it, and so does ctfkit.
			name: "file symlinked inside the root",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.root, "shared/real.tf", `locals {}`)
				link(t, filepath.Join(l.root, "shared", "real.tf"), filepath.Join(l.root, "modules", "m", "main.tf"))
				return `{"Key":"m","Source":"./modules/m","Dir":"modules/m"}`
			},
			key: "m", want: "modules/m/main.tf",
		},
		{
			name: "file in a ../ module symlinked into the root",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.parent, "lib/main.tf", `locals {}`)
				link(t, filepath.Join(l.root, "main.tf"), filepath.Join(l.parent, "lib", "linked.tf"))
				return `{"Key":"lib","Source":"../lib","Dir":"../lib"}`
			},
			key: "lib", want: "../lib/linked.tf",
		},
		{
			// Terraform would execute it, so a file symlink that resolves
			// outside the root and outside its own module is never skipped.
			name: "file in a ../ module symlinked elsewhere outside the root",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.parent, "lib/main.tf", `locals {}`)
				link(t, filepath.Join(l.parent, "outside", "main.tf"), filepath.Join(l.parent, "lib", "linked.tf"))
				return `{"Key":"lib","Source":"../lib","Dir":"../lib"}`
			},
			want: "leaves the configuration directory",
		},
		{
			name:    "directory that does not resolve",
			prepare: func(*testing.T, layout) string { return `{"Key":"gone","Source":"./gone","Dir":"gone"}` },
			want:    "does not resolve",
		},
		{
			name: "directory symlinked inside the root",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.root, "modules/real/main.tf", `locals {}`)
				link(t, filepath.Join(l.root, "modules", "real"), filepath.Join(l.root, "modules", "alias"))
				return `{"Key":"alias","Source":"./modules/alias","Dir":"modules/alias"}`
			},
			key: "alias", want: "modules/alias/main.tf",
		},
		{
			name: "explicit ../repo-evil source",
			prepare: func(*testing.T, layout) string {
				return `{"Key":"evil","Source":"../repo-evil","Dir":"../repo-evil"}`
			},
			key: "evil", want: "../repo-evil/main.tf",
		},
		{
			name: "child joined to its parent's resolved directory, not the decoy",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.parent, "libs/pkg/main.tf", hookCall)
				writeModuleFile(t, l.parent, "libs/hook/main.tf", `locals {}`)
				writeModuleFile(t, l.parent, "hook/main.tf", `locals {}`)
				link(t, filepath.Join(l.parent, "libs", "pkg"), filepath.Join(l.parent, "alias"))
				// As init records it: each Dir resolved.
				return `{"Key":"alias","Source":"../alias","Dir":"../libs/pkg"},` +
					`{"Key":"alias.hook","Source":"../hook","Dir":"../libs/hook"}`
			},
			key: "alias.hook", want: "../libs/hook/main.tf",
		},
		{
			name: "child recorded at the decoy its unresolved join would name",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.parent, "libs/pkg/main.tf", hookCall)
				writeModuleFile(t, l.parent, "libs/hook/main.tf", `locals {}`)
				writeModuleFile(t, l.parent, "hook/main.tf", `locals {}`)
				link(t, filepath.Join(l.parent, "libs", "pkg"), filepath.Join(l.parent, "alias"))
				return `{"Key":"alias","Source":"../alias","Dir":"../libs/pkg"},` +
					`{"Key":"alias.hook","Source":"../hook","Dir":"../hook"}`
			},
			want: "at a directory its source does not name",
		},
		{
			// Not the shape init writes for a test run block (that needs three
			// segments), so it is configuration and is read.
			name: "unknown-shaped test. key",
			prepare: func(t *testing.T, l layout) string {
				writeModuleFile(t, l.root, "x/main.tf", `locals {}`)
				return `{"Key":"test.x","Source":"./x","Dir":"x"}`
			},
			key: "test.x", want: "x/main.tf",
		},
		{
			name: "explicit source that does not resolve, with credentials in it",
			prepare: func(*testing.T, layout) string {
				return `{"Key":"leak","Source":"../CANARY-u:CANARY-t@gone?sshkey=CANARY-k","Dir":"../CANARY-u:CANARY-t@gone?sshkey=CANARY-k"}`
			},
			want: "does not resolve",
		},
		{
			name: "remote module directory that does not resolve, with credentials in it",
			prepare: func(*testing.T, layout) string {
				return `{"Key":"r","Source":"git::https://CANARY-u:CANARY-t@example.com/r.git?sshkey=CANARY-k",` +
					`"Dir":".terraform/modules/CANARY-u:CANARY-t@r"}`
			},
			want: "does not resolve",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := setup(t)
			writeModulesJSON(t, l.root, `{"Modules":[`+rootRecord+tc.prepare(t, l)+`]}`)
			inventory, err := loader.LoadModules(l.root)
			if tc.key == "" {
				if !errors.Is(err, loader.ErrInput) || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("LoadModules error = %v, want an input error containing %q", err, tc.want)
				}
				if err != nil && strings.Contains(err.Error(), "CANARY") {
					t.Errorf("the diagnostic echoes a credential: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadModules: %v", err)
			}
			for _, got := range inventory.Instances {
				if got.Key != tc.key {
					continue
				}
				if len(got.Files) == 0 || got.Files[0].Path != tc.want {
					t.Errorf("instance = %+v, want %s read", got, tc.want)
				}
				return
			}
			t.Errorf("no instance %s in %+v", tc.key, inventory.Instances)
		})
	}

	// A ../ module's manifest outside the root is read like any other: the source
	// that names the directory is explicit.
	t.Run("manifest of a ../ module", func(t *testing.T) {
		l := setup(t)
		writeManifest(t, l.parent, "shared", `{"schema_version": "3.3"}`)
		writeModulesJSON(t, l.root, `{"Modules":[`+rootRecord+`{"Key":"shared","Source":"../shared","Dir":"../shared"}]}`)
		inventory, err := loader.LoadModules(l.root)
		if err != nil {
			t.Fatalf("LoadModules: %v", err)
		}
		if got := inventory.Instances[0]; got.Manifest == nil || got.ManifestSHA256 == "" {
			t.Errorf("instance = %+v, want its manifest read", got)
		}
	})

	// The root record is not trusted as the root. One
	// recorded at ../outside would make the root's ./sub call a join from
	// there, and ../outside/sub would be read as if the configuration had
	// named it, though the root block names ./sub inside the root. Every
	// placement init does not write is exit 2, and the read never happens.
	t.Run("root record anchored outside the root", func(t *testing.T) {
		for name, dir := range map[string]string{
			"relative":       "../outside",
			"absolute":       "",
			"does not exist": "../CANARY-u:CANARY-t@gone",
		} {
			t.Run(name, func(t *testing.T) {
				l := setup(t)
				writeModuleFile(t, l.parent, "outside/sub/main.tf", `resource "terraform_data" "planted" {}`)
				writeModuleFile(t, l.root, "main.tf", block("x", "./sub"))
				if dir == "" {
					dir = filepath.ToSlash(filepath.Join(l.parent, "outside"))
				}
				writeModulesJSON(t, l.root, `{"Modules":[{"Key":"","Source":"","Dir":"`+dir+`"},`+
					`{"Key":"x","Source":"./sub","Dir":"../outside/sub"}]}`)
				inventory, err := loader.LoadModules(l.root)
				if !errors.Is(err, loader.ErrInput) || !strings.Contains(err.Error(), "records the root module at a directory other than") {
					t.Fatalf("LoadModules = %+v, %v; want an input error for the root record", inventory, err)
				}
				if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "outside") {
					t.Errorf("the diagnostic echoes the record: %v", err)
				}
			})
		}
	})

	// A directory that resolves and cannot be listed is exit 2: init installed
	// it, so terraform reads it, and ctfkit was not shown its files.
	t.Run("directory that cannot be listed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a directory whatever its mode")
		}
		l := setup(t)
		locked := filepath.Join(l.parent, "shared")
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o750) }) //nolint:gosec // restores a test directory so TempDir can remove it
		writeModulesJSON(t, l.root, `{"Modules":[`+rootRecord+`{"Key":"shared","Source":"../shared","Dir":"../shared"}]}`)
		_, err := loader.LoadModules(l.root)
		if !errors.Is(err, loader.ErrInput) || !strings.Contains(err.Error(), "cannot be listed") {
			t.Errorf("LoadModules error = %v, want an input error naming the unlistable directory", err)
		}
	})
}

// recordedLayout is a configuration whose .terraform/modules/modules.json was
// written by `tofu init` with the pinned OpenTofu 1.12.6 (mise.toml), local
// only: no provider, no backend. Only the module files were edited after the
// recording, which does not change what init records. It holds a "../shared"
// call with a "./sub" child, a root module call named "test" with a "hook"
// child, and a main.tftest.hcl run block whose module init keyed
// test.main.setup. If a release changes how init writes any of these, this
// test fails.
const recordedLayout = "../../testdata/loader/tofu-local-layout/repo"

// TestLoadModulesRecordedTofuLayout reads the recording. The ../ module and
// its child are read from beside the root; the root call named test and its
// child are configuration (a test. key is a harness
// module only when init wrote no record for one of its prefixes); the run
// block's module is excluded.
func TestLoadModulesRecordedTofuLayout(t *testing.T) {
	inventory, err := loader.LoadModules(recordedLayout)
	if err != nil {
		t.Fatalf("LoadModules: %v", err)
	}
	got := map[string]string{}
	var keys []string
	for _, instance := range inventory.Instances {
		keys = append(keys, instance.Key)
		if len(instance.Files) > 0 {
			got[instance.Key] = instance.Files[0].Path
		}
	}
	if want := []string{"shared", "shared.sub", "test", "test.hook"}; strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("keys = %q, want %q", keys, want)
	}
	for key, want := range map[string]string{
		"shared": "../shared/main.tf", "shared.sub": "../shared/sub/main.tf",
		"test": "test/main.tf", "test.hook": "test/hook/main.tf",
	} {
		if got[key] != want {
			t.Errorf("%s reads %q first, want %q", key, got[key], want)
		}
	}
}

// loadOne loads root and maps every instance key to its DeclaresNoResources.
func loadOne(t *testing.T, root string) map[string]bool {
	t.Helper()

	inventory, err := loader.LoadModules(root)
	if err != nil {
		t.Fatalf("LoadModules: %v", err)
	}
	got := make(map[string]bool, len(inventory.Instances))
	for _, instance := range inventory.Instances {
		got[instance.Key] = instance.DeclaresNoResources
	}

	return got
}

func writeModuleFile(t *testing.T, root, name, body string) {
	t.Helper()

	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("creating the directory of %s: %v", name, err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// TestLoadModulesServedLeafDigest pins one digest to the literal value
// sha256sum prints for that file, so a change in how the bytes are read is
// caught even if the comparison helper drifted with it.
func TestLoadModulesServedLeafDigest(t *testing.T) {
	const want = "bd6add96ced9ccad50c15d3e6e68d0a90efc227f4a23ae8fe5b909eac4e2ce95"

	inventory, err := loader.LoadModules(reportFixtureRoot("served-leaf"))
	if err != nil {
		t.Fatalf("LoadModules returned an error: %v", err)
	}
	if len(inventory.Instances) != 1 {
		t.Fatalf("got %d instances, want 1", len(inventory.Instances))
	}

	instance := inventory.Instances[0]
	if instance.ManifestSHA256 != want {
		t.Fatalf("digest is %q, want %q", instance.ManifestSHA256, want)
	}
	if instance.Provenance != "local-unverified" {
		t.Fatalf("provenance is %q, want local-unverified", instance.Provenance)
	}
}

// TestLoadModulesParsesTheTypedSubset checks the fields analyzers read,
// including the two tri-state ones: a producer that classified and found
// nothing is not the same as a producer that never classified.
func TestLoadModulesParsesTheTypedSubset(t *testing.T) {
	inventory, err := loader.LoadModules(reportFixtureRoot("served-leaf"))
	if err != nil {
		t.Fatalf("LoadModules returned an error: %v", err)
	}

	manifest := inventory.Instances[0].Manifest
	if manifest.SchemaVersion != "3.3" {
		t.Errorf("schema version is %q, want 3.3", manifest.SchemaVersion)
	}
	if manifest.ControlsScope != "subtree" {
		t.Errorf("controls scope is %q, want subtree", manifest.ControlsScope)
	}
	if manifest.ScopePath != "modules/notification" {
		t.Errorf("scope path is %q, want modules/notification", manifest.ScopePath)
	}
	if manifest.Module.RegistrySource == "" || manifest.Module.Version == "" {
		t.Errorf("the module block is incomplete: %+v", manifest.Module)
	}
	if got := manifest.Module.FrameworkNames["soc_2"]; got != "SOC 2" {
		t.Errorf("framework name for soc_2 is %q, want SOC 2", got)
	}
	if len(manifest.Controls) != 1 {
		t.Fatalf("got %d controls, want 1", len(manifest.Controls))
	}

	control := manifest.Controls[0]
	if control.ControlID != "s3_bucket_event_notifications_enabled" {
		t.Errorf("control id is %q", control.ControlID)
	}
	if control.Status != ctfkit.ManifestControlEnforced {
		t.Errorf("control status is %q, want %s", control.Status, ctfkit.ManifestControlEnforced)
	}
	if !equal(control.AppliesIn, []string{"modules/notification"}) {
		t.Errorf("applies_in is %v", control.AppliesIn)
	}
	if len(control.ClausesByFramework["soc_2"]) != 1 {
		t.Errorf("clauses_by_framework is %v", control.ClausesByFramework)
	}

	// posture.degraded is present and empty: the producer reported and
	// nothing was dropped.
	if manifest.Posture.Degraded == nil || len(manifest.Posture.Degraded) != 0 {
		t.Errorf("posture.degraded is %#v, want an empty non-nil slice", manifest.Posture.Degraded)
	}
	// build.controls_not_applicable is absent from a subtree manifest: the
	// producer never classified, which is not the same as classifying none.
	if manifest.Build.ControlsNotApplicable != nil {
		t.Errorf("build.controls_not_applicable is %v, want nil", manifest.Build.ControlsNotApplicable)
	}
}

// TestLoadModulesReadsSupportingClauses checks the schema 3.4 field that
// marks a clause as supporting evidence. It is tri-state like the others: a
// 3.3 manifest has no field at all (nil, unknown), and a 3.4 manifest carries
// an empty list per framework when it classified and hedged nothing there.
func TestLoadModulesReadsSupportingClauses(t *testing.T) {
	inventory, err := loader.LoadModules(reportFixtureRoot("supporting-clauses"))
	if err != nil {
		t.Fatalf("LoadModules returned an error: %v", err)
	}
	manifest := inventory.Instances[0].Manifest
	if manifest.SchemaVersion != "3.4" {
		t.Fatalf("schema version is %q, want 3.4", manifest.SchemaVersion)
	}

	byID := make(map[string]ctfkit.ManifestControl, len(manifest.Controls))
	for _, control := range manifest.Controls {
		byID[control.ControlID] = control
	}
	logging := byID["s3_bucket_logging_enabled"].SupportingClausesByFramework["soc_2"]
	if len(logging) != 1 || !strings.HasPrefix(logging[0], "CC7.3 ") {
		t.Errorf("supporting clauses of s3_bucket_logging_enabled are %v, want the CC7.3 sentence", logging)
	}
	versioning, ok := byID["s3_bucket_versioning_enabled"].SupportingClausesByFramework["soc_2"]
	if !ok || versioning == nil || len(versioning) != 0 {
		t.Errorf("supporting clauses of s3_bucket_versioning_enabled are %#v, want an empty non-nil list", versioning)
	}

	older, err := loader.LoadModules(reportFixtureRoot("delegated-without-sibling"))
	if err != nil {
		t.Fatalf("LoadModules returned an error: %v", err)
	}
	for _, control := range older.Instances[0].Manifest.Controls {
		if control.SupportingClausesByFramework != nil {
			t.Errorf("a 3.3 manifest control %s carries supporting clauses %v, want nil (unknown)",
				control.ControlID, control.SupportingClausesByFramework)
		}
	}
}

// TestLoadModulesReadsPackageScopeFields checks the fields only a
// package-scope manifest carries.
func TestLoadModulesReadsPackageScopeFields(t *testing.T) {
	inventory, err := loader.LoadModules(reportFixtureRoot("delegated-with-sibling"))
	if err != nil {
		t.Fatalf("LoadModules returned an error: %v", err)
	}

	var manifest *ctfkit.Manifest
	for _, instance := range inventory.Instances {
		if instance.Key == "s3_bucket" {
			manifest = instance.Manifest
		}
	}
	if manifest == nil {
		t.Fatal("the package-scope instance has no manifest")
	}

	if manifest.ControlsScope != "package" || manifest.ScopePath != "." {
		t.Errorf("scope is %q at %q, want package at .", manifest.ControlsScope, manifest.ScopePath)
	}
	if manifest.ManifestSetHash == "" {
		t.Error("a package-scope manifest carries no manifest_set_hash")
	}
	if len(manifest.ChildManifests) == 0 {
		t.Error("a package-scope manifest names no child manifests")
	}
	if len(manifest.Build.ControlsNotApplicable) == 0 {
		t.Error("build.controls_not_applicable is empty on a package-scope manifest")
	}
	if len(manifest.Scope.DoesNotProve) == 0 {
		t.Error("scope.does_not_prove is empty")
	}
}

// TestLoadModulesReadsDegradedPosture pins the other side of the posture
// tri-state: a build whose org posture could not be applied in full.
func TestLoadModulesReadsDegradedPosture(t *testing.T) {
	inventory, err := loader.LoadModules(reportFixtureRoot("degraded-build"))
	if err != nil {
		t.Fatalf("LoadModules returned an error: %v", err)
	}

	degraded := inventory.Instances[0].Manifest.Posture.Degraded
	if !equal(degraded, []string{"org-rules-unavailable", "baseline-not-authored"}) {
		t.Fatalf("posture.degraded is %v", degraded)
	}
}

// TestLoadModulesRefusesAnotherSchemaMajor is the schema-4-stub fixture: an
// unsupported major is an environment error naming the major, never a
// finding and never a partly filled inventory.
func TestLoadModulesRefusesAnotherSchemaMajor(t *testing.T) {
	root := reportFixtureRoot("schema-4-stub")

	inventory, err := loader.LoadModules(root)
	if err == nil {
		t.Fatalf("a manifest at schema major 4 loaded without an error: %+v", inventory)
	}
	if inventory != nil {
		t.Fatalf("a manifest at schema major 4 returned an inventory: %+v", inventory)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}

	// The fixture's expected stderr is the oracle for the wording. The
	// command layer adds the program prefix; everything after it is this
	// package's diagnostic.
	expected, readErr := os.ReadFile(filepath.Join(fixtureRoot, "report", "schema-4-stub", "expected", "stderr.txt"))
	if readErr != nil {
		t.Fatalf("reading the expected stderr: %v", readErr)
	}
	want := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(expected)), "ctfkit: "))
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not carry the expected diagnostic %q", err, want)
	}
}

// TestLoadModulesExcludesTestKeys covers the test. prefix rule. No report
// fixture installs a test harness module, so the tree is built here.
func TestLoadModulesExcludesTestKeysAndTheRootModule(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{".terraform/modules/bucket", "tests/harness/inner", "modules/tested"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// test.main.harness is the run block "harness" of main.tftest.hcl, the
	// shape init writes; test.main.harness.inner is a module it calls.
	writeModulesJSON(t, root, `{"Modules":[
		{"Key":"","Source":"","Dir":"."},
		{"Key":"bucket","Source":"bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws","Dir":".terraform/modules/bucket"},
		{"Key":"test.main.harness","Source":"./tests/harness","Dir":"tests/harness"},
		{"Key":"test.main.harness.inner","Source":"./tests/harness/inner","Dir":"tests/harness/inner"},
		{"Key":"tested","Source":"./modules/tested","Dir":"modules/tested"}
	]}`)

	inventory, err := loader.LoadModules(root)
	if err != nil {
		t.Fatalf("LoadModules returned an error: %v", err)
	}

	// "tested" starts with "test" but not with "test.", so it stays.
	if got := instanceKeys(inventory); !equal(got, []string{"bucket", "tested"}) {
		t.Fatalf("keys are %v, want [bucket tested]", got)
	}
}

func TestLoadModulesMissingModulesJSONIsAnInputError(t *testing.T) {
	inventory, err := loader.LoadModules(t.TempDir())
	if err == nil {
		t.Fatalf("a root with no modules.json loaded without an error: %+v", inventory)
	}
	if inventory != nil {
		t.Fatalf("a root with no modules.json returned an inventory: %+v", inventory)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadModulesBrokenModulesJSONIsAnInputError(t *testing.T) {
	root := t.TempDir()
	// The text is written by the repository under analysis, so it must not
	// reach the diagnostic.
	const canary = "SECRET_CANARY_MODULES"
	writeModulesJSON(t, root, `{"Modules": [`+canary)

	inventory, err := loader.LoadModules(root)
	if err == nil {
		t.Fatalf("a truncated modules.json loaded without an error: %+v", inventory)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("the diagnostic echoes text from the file under analysis: %v", err)
	}
}

func TestLoadModulesBrokenManifestIsAnInputError(t *testing.T) {
	root := t.TempDir()
	writeModulesJSON(t, root, `{"Modules":[{"Key":"bucket","Source":"./modules/bucket","Dir":"modules/bucket"}]}`)
	const canary = "SECRET_CANARY_MANIFEST"
	writeManifest(t, root, "modules/bucket", `{"schema_version": `+canary)

	inventory, err := loader.LoadModules(root)
	if err == nil {
		t.Fatalf("a manifest that is not JSON loaded without an error: %+v", inventory)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("the diagnostic echoes text from the file under analysis: %v", err)
	}
}

func TestLoadModulesManifestWithoutASchemaVersionIsAnInputError(t *testing.T) {
	root := t.TempDir()
	writeModulesJSON(t, root, `{"Modules":[{"Key":"bucket","Source":"./modules/bucket","Dir":"modules/bucket"}]}`)
	writeManifest(t, root, "modules/bucket", `{"controls_scope": "package"}`)

	if _, err := loader.LoadModules(root); err == nil {
		t.Fatal("a manifest with no schema_version loaded without an error")
	} else if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

// A refusal echoes no repository text except through the redaction helpers.
// The schema_version a manifest declares is named, since the
// reader needs it, but a downloaded module writes it, so it loses userinfo
// and becomes the placeholder when it holds a control character; and a
// manifest that does not decode, in a directory named after a source with
// credentials, is named with them removed.
func TestLoadModulesRefusalsEchoNoRepositoryText(t *testing.T) {
	for _, tc := range []struct {
		name, dir, manifest, want string
	}{
		{"plain version", "modules/bucket", `{"schema_version": "4.1"}`, "declares schema_version 4.1;"},
		{"version with userinfo", "modules/bucket", `{"schema_version": "CANARY-u:CANARY-t@4.0"}`, "declares schema_version 4.0;"},
		{"version with a control character", "modules/bucket", `{"schema_version": "4.0\u001b[2JCANARY"}`,
			"declares schema_version " + ctfkit.UnparsedSource + ";"},
		{"undecodable manifest in a credential-named directory", "modules/CANARY-u:CANARY-t@bucket",
			`{"schema_version": CANARY`, "modules/bucket/" + manifestFileName + " is not a valid compliance manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeModulesJSON(t, root, `{"Modules":[{"Key":"bucket","Source":"./`+tc.dir+`","Dir":"`+tc.dir+`"}]}`)
			writeManifest(t, root, tc.dir, tc.manifest)
			_, err := loader.LoadModules(root)
			if !errors.Is(err, loader.ErrInput) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadModules error = %v, want an input error containing %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "CANARY") || strings.ContainsFunc(err.Error(), func(r rune) bool { return r < ' ' }) {
				t.Errorf("the diagnostic echoes repository text: %q", err)
			}
		})
	}
}

// TestLoadModulesRefusesAManifestSymlinkedOutOfTheRoot is the containment
// guard of PR #29 applied to the manifest read: a link that leaves the root
// would pull bytes from outside the repository into evidence under an
// in-root name.
func TestLoadModulesRefusesAManifestSymlinkedOutOfTheRoot(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, manifestFileName)
	if err := os.WriteFile(secret, []byte(`{"schema_version": "3.3", "scope_path": "OUTSIDE-ROOT-SECRET"}`), 0o600); err != nil {
		t.Fatalf("writing the outside manifest: %v", err)
	}

	root := t.TempDir()
	writeModulesJSON(t, root, `{"Modules":[{"Key":"bucket","Source":"./modules/bucket","Dir":"modules/bucket"}]}`)
	dir := filepath.Join(root, "modules", "bucket")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating the instance directory: %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, manifestFileName)); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	inventory, err := loader.LoadModules(root)
	if err == nil {
		t.Fatalf("a manifest symlinked out of the root loaded without an error: %+v", inventory)
	}
	if inventory != nil {
		t.Fatalf("a manifest symlinked out of the root returned an inventory: %+v", inventory)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
	if strings.Contains(err.Error(), "OUTSIDE-ROOT-SECRET") {
		t.Fatalf("the error carries the content of the file it refused: %v", err)
	}
}

// TestLoadModulesRefusesAnInstanceDirectoryOutOfTheRoot covers the other
// escape: modules.json itself naming a directory above the root for a module
// whose source is not an explicit ./ or ../ path. (An explicit ../ source is
// read, manifest included; see TestLoadModulesLocalModuleDirectories.)
func TestLoadModulesRefusesAnInstanceDirectoryOutOfTheRoot(t *testing.T) {
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, manifestFileName), []byte(`{"schema_version": "3.3"}`), 0o600); err != nil {
		t.Fatalf("writing the outside manifest: %v", err)
	}

	root := filepath.Join(parent, "repo")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("creating the root: %v", err)
	}
	writeModulesJSON(t, root, `{"Modules":[{"Key":"escape","Source":"git::https://example.com/bobthecorp/escape.git","Dir":".."}]}`)

	if _, err := loader.LoadModules(root); err == nil {
		t.Fatal("an instance directory above the root loaded without an error")
	} else if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func TestLoadModulesDanglingManifestSymlinkIsAnInputError(t *testing.T) {
	root := t.TempDir()
	writeModulesJSON(t, root, `{"Modules":[{"Key":"bucket","Source":"./modules/bucket","Dir":"modules/bucket"}]}`)
	dir := filepath.Join(root, "modules", "bucket")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating the instance directory: %v", err)
	}
	// A broken link where a manifest should be is not the same as having no
	// manifest, so it is an error and not a silent nil.
	if err := os.Symlink(filepath.Join(dir, "gone.json"), filepath.Join(dir, manifestFileName)); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	inventory, err := loader.LoadModules(root)
	if err == nil {
		t.Fatalf("a dangling manifest link was treated as no manifest: %+v", inventory)
	}
	if !errors.Is(err, loader.ErrInput) {
		t.Fatalf("error %v is not an ErrInput", err)
	}
}

func reportFixtureRoot(name string) string {
	return filepath.Join(fixtureRoot, "report", name, "input")
}

func instanceKeys(inventory *ctfkit.ModuleInventory) []string {
	out := make([]string, 0, len(inventory.Instances))
	for _, instance := range inventory.Instances {
		out = append(out, instance.Key)
	}
	return out
}

func instanceDirs(inventory *ctfkit.ModuleInventory) []string {
	out := make([]string, 0, len(inventory.Instances))
	for _, instance := range inventory.Instances {
		out = append(out, instance.Dir)
	}
	return out
}

func digestOnDisk(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	sum := sha256.Sum256(content)

	return hex.EncodeToString(sum[:])
}

func writeModulesJSON(t *testing.T, root, body string) {
	t.Helper()

	dir := filepath.Join(root, ".terraform", "modules")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "modules.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing modules.json: %v", err)
	}
}

func writeManifest(t *testing.T, root, dir, body string) {
	t.Helper()

	full := filepath.Join(root, filepath.FromSlash(dir))
	if err := os.MkdirAll(full, 0o750); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(full, manifestFileName), []byte(body), 0o600); err != nil {
		t.Fatalf("writing the manifest: %v", err)
	}
}
