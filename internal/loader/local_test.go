package loader_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// localModules runs LoadConfig and then LoadLocalModules on root, as a
// pre_plan directory scan does.
func localModules(t *testing.T, root string) ([]ctfkit.LocalModule, error) {
	t.Helper()
	cfg, err := loader.LoadConfig(root)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	modules, _, err := loader.LoadLocalModules(root, cfg.Files)
	return modules, err
}

// A directory scan reads the ../ modules the configuration calls and their
// own local children, from beside the root, with root-relative paths; a ./
// module under the root is LoadConfig's and is not repeated.
func TestLoadLocalModulesReadsExplicitSourcesOutsideTheRoot(t *testing.T) {
	modules, err := localModules(t, recordedLayout)
	if err != nil {
		t.Fatalf("LoadLocalModules: %v", err)
	}
	var got []string
	for _, m := range modules {
		if m.Unread {
			t.Errorf("%s is unread", m.Dir)
		}
		for _, f := range m.Files {
			got = append(got, f.Path)
		}
	}
	if want := []string{"../shared/main.tf", "../shared/sub/main.tf"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("files = %q, want %q", got, want)
	}
}

// filesOf flattens the files of modules into their paths.
func filesOf(modules []ctfkit.LocalModule) []string {
	var out []string
	for _, m := range modules {
		for _, f := range m.Files {
			out = append(out, f.Path)
		}
	}
	return out
}

// The traversal rules, each on a fresh tree with
// the root at parent/repo:
//
//   - an explicit source into a directory the walk skips, ./.terraform.d/hook,
//     is read;
//   - a child source is joined to its module's resolved directory: ../alias,
//     a symlink to ../libs/pkg, calls ../hook, which reads ../libs/hook and
//     never the decoy ../hook;
//   - an explicit ../repo-evil source is read (containment matrix: only a
//     symlink or prefix confusion reaching repo-evil is refused);
//   - a cycle of local sources, and a ../ directory that exists and cannot be
//     listed, are input errors whose messages carry no credential.
func TestLoadLocalModulesTraversal(t *testing.T) {
	t.Run("explicit source into a skipped directory", func(t *testing.T) {
		root := t.TempDir()
		writeModuleFile(t, root, "main.tf", "module \"hook\" {\n  source = \"./.terraform.d/hook\"\n}\n")
		writeModuleFile(t, root, ".terraform.d/hook/main.tf", `locals {}`)
		modules, err := localModules(t, root)
		if err != nil || strings.Join(filesOf(modules), ",") != ".terraform.d/hook/main.tf" {
			t.Errorf("files = %q, err = %v; want .terraform.d/hook/main.tf", filesOf(modules), err)
		}
	})

	t.Run("child joined to the resolved directory, not the decoy", func(t *testing.T) {
		parent := t.TempDir()
		writeModuleFile(t, parent, "libs/pkg/main.tf", "module \"hook\" {\n  source = \"../hook\"\n}\n")
		writeModuleFile(t, parent, "libs/hook/main.tf", `locals {}`)
		writeModuleFile(t, parent, "hook/main.tf", `locals {}`)
		if err := os.Symlink(filepath.Join(parent, "libs", "pkg"), filepath.Join(parent, "alias")); err != nil {
			t.Skipf("this filesystem does not support symlinks: %v", err)
		}
		root := filepath.Join(parent, "repo")
		writeModuleFile(t, root, "main.tf", "module \"alias\" {\n  source = \"../alias\"\n}\n")
		modules, err := localModules(t, root)
		want := "../libs/pkg/main.tf,../libs/hook/main.tf"
		if err != nil || strings.Join(filesOf(modules), ",") != want {
			t.Errorf("files = %q, err = %v; want %q", filesOf(modules), err, want)
		}
	})

	t.Run("explicit ../repo-evil source", func(t *testing.T) {
		parent := t.TempDir()
		writeModuleFile(t, parent, "repo-evil/main.tf", `locals {}`)
		root := filepath.Join(parent, "repo")
		writeModuleFile(t, root, "main.tf", "module \"evil\" {\n  source = \"../repo-evil\"\n}\n")
		modules, err := localModules(t, root)
		if err != nil || strings.Join(filesOf(modules), ",") != "../repo-evil/main.tf" {
			t.Errorf("files = %q, err = %v; want ../repo-evil/main.tf", filesOf(modules), err)
		}
	})

	// A file symlink in a module directory is read when it resolves inside
	// the root or inside its own module, and is an input error otherwise:
	// terraform would read it, so it is never skipped.
	for name, into := range map[string]string{
		"file in a ../ module symlinked into the root":          "repo/shared.tf",
		"file in a ../ module symlinked elsewhere outside root": "outside/main.tf",
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			writeModuleFile(t, parent, "outside/main.tf", `locals {}`)
			writeModuleFile(t, parent, "lib/main.tf", `locals {}`)
			root := filepath.Join(parent, "repo")
			writeModuleFile(t, root, "main.tf", "module \"lib\" {\n  source = \"../lib\"\n}\n")
			// A root file with no module call: linking to main.tf would make
			// ../lib call itself, which the cycle check refuses.
			writeModuleFile(t, root, "shared.tf", `locals {}`)
			if err := os.Symlink(filepath.Join(parent, filepath.FromSlash(into)), filepath.Join(parent, "lib", "linked.tf")); err != nil {
				t.Skipf("this filesystem does not support symlinks: %v", err)
			}
			modules, err := localModules(t, root)
			if strings.HasPrefix(into, "repo/") {
				if err != nil || !strings.Contains(strings.Join(filesOf(modules), ","), "../lib/linked.tf") {
					t.Errorf("files = %q, err = %v; want ../lib/linked.tf read", filesOf(modules), err)
				}
				return
			}
			if !errors.Is(err, loader.ErrInput) || !strings.Contains(err.Error(), "leaves the configuration directory") {
				t.Errorf("err = %v, want an input error naming the escape", err)
			}
		})
	}

	t.Run("cycle", func(t *testing.T) {
		parent := t.TempDir()
		writeModuleFile(t, parent, "CANARY-u:CANARY-t@a/main.tf", "module \"b\" {\n  source = \"../b\"\n}\n")
		writeModuleFile(t, parent, "b/main.tf", "module \"a\" {\n  source = \"../CANARY-u:CANARY-t@a\"\n}\n")
		root := filepath.Join(parent, "repo")
		writeModuleFile(t, root, "main.tf", "module \"a\" {\n  source = \"../CANARY-u:CANARY-t@a\"\n}\n")
		_, err := localModules(t, root)
		if !errors.Is(err, loader.ErrInput) || !strings.Contains(err.Error(), "cycle") || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("err = %v, want a value-free cycle error", err)
		}
	})

	t.Run("../ directory that cannot be listed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lists a directory whatever its mode")
		}
		parent := t.TempDir()
		locked := filepath.Join(parent, "CANARY-u:CANARY-t@locked")
		writeModuleFile(t, parent, "CANARY-u:CANARY-t@locked/main.tf", `locals {}`)
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o750) }) //nolint:gosec // restores a test directory so TempDir can remove it
		root := filepath.Join(parent, "repo")
		writeModuleFile(t, root, "main.tf", "module \"l\" {\n  source = \"../CANARY-u:CANARY-t@locked\"\n}\n")
		_, err := localModules(t, root)
		if !errors.Is(err, loader.ErrInput) || !strings.Contains(err.Error(), "cannot be listed") || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("err = %v, want a credential-free error naming the unlistable directory", err)
		}
	})
}

// Scan runs before init, so a ../ directory that is not there is reported as
// unread rather than failing the scan; a ./ directory a symlink leads out of
// the root is an error unless it lands on an explicit ../ target.
func TestLoadLocalModulesUnreadAndSymlinks(t *testing.T) {
	t.Run("missing ../ directory", func(t *testing.T) {
		root := t.TempDir()
		writeModuleFile(t, root, "main.tf", "module \"gone\" {\n  source = \"../gone\"\n}\n")
		modules, err := localModules(t, root)
		if err != nil || len(modules) != 1 || !modules[0].Unread || modules[0].Dir != "../gone" {
			t.Errorf("modules = %+v, err = %v; want ../gone unread", modules, err)
		}
	})

	for name, explicit := range map[string]bool{
		"./x symlinked out of the root":                 false,
		"./x symlinked onto the target of a ../ source": true,
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			writeModuleFile(t, parent, "shared/main.tf", `locals {}`)
			root := filepath.Join(parent, "repo")
			body := "module \"x\" {\n  source = \"./x\"\n}\n"
			if explicit {
				body += "module \"shared\" {\n  source = \"../shared\"\n}\n"
			}
			writeModuleFile(t, root, "main.tf", body)
			if err := os.Symlink(filepath.Join(parent, "shared"), filepath.Join(root, "x")); err != nil {
				t.Skipf("this filesystem does not support symlinks: %v", err)
			}
			_, err := localModules(t, root)
			if explicit && err != nil {
				t.Errorf("LoadLocalModules: %v", err)
			}
			if !explicit && (!errors.Is(err, loader.ErrInput) || !strings.Contains(err.Error(), "leaves the configuration directory")) {
				t.Errorf("err = %v, want an input error naming the escape", err)
			}
		})
	}
}
