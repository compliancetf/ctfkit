package tfexec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
)

// lockfile writes the configuration's lock file pinning the fake provider
// with the h1: hash of a package holding body.
func lockfile(t *testing.T, dir, body string) {
	t.Helper()
	pkg := t.TempDir()
	if err := os.WriteFile(filepath.Join(pkg, "terraform-provider-fake_v1.0.0"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	h1, err := dirhash.HashDir(pkg, "", dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	lock := fmt.Sprintf("provider %q {\n  version = \"1.0.0\"\n  hashes = [%q]\n}\n", "registry.terraform.io/bobthecorp/fake", h1)
	if err = os.WriteFile(filepath.Join(dir, ".terraform.lock.hcl"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestProviderSealing: the first init's packages are sealed against the
// lock file and every later init links the sealed copies; a package the
// lock file does not record, a copy instead of a link or a missing lock
// entry stops the session before any later call.
func TestProviderSealing(t *testing.T) {
	t.Run("sealed and linked", func(t *testing.T) {
		f := newFake(t, fakeOpts{provider: "fake provider v1", mirror: "link"})
		cfg := config(t, f)
		lockfile(t, cfg.Dir, "fake provider v1")
		s := open(t, cfg)
		run(t, s, Version(), Init(), Schema(), Plan(), Init())
		calls := f.calls(t)
		if len(calls) != 6 || !strings.HasSuffix(calls[2], " init -input=false -lockfile=readonly") || !strings.HasSuffix(calls[3], " providers schema -json") {
			t.Fatalf("calls %q: want version, init, mirror init, schema, plan, init", calls)
		}
		for i, want := range []string{"empty.tfrc", "empty.tfrc", "mirror.tfrc", "mirror.tfrc", "mirror.tfrc", "mirror.tfrc"} {
			if !slices.Contains(f.env(t, i), "TF_CLI_CONFIG_FILE="+s.Owned(want)) {
				t.Errorf("call %d not under %s", i, want)
			}
		}
		bin := s.Owned("sealed/providers/" + fakePkg + "/terraform-provider-fake_v1.0.0")
		if fi, err := os.Lstat(bin); err != nil || fi.Mode().Perm() != 0o500 {
			t.Fatalf("sealed provider: %v %v", fi, err)
		}
		if target, err := filepath.EvalSymlinks(s.Owned("data/providers/" + fakePkg)); err != nil || target != filepath.Dir(bin) {
			t.Fatalf("data dir package resolves to %s (%v)", target, err)
		}
	})
	t.Run("link re-pointed after init", func(t *testing.T) {
		f := newFake(t, fakeOpts{provider: "fake provider v1", mirror: "link"})
		cfg := config(t, f)
		lockfile(t, cfg.Dir, "fake provider v1")
		s := open(t, cfg)
		run(t, s, Init())
		link := s.Owned("data/providers/" + fakePkg)
		other := t.TempDir()
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, link); err != nil {
			t.Fatal(err)
		}
		n := len(f.calls(t))
		if err := s.Run(Plan(), io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
			t.Fatalf("plan after the link moved: %v", err)
		}
		if len(f.calls(t)) != n {
			t.Fatal("terraform ran with a re-pointed provider link")
		}
	})
	for _, tc := range []struct{ name, lock, mirror, want string }{
		{"hash not in the lock file", "another build", "link", "does not record (an h1: hash for this platform is required); run `terraform providers lock -platform=" + runtime.GOOS + "_" + runtime.GOARCH + "`"},
		{"copied, not linked", "fake provider v1", "copy", "not a link to its sealed copy"},
		{"not linked at all", "fake provider v1", "", "installed providers"},
		{"no lock file", "", "link", "does not pin it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, fakeOpts{provider: "fake provider v1", mirror: tc.mirror})
			cfg := config(t, f)
			if tc.lock != "" {
				lockfile(t, cfg.Dir, tc.lock)
			}
			s := open(t, cfg)
			if err := s.Run(Init(), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("init: %v, want %q", err, tc.want)
			}
			n := len(f.calls(t))
			if err := s.Run(Plan(), io.Discard, io.Discard); !errors.Is(err, ErrNotStarted) {
				t.Fatalf("plan after a refused init: %v", err)
			}
			if len(f.calls(t)) != n {
				t.Fatal("terraform ran after the session stopped")
			}
		})
	}
}
