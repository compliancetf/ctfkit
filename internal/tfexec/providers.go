package tfexec

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// sealProviders runs after the first init: it copies every package terraform
// installed into the owned data dir into the sealed provider dir, checks the
// copy's h1: hash against the lock file, removes the data dir's packages and
// switches every later call to the mirror-only CLI config.
func (s *Session) sealProviders() error {
	s.cliConfig = s.owned("mirror.tfrc")
	pkgs, err := packages(s.owned("data/providers"))
	if err != nil || len(pkgs) == 0 {
		return err
	}
	locks, err := loader.LoadLockfiles(s.cfg.Dir, []string{"."})
	if err != nil {
		return err
	}
	for _, p := range pkgs {
		src, dst := s.owned("data/providers/"+p), s.owned("sealed/providers/"+p)
		if err = copyTree(src, dst); err != nil {
			return fmt.Errorf("sealing provider %s: %w", p, err)
		}
		h1, err := dirhash.HashDir(dst, "", dirhash.Hash1)
		if err != nil {
			return err
		}
		if err = locked(locks["."], p, h1); err != nil {
			return err
		}
	}
	s.sealed = pkgs
	return os.RemoveAll(s.owned("data/providers"))
}

// locked checks that the lock file pins pkg (<host>/<ns>/<type>/<version>/<os_arch>)
// with hash h1.
func locked(lock *ctfkit.Lockfile, pkg, h1 string) error {
	parts := strings.Split(pkg, "/")
	source, version := strings.Join(parts[:3], "/"), parts[3]
	if lock != nil {
		for _, lp := range lock.Providers {
			if strings.EqualFold(lp.Source, source) && lp.Version == version {
				if slices.Contains(lp.Hashes, h1) {
					return nil
				}
				return fmt.Errorf("provider %s %s (%s) is %s, which the lock file does not record (an h1: hash for this platform is required); run `terraform providers lock -platform=%s`", source, version, parts[4], h1, parts[4])
			}
		}
	}
	return fmt.Errorf("provider %s %s was installed but the lock file does not pin it", source, version)
}

// verifyLinks checks, after an init under the mirror config, that the data
// dir holds exactly the sealed packages, each a symlink to its sealed copy.
func (s *Session) verifyLinks() error {
	dir := s.owned("data/providers")
	var got []string
	err := walkDepth(dir, 5, func(rel string, fi fs.FileInfo) error {
		want := s.owned("sealed/providers/" + rel)
		target, err := filepath.EvalSymlinks(filepath.Join(dir, filepath.FromSlash(rel)))
		if fi.Mode()&fs.ModeSymlink == 0 || err != nil || target != want {
			return fmt.Errorf("provider %s is not a link to its sealed copy", rel)
		}
		got = append(got, rel)
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err == nil && !slices.Equal(got, s.sealed) {
		err = fmt.Errorf("installed providers %q, sealed %q", got, s.sealed)
	}
	return err
}

// packages lists the package dirs <host>/<ns>/<type>/<version>/<os_arch> of
// a providers dir, sorted; anything but directories down to that depth is
// refused.
func packages(dir string) ([]string, error) {
	var pkgs []string
	err := walkDepth(dir, 5, func(rel string, fi fs.FileInfo) error {
		if !fi.IsDir() {
			return fmt.Errorf("provider package %s is not a directory", rel)
		}
		pkgs = append(pkgs, rel)
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return pkgs, err
}

// walkDepth calls fn, in path order, for every entry exactly depth levels
// below dir; entries above that depth must be real directories.
func walkDepth(dir string, depth int, fn func(rel string, fi fs.FileInfo) error) error {
	if fi, err := os.Lstat(dir); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	var walk func(rel string, d int) error
	walk = func(rel string, d int) error {
		entries, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		for _, e := range entries {
			r := pathJoin(rel, e.Name())
			fi, err := e.Info()
			if err != nil {
				return err
			}
			if d == depth {
				if installLock(fi) {
					continue
				}
				if err = fn(r, fi); err != nil {
					return err
				}
				continue
			}
			if !fi.IsDir() {
				return fmt.Errorf("provider path %s is not a directory", r)
			}
			if err = walk(r, d+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk("", 1)
}

// installLock reports an OpenTofu install lock: the regular file
// <os_arch>.lock beside a package dir. It is never executed.
func installLock(fi fs.FileInfo) bool {
	return fi.Mode().IsRegular() && strings.HasSuffix(fi.Name(), ".lock")
}

func pathJoin(a, b string) string {
	if a == "" {
		return b
	}
	return a + "/" + b
}

// copyTree copies the regular files and directories under src to dst,
// reading each file through one no-follow open; a symlink, device, fifo or
// socket is refused. Executable files are sealed 0500, others 0400.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		fi, err := d.Info()
		switch {
		case err != nil:
			return err
		case fi.IsDir():
			return os.MkdirAll(out, 0o700)
		case !fi.Mode().IsRegular():
			return fmt.Errorf("%s is not a regular file", rel)
		}
		mode := os.FileMode(0o400)
		if fi.Mode()&0o111 != 0 {
			mode = 0o500
		}
		return copyFile(p, out, mode)
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := OpenRegular(src)
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // read-only

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600) // #nosec G304 -- inside the owned root
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if err == nil {
		err = out.Chmod(mode)
	}
	return errors.Join(err, out.Close())
}
