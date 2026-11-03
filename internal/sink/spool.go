package sink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	spoolVersion   = 1
	spoolExt       = ".json"
	spoolTmpPrefix = ".tmp-"
	spoolLock      = ".lock" // flock target serializing Add and Drain across processes
)

// Spool holds evidence objects whose put failed, one 0600 file per (sink, key), in a
// 0700 directory owned by the runner. Add and Drain hold an exclusive lock on the
// directory, so concurrent runners never remove each other's files. Each entry is written to a temp file, fsynced,
// hard-linked to its final name and the directory fsynced, so a crash leaves either no
// entry or a complete one.
type Spool struct {
	dir string
}

type spoolEntry struct {
	V      int    `json:"v"`
	Sink   string `json:"sink"`
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
	Body   []byte `json:"body"`
}

// OpenSpool creates dir (0700) if absent and refuses one that is a symlink, has a wider
// mode or another owner.
func OpenSpool(dir string) (*Spool, error) {
	dir = filepath.Clean(dir) // a trailing slash would make Lstat follow a symlink
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("spool %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("spool %s: not a directory", dir)
	}
	if err := checkOwned(fi, 0o700); err != nil {
		return nil, fmt.Errorf("spool %s: %w", dir, err)
	}
	if err := syncAncestors(dir); err != nil {
		return nil, fmt.Errorf("spool %s: %w", dir, err)
	}
	return &Spool{dir: dir}, nil
}

// syncAncestors fsyncs the parent of dir and of every ancestor the runner owns, up to the
// first one it does not own. Any directory this or a concurrent same-uid OpenSpool may
// have just created is among them, so its name survives a crash before an Add returns.
func syncAncestors(dir string) error {
	d, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		p := filepath.Dir(d)
		if p == d || !ownedByRunner(fi) {
			return nil
		}
		if err := syncDir(p); err != nil {
			return err
		}
		d = p
	}
}

func (s *Spool) path(sinkName, key string) string {
	h := sha256.Sum256([]byte(sinkName + "\x00" + key))
	return filepath.Join(s.dir, hex.EncodeToString(h[:])+spoolExt)
}

// Add spools obj for sinkName. Adding the same object again is a no-op; the same key
// with a different body is an error.
func (s *Spool) Add(sinkName string, obj Object) error {
	if err := validKey(obj.Key); err != nil {
		return err
	}
	unlock, err := lockDir(s.dir)
	if err != nil {
		return fmt.Errorf("spool %s: %w", obj.Key, err)
	}
	defer unlock()
	final := s.path(sinkName, obj.Key)
	want := digest(obj.Body)
	b, err := json.Marshal(spoolEntry{V: spoolVersion, Sink: sinkName, Key: obj.Key, SHA256: want, Body: obj.Body})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, spoolTmpPrefix) // O_EXCL, 0600
	if err != nil {
		return fmt.Errorf("spool %s: %w", obj.Key, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("spool %s: %w", obj.Key, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("spool %s: %w", obj.Key, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("spool %s: %w", obj.Key, err)
	}
	// Link, unlike rename, never replaces an existing entry.
	if err := os.Link(tmp.Name(), final); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("spool %s: %w", obj.Key, err)
		}
		e, rerr := s.read(final)
		if rerr != nil {
			return rerr
		}
		if e.SHA256 != want {
			return fmt.Errorf("spool %s: already spooled with a different digest", obj.Key)
		}
		// The earlier Add may have failed its dir fsync; do not acknowledge before one.
		return syncDir(s.dir)
	}
	if err := os.Remove(tmp.Name()); err != nil {
		return fmt.Errorf("spool %s: %w", obj.Key, err)
	}
	return syncDir(s.dir)
}

func (s *Spool) read(path string) (spoolEntry, error) {
	var e spoolEntry
	fi, err := os.Lstat(path)
	if err != nil {
		return e, fmt.Errorf("spool entry %s: %w", filepath.Base(path), err)
	}
	if !fi.Mode().IsRegular() {
		return e, fmt.Errorf("spool entry %s: not a regular file", filepath.Base(path))
	}
	if err = checkOwned(fi, 0o600); err != nil {
		return e, fmt.Errorf("spool entry %s: %w", filepath.Base(path), err)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- a spool entry path under the checked spool dir
	if err != nil {
		return e, fmt.Errorf("spool entry %s: %w", filepath.Base(path), err)
	}
	if err = json.Unmarshal(b, &e); err != nil {
		return e, fmt.Errorf("spool entry %s: malformed", filepath.Base(path))
	}
	if e.V != spoolVersion || validKey(e.Key) != nil || digest(e.Body) != e.SHA256 || s.path(e.Sink, e.Key) != path {
		return e, fmt.Errorf("spool entry %s: corrupt", filepath.Base(path))
	}
	return e, nil
}

// Pending returns the number of spooled entries.
func (s *Spool) Pending() (int, error) {
	names, err := s.entries()
	return len(names), err
}

func (s *Spool) entries() ([]string, error) {
	des, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("spool %s: %w", s.dir, err)
	}
	var names []string
	for _, de := range des {
		n := de.Name()
		if strings.HasSuffix(n, spoolExt) && !strings.HasPrefix(n, spoolTmpPrefix) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

// Drain retries every spooled entry against the sink with the same Name and removes the
// entries that land. Entries for a sink not in sinks stay. It returns the receipts of
// the entries shipped and an error for every entry that did not. It holds the spool
// lock, so no Add is in flight and every temp file is left by a crashed Add and removed.
func (s *Spool) Drain(ctx context.Context, sinks ...Sink) ([]Receipt, error) {
	byName := make(map[string]Sink, len(sinks))
	for _, sk := range sinks {
		byName[sk.Name()] = sk
	}
	unlock, err := lockDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("spool %s: %w", s.dir, err)
	}
	defer unlock()
	des, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("spool %s: %w", s.dir, err)
	}
	var (
		out  []Receipt
		errs []error
	)
	for _, de := range des {
		if strings.HasPrefix(de.Name(), spoolTmpPrefix) {
			if rerr := os.Remove(filepath.Join(s.dir, de.Name())); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("spool temp file %s: %w", de.Name(), rerr))
			}
		}
	}
	names, err := s.entries()
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		path := filepath.Join(s.dir, n)
		e, err := s.read(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sk, ok := byName[e.Sink]
		if !ok {
			continue
		}
		r, err := sk.Put(ctx, Object{Key: e.Key, Body: e.Body})
		if err != nil {
			errs = append(errs, fmt.Errorf("drain %s: %w", e.Key, err))
			continue
		}
		if err := os.Remove(path); err != nil {
			errs = append(errs, fmt.Errorf("drain %s: %w", e.Key, err))
			continue
		}
		out = append(out, r)
	}
	if len(out) > 0 {
		if err := syncDir(s.dir); err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}
