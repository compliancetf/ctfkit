package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
)

// Custody files ctfkit apply keeps in the artifact set beside result.json
// and the tombstone. None is in candidate.json's exact list.
const (
	artifactLock   = "ctfkit-run.lock"   // owner lock: flock plus the owner identity
	artifactStart  = "apply-start.json"  // durable before terraform apply starts
	artifactStaged = "ctfkit-run.staged" // dir: the apply child's copies of the verdict and keys
	reapedPrefix   = "ctfkit-run.key.reaped-"
	tmpPrefix      = ".ctfkit-tmp-"
)

var errLockHeld = errors.New("owner lock held")

var errTombstoned = errors.New("is tombstoned: ctfkit apply already ran on it; run gate plan again")

// custodyHook runs after each custody step; tests kill the process there.
var custodyHook = func(string) {}

func isCustody(name string) bool {
	return slices.Contains([]string{artifactLock, artifactStart, artifactResult, artifactStaged}, name) ||
		strings.HasPrefix(name, reapedPrefix) || strings.HasPrefix(name, tmpPrefix)
}

func checkCustodyMode(name string, fi os.FileInfo) error {
	if name == artifactStaged {
		if fi.IsDir() && fi.Mode().Perm()&^0o700 == 0 && ownedByUs(fi) {
			return nil
		}
	} else if fi.Mode().IsRegular() && fi.Mode().Perm()&^0o600 == 0 && ownedByUs(fi) {
		return nil
	}
	return fmt.Errorf("%s: wrong type, mode or owner", name)
}

// owner is a process identity: the pid alone can be reused, the pid with
// its start time and the boot id cannot.
type owner struct {
	PID   int    `json:"pid"`
	Start string `json:"start_time"`
	Boot  string `json:"boot_id"`
}

// self is this process's identity; empty fields when the platform has none.
func self() owner {
	o := owner{PID: os.Getpid()}
	o.Start, _ = procStart(o.PID)
	o.Boot, _ = bootID()
	return o
}

// gone reports that o no longer exists: no identity was recorded, the boot
// id differs, the pid is absent or its start time differs. An identity that
// cannot be read counts as live.
func (o owner) gone() bool {
	if o.PID == 0 {
		return true
	}
	boot, err := bootID()
	if err != nil || o.Boot == "" {
		return false
	}
	if boot != o.Boot {
		return true
	}
	start, err := procStart(o.PID)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	return err == nil && start != o.Start
}

// runLock is the held owner lock of one artifact set.
type runLock struct {
	f    *os.File
	prev owner // identity the lock file held when taken
}

// lockSet takes the owner lock without waiting. A held lock names its owner.
func lockSet(dir string) (*runLock, error) {
	f, err := os.OpenFile(filepath.Join(dir, artifactLock), os.O_RDWR|os.O_CREATE|oNoFollow, 0o600) // #nosec G304 -- inside the checked artifact set
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil {
		err = checkCustodyMode(artifactLock, st)
	}
	if err == nil && linkCount(st) != 1 {
		// claim truncates it: a hard link would overwrite another file
		err = fmt.Errorf("%s: has %d hard links", artifactLock, linkCount(st))
	}
	if err == nil {
		err = flockNB(f)
	}
	var prev owner
	b, rerr := io.ReadAll(io.LimitReader(f, 4096))
	if rerr == nil {
		_ = json.Unmarshal(b, &prev) // a torn or empty lock records no identity
	}
	if err != nil {
		_ = f.Close()
		if errors.Is(err, errLockHeld) {
			return nil, fmt.Errorf("in use by ctfkit pid %d", prev.PID)
		}
		return nil, err
	}
	return &runLock{f: f, prev: prev}, nil
}

// claim records this process as the owner.
func (l *runLock) claim() error {
	b, err := json.Marshal(self())
	if err == nil {
		err = l.f.Truncate(0)
	}
	if err == nil {
		_, err = l.f.WriteAt(b, 0)
	}
	if err == nil {
		err = l.f.Sync()
	}
	return err
}

// release drops the lock; the lock file stays.
func (l *runLock) release() { _ = l.f.Close() }

// restoreModes sets a set narrowed in transport (0500 dir, 0400 files) back
// to 0700 and 0600; readArtifactSet refused any wider mode already.
func restoreModes(dir string) error {
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its search bit
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			if err = os.Chmod(filepath.Join(dir, e.Name()), 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// publish writes v as name once: to a temp name, fsynced, then hard-linked
// into place (never over an existing file) and the dir fsynced, so a crash
// leaves either no file or the whole file.
func publish(dir, name string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, tmpPrefix+name)
	_ = os.Remove(tmp) // a leftover of a crashed run, under the lock
	if err = writeExclusive(tmp, body, 0o600); err != nil {
		return err
	}
	err = os.Link(tmp, filepath.Join(dir, name))
	if rerr := os.Remove(tmp); err == nil {
		err = rerr
	}
	if err == nil {
		err = syncDir(dir)
	}
	return err
}

// applyStart is apply-start.json.
type applyStart struct {
	RunID     string `json:"run_id"`
	StartedAt string `json:"started_at"`
	Owner     owner  `json:"owner"`
}

// finish ends a run in one order for apply, recovery and the reaper: the
// staged copies removed, result.json published (res nil: it exists), the
// tombstone published, then the key renamed to a reaper name and unlinked.
// The key goes only once the result and tombstone are durable.
func finish(dir string, nonceDigest string, res *applyResult, outcome string) error {
	err := removeStaged(dir)
	if err == nil && res != nil {
		err = publish(dir, artifactResult, res)
	}
	custodyHook("result")
	if err == nil {
		err = publish(dir, artifactTombstone, tombstone{NonceDigest: nonceDigest, RunID: runIDOf(res, dir), Outcome: outcome})
	}
	custodyHook("tombstone")
	if err == nil {
		err = retireKey(dir)
	}
	return err
}

func runIDOf(res *applyResult, dir string) string {
	if res != nil {
		return res.RunID
	}
	if r, err := readJSON[applyResult](filepath.Join(dir, artifactResult)); err == nil {
		return r.RunID
	}
	return ""
}

// retireKey renames ctfkit-run.key to a reaper name, then unlinks it and
// any leftover of an earlier rename.
func retireKey(dir string) error {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	key := filepath.Join(dir, artifactRunKey)
	if err := os.Rename(key, filepath.Join(dir, reapedPrefix+hex.EncodeToString(r[:]))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	custodyHook("renamed")
	if err := removeLeftovers(dir); err != nil {
		return err
	}
	return syncDir(dir)
}

// removeLeftovers unlinks reaper-named keys and temp files.
func removeLeftovers(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), reapedPrefix) || strings.HasPrefix(e.Name(), tmpPrefix) {
			if err = os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func removeStaged(dir string) error {
	p := filepath.Join(dir, artifactStaged)
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err == nil {
		err = checkCustodyMode(artifactStaged, st)
	}
	if err == nil {
		err = os.Chmod(p, 0o700) //nolint:gosec // G302: a directory needs its search bit; a 0500 dir could not be emptied
	}
	if err == nil {
		err = os.RemoveAll(p) // does not follow symlinks inside
	}
	return err
}

func readJSON[T any](path string) (T, error) {
	var v T
	b, err := readCapped(path, 1<<20)
	if err == nil {
		err = json.Unmarshal(b, &v)
	}
	return v, err
}

func inSet(dir, name string) bool {
	_, err := os.Lstat(filepath.Join(dir, name))
	return err == nil
}

// recoverSet ends an earlier run on the set whose owner is gone, under the
// lock: a tombstoned set loses a leftover key; a result without a tombstone
// is tombstoned with its outcome; apply-start.json without a result gets a
// failed result, then the tombstone. It never records enforced for a run
// that has no result. done is false when there was nothing to recover.
func recoverSet(dir string, prev owner, now time.Time) (done bool, what string, err error) {
	key := filepath.Join(dir, artifactRunKey)
	switch {
	case inSet(dir, artifactTombstone):
		if err = removeStaged(dir); err == nil {
			err = retireKey(dir)
		}
		return true, "tombstoned", err
	case !inSet(dir, artifactResult) && !inSet(dir, artifactStart):
		return false, "", removeLeftovers(dir)
	case !prev.gone():
		return true, "", fmt.Errorf("the earlier ctfkit apply (pid %d) may still run", prev.PID)
	}
	raw, err := readCapped(key, 1<<10)
	if err != nil {
		return true, "", err
	}
	if inSet(dir, artifactResult) {
		outcome := outcomeFailed
		if r, rerr := readJSON[applyResult](filepath.Join(dir, artifactResult)); rerr == nil && r.Outcome != "" {
			outcome = r.Outcome
		}
		return true, "an earlier ctfkit apply ended with outcome " + outcome + " before consuming the set", finish(dir, rawDigest(raw), nil, outcome)
	}
	start, err := readJSON[applyStart](filepath.Join(dir, artifactStart))
	if err != nil {
		return true, "", fmt.Errorf("%s: %w", artifactStart, err)
	}
	msg := fmt.Sprintf("the ctfkit apply that started terraform apply at %s did not finish: outcome failed", start.StartedAt)
	res := &applyResult{RunID: start.RunID, Outcome: outcomeFailed, Exit: "1", Message: msg + "; recorded at " + now.UTC().Format(time.RFC3339), Rows: []resolve.Row{}}
	return true, msg, finish(dir, rawDigest(raw), res, outcomeFailed)
}

// reap ends orphaned artifact sets directly under root that belong to org
// and profile: an apply that started and never finished gets fail evidence
// and the tombstone at any age; a set never applied, older than ttl, whose
// owner lock is free and whose owner is gone, gets a refused result and the
// tombstone, its key renamed to a reaper name and unlinked. A tombstoned
// set, a set of another profile and a held lock are left alone. It returns
// one line per set it changed or could not.
func reap(root, skip, org, profileDigest string, ttl time.Duration, now time.Time) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return []string{"--reap-dir: " + err.Error()}
	}
	var notes []string
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if !e.IsDir() || dir == skip {
			continue
		}
		if note := reapOne(dir, org, profileDigest, ttl, now); note != "" {
			notes = append(notes, dir+": "+note)
		}
	}
	return notes
}

// verdictExpired reports whether a signed set's verdict has expired; true for
// an unsigned set. A set signed late is not reaped while its verdict is valid.
func verdictExpired(raw []byte, now time.Time) bool {
	if raw == nil {
		return true
	}
	var doc struct {
		ExpiresAt string `json:"expires_at"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	exp, err := time.Parse(time.RFC3339, doc.ExpiresAt)
	return err == nil && !now.Before(exp)
}

func reapOne(dir, org, profileDigest string, ttl time.Duration, now time.Time) string {
	files, cand, _, err := readSetMode(dir, true, false)
	if err != nil || cand.OrgID != org || cand.ProfileDigest != profileDigest {
		return "" // not a set of this profile, or tombstoned
	}
	st, err := os.Lstat(filepath.Join(dir, artifactCandidate))
	young := err != nil || now.Sub(st.ModTime()) < ttl || !verdictExpired(files[artifactVerdict], now)
	if young && !inSet(dir, artifactStart) {
		return "" // untouched: the lock file would stop gate sign
	}
	custodyHook("reap-read")
	if err = restoreModes(dir); err != nil {
		return "not reaped: " + err.Error()
	}
	lock, err := lockSet(dir)
	if err != nil {
		return "not reaped: " + err.Error()
	}
	defer lock.release()
	done, what, err := recoverSet(dir, lock.prev, now)
	switch {
	case err != nil:
		return "not reaped: " + err.Error()
	case done:
		return what
	}
	// Read again under the lock: gate sign may have signed the set since.
	if files, _, _, err = readSetMode(dir, true, false); err != nil {
		return "not reaped: " + err.Error()
	}
	if young || !verdictExpired(files[artifactVerdict], now) || !lock.prev.gone() {
		return ""
	}
	res := &applyResult{PlanDigest: cand.PlanDigest, Outcome: outcomeRefused, Exit: "2", Rows: []resolve.Row{},
		Message: "reaped: older than verdict.max_ttl and never applied; nothing applied"}
	if raw, ok := files[artifactVerdict]; ok {
		var doc struct {
			RunID string `json:"run_id"`
		}
		_ = json.Unmarshal(raw, &doc)
		res.RunID = doc.RunID
	}
	if err = finish(dir, rawDigest(files[artifactRunKey]), res, outcomeRefused); err != nil {
		return "not reaped: " + err.Error()
	}
	return "reaped: older than verdict.max_ttl"
}

// errTombstonedSet is readSigned's error for a tombstoned set: the directory
// passed every check up to the tombstone, so apply may lock it to clean up.
type errTombstonedSet struct{ *ExitError }

func (e errTombstonedSet) Unwrap() error { return e.ExitError }
