package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/tfexec"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
)

// Env the provider reads in the terraform apply child, and only there.
const (
	envVerdict         = "COMPLIANCETF_VERDICT"
	envVerdictKeyFile  = "COMPLIANCETF_VERDICT_KEY_FILE"
	envBaselineKeyFile = "COMPLIANCETF_BASELINE_KEY_FILE"
)

// Outcomes of an apply run in result.json and the tombstone.
const (
	outcomeEnforced   = "enforced"
	outcomeFailed     = "failed"
	outcomeOverridden = "overridden"
	outcomeRefused    = "refused" // nothing applied
)

// applyResult is result.json.
// shortcut: the run's result and per-decision evidence in one file, which
// ctfkit evidence ship --artifacts reads for the provider-run receipt; the
// post-apply evidence records and the exit code table replace it.
type applyResult struct {
	RunID         string        `json:"run_id"`
	PlanDigest    string        `json:"plan_digest"`
	Outcome       string        `json:"outcome"`
	Exit          string        `json:"exit"`
	TerraformExit string        `json:"terraform_exit,omitempty"`
	Message       string        `json:"message,omitempty"`
	Rows          []resolve.Row `json:"rows"`
}

// apply checks the artifact set, applies its sealed planfile and finalizes
// the set on every exit after it was read, under the set's owner lock.
func (c *CLI) apply(cmd *cobra.Command, opts *applyOptions) (err error) {
	// A signal ends the run through finalize, never by the default handler.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd.SetContext(ctx)
	baseline, err := readBaselineKey(opts.baselineKeyFile)
	if err != nil {
		return err
	}
	// A set that is not exact is left as it is; a tombstoned one is locked
	// once more, to remove a key an interrupted finalize left.
	dir, _, _, _, err := readSigned(cmd, opts)
	var tomb errTombstonedSet
	if errors.As(err, &tomb) {
		err = nil // a valid set directory: lock it to clean up, then refuse
	}
	if err != nil {
		return err
	}
	lock, err := c.takeSet(dir, opts.artifacts)
	if err != nil {
		return err
	}
	defer lock.release()
	// Read again under the lock: another run may have consumed the set.
	_, files, cand, _, err := readSigned(cmd, opts)
	if err != nil {
		return err
	}
	if err = lock.claim(); err != nil {
		return environmentError(err)
	}
	custodyHook("locked")
	res := &applyResult{PlanDigest: cand.PlanDigest, Outcome: outcomeRefused, Rows: []resolve.Row{}}
	defer func() {
		// A panic still consumes the set, recorded as an environment error.
		if r := recover(); r != nil {
			err = environmentError(fmt.Errorf("panic: %v", r))
		}
		err = finalize(dir, files[artifactRunKey], res, err)
	}()
	s, err := c.checkSigned(cmd, opts, files, cand)
	defer s.cleanup(cmd.ErrOrStderr())
	if s.doc != nil {
		res.RunID = s.doc.RunID
	}
	if s.outcome != nil {
		res.Rows = s.outcome.Rows
	}
	if err == nil && ctx.Err() != nil {
		err = inputError("interrupted by a signal; nothing applied")
	}
	if err != nil {
		return err
	}
	printWarnings(cmd.ErrOrStderr(), s.outcome)
	if err = c.startApply(dir, s, files, baseline); err != nil {
		return environmentError(err)
	}
	res.Outcome = outcomeFailed
	err = s.run.apply(cmd.ErrOrStderr())
	custodyHook("applied")
	if ctx.Err() != nil && !errors.Is(err, tfexec.ErrNotStarted) {
		// Interrupted: failed even when terraform exited 0.
		_ = applyFailure(res, err)
		res.Outcome = outcomeFailed
		return &ExitError{Code: ExitFindings, Message: "interrupted by a signal during terraform apply: outcome failed"}
	}
	if err != nil {
		return applyFailure(res, err)
	}
	res.TerraformExit = "0"
	res.Outcome = applyOutcome(s.outcome)
	switch res.Outcome {
	case outcomeFailed:
		// shortcut: the post-apply linkage check is not built, so a
		// pending decision stays undecided and ends fail.
		return &ExitError{Code: ExitFindings, Message: "terraform apply succeeded, but pending decisions need the post-apply linkage check, which is not available yet: outcome failed"}
	case outcomeOverridden:
		return &ExitError{Code: ExitFindings, Message: "terraform apply succeeded under a break-glass receipt: outcome overridden"}
	}
	return nil
}

// takeSet restores the set's modes, takes its owner lock and ends an earlier
// run whose owner is gone; any error releases the lock.
func (c *CLI) takeSet(dir, name string) (*runLock, error) {
	if err := restoreModes(dir); err != nil {
		return nil, environmentError(err)
	}
	lock, err := lockSet(dir)
	if err != nil {
		return nil, inputError("--artifacts %s: owner lock: %v", name, err)
	}
	done, what, err := recoverSet(dir, lock.prev, c.now())
	switch {
	case err != nil:
		err = environmentError(fmt.Errorf("--artifacts %s: ending an earlier run: %w", name, err))
	case done && what == "tombstoned":
		err = inputError("--artifacts %s %v", name, errTombstoned)
	case done:
		err = inputError("--artifacts %s: %s; this set is consumed now, nothing applied: run gate plan again", name, what)
	}
	if err != nil {
		lock.release()
		return nil, err
	}
	return lock, nil
}

// startApply makes apply-start.json durable, then stages the child's copies
// of the checked verdict and keys in the set's staged dir, so a crash leaves
// them where recovery removes them, and sets the apply child's env.
func (c *CLI) startApply(dir string, s *signedRun, files map[string][]byte, baseline []byte) error {
	start := applyStart{RunID: s.doc.RunID, StartedAt: c.now().UTC().Format(time.RFC3339), Owner: self()}
	if err := publish(dir, artifactStart, start); err != nil {
		return err
	}
	custodyHook("started")
	staged := filepath.Join(dir, artifactStaged)
	if err := os.Mkdir(staged, 0o700); err != nil {
		return err
	}
	copies := []struct {
		name, env string
		body      []byte
		mode      os.FileMode
	}{
		{artifactVerdict, envVerdict, files[artifactVerdict], 0o600},
		{artifactRunKey, envVerdictKeyFile, files[artifactRunKey], 0o400},
		{"baseline.key", envBaselineKeyFile, baseline, 0o400},
	}
	for _, cp := range copies {
		if cp.body == nil {
			continue
		}
		p := filepath.Join(staged, cp.name)
		if err := writeExclusive(p, cp.body, cp.mode); err != nil {
			return err
		}
		s.run.applyEnv = append(s.run.applyEnv, cp.env+"="+p)
	}
	return syncDir(staged)
}

// readBaselineKey reads --baseline-key-file: an absolute path of a regular
// file of this user with no mode bits outside 0600. nil when not given.
func readBaselineKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return readSecretFile("--baseline-key-file", path)
}

// readSecretFile reads a key file named by flag: an absolute path of a
// regular file of this user with no mode bits outside 0600, 1 byte to 64 KiB.
func readSecretFile(flag, path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, inputError("%s %s is not an absolute path; give the full path", flag, path)
	}
	f, err := openRegular(path)
	if err != nil {
		return nil, inputError("%s: %v", flag, err)
	}
	defer f.Close() //nolint:errcheck // read-only
	st, err := f.Stat()
	if err == nil && (st.Mode().Perm()&^0o600 != 0 || !ownedByUs(st)) {
		err = errors.New("must be a 0600 file owned by this user")
	}
	var b []byte
	if err == nil {
		b, err = io.ReadAll(io.LimitReader(f, 1<<16+1))
	}
	if err == nil && (len(b) == 0 || len(b) > 1<<16) {
		err = errors.New("empty or larger than 64 KiB")
	}
	if err != nil {
		return nil, inputError("%s: %v", flag, err)
	}
	return b, nil
}

// applyFailure records a terraform apply that did not succeed. Only a
// process that never started is refused; once it ran, the outcome is failed
// whatever stopped it, since state may have changed.
func applyFailure(res *applyResult, err error) error {
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		res.TerraformExit = strconv.Itoa(exitErr.ExitCode())
		return &ExitError{Code: ExitFindings, Message: "terraform apply failed: outcome failed"}
	case errors.Is(err, tfexec.ErrNotStarted):
		res.Outcome = outcomeRefused
		return inputError("terraform apply: %v", err)
	}
	return environmentError(fmt.Errorf("terraform apply ran, but its result is unknown: %w; outcome failed", err))
}

// applyOutcome is the outcome after a successful terraform apply.
func applyOutcome(o *resolve.Outcome) string {
	out := outcomeEnforced
	for _, r := range o.Rows {
		switch {
		case r.Result == resolve.ResultPending:
			return outcomeFailed
		case r.Proof != nil && r.Proof.Kind == resolve.KindBreakGlass:
			out = outcomeOverridden
		}
	}
	return out
}

// tombstone is ctfkit-run.tombstone.
type tombstone struct {
	NonceDigest string `json:"nonce_digest"`
	RunID       string `json:"run_id"`
	Outcome     string `json:"outcome"`
}

// finalize ends the run (finish): result.json, then the tombstone, then the
// key unlinked, each durable before the next. A failure keeps the key and
// exits 2.
func finalize(dir string, key []byte, res *applyResult, runErr error) error {
	res.Exit = strconv.Itoa(ExitCode(runErr))
	if runErr != nil {
		res.Message = runErr.Error()
	}
	err := finish(dir, rawDigest(key), res, res.Outcome)
	if err == nil {
		return runErr
	}
	msg := "finalizing the artifact set: " + err.Error()
	if runErr != nil {
		msg = runErr.Error() + "; " + msg
	}
	return &ExitError{Code: ExitEnvironment, Category: categoryInput, Message: msg}
}
