package migrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/compliancetf/ctfkit/internal/tfexec"
)

// maxStateBytes caps a state pull, a plan file and a show -json output.
const maxStateBytes = 1 << 30

// Pin is the terraform binary migrate plan resolved and recorded in the plan
// file (tf_bin, tf_bin_sha256); every call runs a sealed copy of it.
type Pin struct {
	TFBin       string
	TFBinSHA256 string // hex, as the plan file records it
}

// VerifyLock runs ctfkit verify-lock on a unit's root and returns an error
// for a finding or an environment error.
type VerifyLock func(ctx context.Context, dir string) error

// Runner runs one unit's terraform calls through one internal/tfexec session
// spanning its steps: only the migrate rows of the Phase 3 argv table (A1,
// A2, A9-A14), each call of a workspace's steps with TF_WORKSPACE set to that
// workspace from the plan file, the unit's backend_env[] the only credential
// names, and its canonical local_paths on every init.
//
// The spec's Runner.Run(ctx, dir, env, args...) takes raw args; the Runner
// has one method per row instead, so no argv outside the table can be built.
type Runner struct {
	s      *tfexec.Session
	unit   Unit
	dir    string
	verify VerifyLock
}

// NewRunner opens the unit's session. root is the directory the plan file's
// unit dirs are relative to. Close removes the owned dirs.
func NewRunner(ctx context.Context, pin Pin, root string, u Unit, verify VerifyLock) (*Runner, error) {
	if verify == nil {
		return nil, errors.New("migrate: runner without verify-lock")
	}
	if !filepath.IsAbs(pin.TFBin) {
		return nil, fmt.Errorf("migrate: --tf-bin %q is not an absolute path", pin.TFBin)
	}
	dir, err := unitDir(root, u.Dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: %s: %w", u.ID, err)
	}
	cfg := tfexec.Config{Terraform: pin.TFBin, Digest: "sha256:" + pin.TFBinSHA256, Dir: dir, Credentials: u.BackendEnv, Ctx: ctx}
	if u.LocalPaths != nil {
		cfg.LocalPaths = &tfexec.LocalPaths{StatePath: u.LocalPaths.StatePath, WorkspaceDir: u.LocalPaths.WorkspaceDir}
	}
	s, err := tfexec.Open(cfg)
	if err != nil {
		return nil, fmt.Errorf("migrate: %s: %w", u.ID, err)
	}
	return &Runner{s: s, unit: u, dir: dir, verify: verify}, nil
}

// unitDir resolves a plan file unit dir against root; it must stay inside
// root once symlinks are resolved.
func unitDir(root, rel string) (string, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Join(realRoot, filepath.FromSlash(rel)))
	if err != nil {
		return "", err
	}
	if r, err := filepath.Rel(realRoot, dir); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unit dir %q is outside %s", rel, root)
	}
	return dir, nil
}

// Close removes the session's owned dirs.
func (r *Runner) Close() error { return r.s.Close() }

// run runs c in workspace ws: one of the plan file's workspaces, or "" (unset)
// while discovery has not listed them yet.
func (r *Runner) run(ws string, c tfexec.Call, stdout, stderr io.Writer) error {
	if ws == "" && len(r.unit.Workspaces) > 0 || ws != "" && !slices.Contains(r.unit.Workspaces, ws) {
		return fmt.Errorf("migrate: %s: workspace %q is not in the plan file", r.unit.ID, ws)
	}
	if err := r.s.Run(c.In(ws), stdout, stderr); err != nil {
		return fmt.Errorf("migrate: %s: %s: %w", r.unit.ID, c.Row(), err)
	}
	return nil
}

// output runs c and returns its stdout, capped.
func (r *Runner) output(ws string, c tfexec.Call, stderr io.Writer) ([]byte, error) {
	out := &cappedBuffer{limit: maxStateBytes}
	if err := r.run(ws, c, out, stderr); err != nil {
		return nil, err
	}
	return out.b, nil
}

// Version is A1.
func (r *Runner) Version(ws string, stderr io.Writer) ([]byte, error) {
	return r.output(ws, tfexec.Version(), stderr)
}

// Init is A2.
func (r *Runner) Init(ws string, stderr io.Writer) error {
	return r.run(ws, tfexec.Init(), nil, stderr)
}

// WorkspaceList is A9; TF_WORKSPACE is unset for it whatever ws is.
func (r *Runner) WorkspaceList(ws string, stderr io.Writer) ([]byte, error) {
	return r.output(ws, tfexec.WorkspaceList(), stderr)
}

// PreflightPlan is A10 pre. Its lock file predates the rewrite, so it runs
// without verify-lock. It returns the -detailed-exitcode (0 no changes, 2
// changes) and the sealed plan file.
func (r *Runner) PreflightPlan(ws string, stderr io.Writer) (int, tfexec.Sealed, error) {
	return r.plan(ws, "pre", stderr)
}

// ProofPlan is A10 post: verify-lock on the unit first, and a finding stops
// the plan.
func (r *Runner) ProofPlan(ctx context.Context, ws string, stderr io.Writer) (int, tfexec.Sealed, error) {
	if err := r.verify(ctx, r.dir); err != nil {
		return 0, tfexec.Sealed{}, fmt.Errorf("migrate: %s: verify-lock: %w", r.unit.ID, err)
	}
	return r.plan(ws, "post", stderr)
}

func (r *Runner) plan(ws, name string, stderr io.Writer) (int, tfexec.Sealed, error) {
	code := 0
	err := r.run(ws, tfexec.MigratePlan(name), nil, stderr)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
		code, err = 2, nil
	}
	if err != nil {
		return 0, tfexec.Sealed{}, err
	}
	// One sealed copy per workspace and kind: a unit's workspaces share the session.
	sealed, _, err := r.s.SealOwned(name+".tfplan", ws+"."+name+".tfplan", maxStateBytes)
	if err != nil {
		return 0, tfexec.Sealed{}, err
	}
	return code, sealed, nil
}

// Show is A11 of a sealed plan file (the A5 template, which tfexec.Check
// reports); show takes no lock.
func (r *Runner) Show(ws string, plan tfexec.Sealed, stderr io.Writer) ([]byte, error) {
	return r.output(ws, tfexec.Show(plan), stderr)
}

// StatePull is A12 (the A7 template, which tfexec.Check reports); state pull
// takes no lock.
func (r *Runner) StatePull(ws string, stderr io.Writer) ([]byte, error) {
	return r.output(ws, tfexec.StatePull(), stderr)
}

// ReplaceProvider is A13.
func (r *Runner) ReplaceProvider(ws, from, to, lockTimeout string, stderr io.Writer) error {
	return r.run(ws, tfexec.ReplaceProvider(from, to, lockTimeout), nil, stderr)
}

// ProvidersLock is A14.
func (r *Runner) ProvidersLock(ws, to string, platforms []string, stderr io.Writer) error {
	return r.run(ws, tfexec.ProvidersLock(to, platforms...), nil, stderr)
}

// cappedBuffer fails a write past limit. It has no ReadFrom, so io.Copy
// cannot bypass the cap.
type cappedBuffer struct {
	limit int
	b     []byte
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if len(c.b)+len(p) > c.limit {
		return 0, errors.New("terraform output too large")
	}
	c.b = append(c.b, p...)
	return len(p), nil
}
