// Package tfexec runs terraform under the Terraform exec rules (phase-3 D1,
// E6, E7, F1, F8; phase-m PM-T30): every call of gate plan, gate sign,
// ctfkit apply and migrate goes through a Session.
//
//   - Owned dirs: one 0700 mkdtemp root per session holds the child's cwd,
//     TF_DATA_DIR, HOME, TMPDIR, the sealed dir and the CLI config files, each
//     created exclusively (never over an existing path or symlink) and
//     checked for type, owner and mode.
//   - Terraform: before every call the pinned binary is opened, hashed from
//     the open fd against its recorded digest while its bytes are copied into
//     the sealed dir, and only that copy runs.
//   - Providers: the first init installs them from the lock file under an
//     empty CLI config; their packages are copied into the sealed provider
//     dir and checked against the lock file's h1: hashes; every later call
//     runs under a CLI config whose only installation method is a filesystem
//     mirror on the sealed dir, and after every later init each installed
//     package must be a link to its sealed copy.
//   - Env: deny by default, only the env table.
//   - Argv: only the rows of the argv table (argv.go).
//
// A refused terraform binary, a failed init or a failed provider check
// poisons the session: no later call runs. A refused argv, env or seal fails only that call.
package tfexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// fixedPath is the child PATH; nothing of the parent PATH reaches terraform.
const fixedPath = "/usr/bin:/bin"

// InterruptGrace is how long terraform gets to stop after its context is
// canceled before its process group is killed.
var InterruptGrace = 2 * time.Minute

// ErrNotStarted wraps an exec error from before terraform started.
var ErrNotStarted = errors.New("terraform did not start")

// LocalPaths are the canonical absolute state locations of a local backend,
// passed on every init so authoritative state never lands in an owned dir.
type LocalPaths struct{ StatePath, WorkspaceDir string }

// Config is what a session runs. Credentials and Proxy are variable names
// whose parent values pass through: the signed profile's names, or a migrate
// unit's backend_env[]; any other name is refused.
type Config struct {
	Terraform   string // absolute path of the pinned binary
	Digest      string // sha256:<hex> of its bytes
	Dir         string // absolute configuration directory
	Workspace   string // TF_WORKSPACE of every call; "" leaves it unset
	Credentials []string
	Proxy       []string
	LocalPaths  *LocalPaths
	// Ctx, when set, interrupts terraform's process group on cancel.
	Ctx context.Context
}

// Session is one run's terraform session in owned directories.
type Session struct {
	cfg       Config
	root      string
	cliConfig string   // the owned CLI config of the next call
	sealed    []string // sealed provider package dirs, relative to sealed/providers
	inited    bool
	broken    error
	seq       int
}

// Open creates the owned directories of a session. Close removes them.
func Open(cfg Config) (*Session, error) {
	if err := checkConfig(&cfg); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp("", "ctfkit-tf-") // 0700
	if err != nil {
		return nil, err
	}
	s := &Session{cfg: cfg, root: root}
	if s.root, err = filepath.EvalSymlinks(root); err != nil { // no symlink in any owned path
		return nil, errors.Join(err, os.RemoveAll(root))
	}
	if err = s.createOwned(); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	s.cliConfig = s.owned("empty.tfrc")
	return s, nil
}

// BeforeOwned runs between the root and its entries; tests (here and in
// internal/cli) plant paths there. Production code never sets it.
var BeforeOwned = func(string) {}

func (s *Session) createOwned() error {
	if err := checkOwned(s.root, true, 0o700); err != nil {
		return err
	}
	BeforeOwned(s.root)
	for _, d := range []string{"cwd", "data", "home", "tmp", "sealed", "sealed/providers"} {
		if err := os.Mkdir(s.owned(d), 0o700); err != nil { // EEXIST on any existing path, a symlink included
			return err
		}
	}
	mirror := fmt.Sprintf("provider_installation {\n  filesystem_mirror {\n    path    = %q\n    include = [\"*/*/*\"]\n  }\n}\n", s.owned("sealed/providers"))
	for name, body := range map[string]string{"empty.tfrc": "", "mirror.tfrc": mirror} {
		if err := writeExclusive(s.owned(name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	for _, d := range []string{"cwd", "data", "home", "tmp", "sealed", "sealed/providers"} {
		if err := checkOwned(s.owned(d), true, 0o700); err != nil {
			return err
		}
	}
	for _, f := range []string{"empty.tfrc", "mirror.tfrc"} {
		if err := checkOwned(s.owned(f), false, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// checkOwned refuses a path that is a symlink, not the expected type, not
// this uid's, or has another mode.
func checkOwned(path string, dir bool, mode os.FileMode) error {
	fi, err := os.Lstat(path)
	switch {
	case err != nil:
		return err
	case fi.IsDir() != dir || (!dir && !fi.Mode().IsRegular()):
		return fmt.Errorf("%s: not an owned %s", path, map[bool]string{true: "directory", false: "file"}[dir])
	case !ownedByUs(fi):
		return fmt.Errorf("%s: owned by another user", path)
	case fi.Mode().Perm() != mode:
		return fmt.Errorf("%s: mode %o, want %o", path, fi.Mode().Perm(), mode)
	}
	return nil
}

// Close removes the owned root.
func (s *Session) Close() error { return os.RemoveAll(s.root) }

// Owned is the absolute path of name inside the owned root.
func (s *Session) Owned(name string) string { return s.owned(name) }

func (s *Session) owned(name string) string { return filepath.Join(s.root, filepath.FromSlash(name)) }

// Run runs one call. Output goes to stdout (nil: stderr); the error is the
// *exec.ExitError of a non-zero exit, ErrNotStarted when the process never
// ran, or a check that refused the call.
func (s *Session) Run(c Call, stdout, stderr io.Writer) error {
	if s.broken != nil {
		// %v: a stopped session's cause is never this call's exit status
		return fmt.Errorf("%w: terraform session stopped: %v", ErrNotStarted, s.broken)
	}
	tmpl := slices.Clone(c.argv)
	if c.init && s.cfg.LocalPaths != nil {
		tmpl = append(tmpl, "-backend-config=path="+s.cfg.LocalPaths.StatePath,
			"-backend-config=workspace_dir="+s.cfg.LocalPaths.WorkspaceDir)
	}
	// Every decision below uses the row the table matches, never the call's own label.
	row, err := Check(tmpl)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStarted, err)
	}
	init := row == "A2" || row == "A15"
	if !s.inited && !init && row != "A1" {
		return fmt.Errorf("%w: argv row %s before init", ErrNotStarted, row)
	}
	if s.inited {
		// Every call after the first init may run a provider: the data dir
		// must still link exactly the sealed copies.
		if err = s.verifyLinks(); err != nil {
			s.broken = err
			return fmt.Errorf("%w: %w", ErrNotStarted, err)
		}
	}
	err = s.exec(row, tmpl, c, stdout, stderr)
	if !init {
		return err
	}
	if err != nil {
		s.broken = fmt.Errorf("terraform init failed: %w", err)
		return err
	}
	if !s.inited {
		s.inited = true
		if err = s.sealProviders(); err == nil && len(s.sealed) > 0 {
			err = s.exec(row, tmpl, c, stdout, stderr) // the mirror init: terraform links the sealed copies
		}
	}
	if err == nil {
		err = s.verifyLinks()
	}
	if err != nil {
		s.broken = err
	}
	return err
}

func (s *Session) exec(row string, tmpl []string, c Call, stdout, stderr io.Writer) error {
	env, err := s.env(row, c)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStarted, err)
	}
	tf, err := s.sealTerraform()
	if err != nil {
		s.broken = err
		return fmt.Errorf("%w: %w", ErrNotStarted, err)
	}
	defer os.Remove(tf) //nolint:errcheck // Close removes the root anyway
	argv := make([]string, len(tmpl))
	for i, a := range tmpl {
		a = strings.Replace(a, "<tf>", tf, 1)
		a = strings.Replace(a, "-chdir=<dir>", "-chdir="+s.cfg.Dir, 1)
		argv[i] = strings.Replace(a, "<owned>/", s.root+string(filepath.Separator), 1)
	}
	ctx := s.cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// A cancel interrupts terraform's process group (terraform stops
	// gracefully on SIGINT), then kills it after InterruptGrace. A caller that
	// cannot cancel leaves terraform in ctfkit's group, so a terminal SIGINT
	// still reaches it and it never outlives ctfkit holding a state lock.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv comes only from the argv table
	group := ctx.Done() != nil
	if group {
		setProcessGroup(cmd)
	}
	cmd.WaitDelay = InterruptGrace
	cmd.Dir, cmd.Env = s.owned("cwd"), env
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if stdout == nil {
		cmd.Stdout = stderr
	}
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("%w: %w", ErrNotStarted, err)
	}
	err = cmd.Wait()
	if group {
		killGroup(cmd) // a provider process left behind never outlives its call
	}
	return err
}

// env is the child env of one call of row: the env table and nothing else.
func (s *Session) env(row string, c Call) ([]string, error) {
	ws := s.cfg.Workspace
	if c.workspace != nil {
		ws = *c.workspace
	}
	switch {
	case row == "A9" || row == "A16":
		ws = ""
	case ws == "" && row != "A1" && row != "A2":
		// TF_WORKSPACE is unset only for A9 and A16, and for version and init
		// before migrate discovery has listed the workspaces.
		return nil, fmt.Errorf("argv row %s needs a workspace", row)
	}
	if ws != "" && !reWorkspace.MatchString(ws) {
		return nil, fmt.Errorf("workspace %q", ws)
	}
	env := []string{
		"PATH=" + fixedPath,
		"HOME=" + s.owned("home"),
		"TMPDIR=" + s.owned("tmp"),
		"TF_DATA_DIR=" + s.owned("data"),
		"TF_CLI_CONFIG_FILE=" + s.cliConfig,
		"TF_IN_AUTOMATION=1",
	}
	if ws != "" {
		env = append(env, "TF_WORKSPACE="+ws)
	}
	for _, n := range slices.Concat(s.cfg.Credentials, s.cfg.Proxy) {
		if v, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+v)
		}
	}
	for _, kv := range c.extra {
		n, v, _ := strings.Cut(kv, "=")
		if row != "A6" || !slices.Contains(applyEnv, n) || !filepath.IsAbs(v) {
			return nil, fmt.Errorf("%s may not reach terraform", n)
		}
		env = append(env, kv)
	}
	return env, nil
}

// applyEnv are the only COMPLIANCETF_* variables, set by ctfkit apply on
// A6 alone; each names an owned file.
var applyEnv = []string{"COMPLIANCETF_VERDICT", "COMPLIANCETF_VERDICT_KEY_FILE", "COMPLIANCETF_BASELINE_KEY_FILE"}

var reEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// proxyNames are the only names Proxy may hold, matched in any case.
var proxyNames = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}

// reserved reports whether name is set by the session itself or never passes:
// the env table's fixed rows, LD_*, DYLD_*, TF_* and TOFU_* (TF_CLI_ARGS*,
// TF_REATTACH_PROVIDERS, TF_PLUGIN_CACHE_DIR, TF_LOG* included), the CA
// variables, TERRAFORM_CONFIG, and the variables that make a child terraform
// starts (git, ssh, a shell, node, go) or an AWS config file run code.
func reserved(name string) bool {
	u := strings.ToUpper(name)
	for _, p := range []string{"TF_", "TOFU_", "COMPLIANCETF_", "LD_", "DYLD_", "SSL_CERT_", "GIT_", "SSH_"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return strings.HasSuffix(u, "_CA_BUNDLE") || slices.Contains([]string{"PATH", "HOME", "TMPDIR", "TERRAFORM_CONFIG",
		"GODEBUG", "GOFLAGS", "BASH_ENV", "ENV", "NODE_OPTIONS", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"}, u)
}

func checkConfig(cfg *Config) error {
	if !supported {
		return errors.New("the Terraform exec rules need a unix runner")
	}
	if !filepath.IsAbs(cfg.Terraform) {
		return fmt.Errorf("terraform binary %q is not an absolute path", cfg.Terraform)
	}
	if !strings.HasPrefix(cfg.Digest, "sha256:") {
		return errors.New("no recorded terraform digest")
	}
	if !filepath.IsAbs(cfg.Dir) || filepath.Clean(cfg.Dir) != cfg.Dir {
		return fmt.Errorf("configuration directory %q is not a clean absolute path", cfg.Dir)
	}
	if cfg.Workspace != "" && !reWorkspace.MatchString(cfg.Workspace) {
		return fmt.Errorf("workspace %q", cfg.Workspace)
	}
	for _, n := range cfg.Credentials {
		if !reEnvName.MatchString(n) || reserved(n) || slices.Contains(proxyNames, strings.ToUpper(n)) {
			return fmt.Errorf("credential variable %q may not reach terraform", n)
		}
	}
	for _, n := range cfg.Proxy {
		if !slices.Contains(proxyNames, strings.ToUpper(n)) {
			return fmt.Errorf("proxy variable %q is not a proxy variable", n)
		}
	}
	if p := cfg.LocalPaths; p != nil {
		for _, a := range []string{p.StatePath, p.WorkspaceDir} {
			if !token("<abs>", a) {
				return fmt.Errorf("local backend path %q is not a clean absolute path", a)
			}
		}
	}
	return nil
}
