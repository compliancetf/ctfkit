package migrate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/tfroots"
)

// Unit is one units[] entry of the plan file (ctfkit.migrate-plan/1): a root
// and the state instances migrate rebinds in it.
type Unit struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	Dir        string      `json:"dir"`
	Backend    string      `json:"backend"`
	BackendEnv []string    `json:"backend_env"`
	LocalPaths *LocalPaths `json:"local_paths,omitempty"`
	Workspaces []string    `json:"workspaces"`
}

// LocalPaths are the canonical absolute state locations of a local backend,
// passed on every init so authoritative state never lands in an owned dir.
type LocalPaths struct {
	StatePath    string `json:"state_path"`
	WorkspaceDir string `json:"workspace_dir"`
}

// WorkspaceLister runs `<tf> -chdir=<dir> workspace list` (argv A9, with
// TF_WORKSPACE unset) for a unit and returns its stdout.
type WorkspaceLister func(ctx context.Context, u Unit) ([]byte, error)

// backendEnv names the credential variables the env table passes for each CLI
// backend migrate supports; values are never recorded. A backend missing here
// is refused rather than run without its credentials. These names are the
// only credential names a Runner passes (internal/tfexec refuses any name the
// env table never passes, a CA or proxy variable included); a set parent value
// passes unchanged, an unset one is left out.
var backendEnv = map[string][]string{
	"local":   {},
	"s3":      {"AWS_ACCESS_KEY_ID", "AWS_REGION", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"},
	"gcs":     {"GOOGLE_BACKEND_CREDENTIALS", "GOOGLE_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN"},
	"azurerm": {"ARM_ACCESS_KEY", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_SAS_TOKEN", "ARM_SUBSCRIPTION_ID", "ARM_TENANT_ID"},
}

// Local backend defaults, as Terraform and OpenTofu apply them.
const (
	defaultStatePath    = "terraform.tfstate"
	defaultWorkspaceDir = "terraform.tfstate.d"
)

// DiscoverUnits returns the CLI units under root, one per tfroots root in Dir
// order, each with the workspaces list reports for it.
func DiscoverUnits(ctx context.Context, root string, list WorkspaceLister) ([]Unit, error) {
	archive, err := loader.LoadConfig(root)
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	roots, err := tfroots.Roots(archive)
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	units := make([]Unit, 0, len(roots))
	for _, r := range roots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		u, err := cliUnit(absRoot, r)
		if err != nil {
			return nil, fmt.Errorf("migrate: %s: %w", r.Dir, err)
		}
		out, err := list(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("migrate: %s: workspace list: %w", r.Dir, err)
		}
		if u.Workspaces, err = parseWorkspaceList(out); err != nil {
			return nil, fmt.Errorf("migrate: %s: workspace list: %w", r.Dir, err)
		}
		units = append(units, u)
	}
	return units, nil
}

// cliUnit builds the unit of one root, workspaces not yet listed.
func cliUnit(absRoot string, r tfroots.Root) (Unit, error) {
	if r.Unparseable {
		return Unit{}, errors.New("a configuration file does not parse, so its backend is unknown")
	}
	backend := r.Backend
	if backend == "" {
		backend = "local"
	}
	if backend == "cloud" || backend == "remote" {
		// shortcut: HCP/TFE units arrive in M2 (PM-T17); until then refuse them.
		return Unit{}, fmt.Errorf("backend %s is migrated through HCP/TFE, which this build does not support yet", backend)
	}
	env, ok := backendEnv[backend]
	if !ok {
		return Unit{}, fmt.Errorf("backend %s is not supported by migrate", backend)
	}
	u := Unit{ID: r.Dir, Kind: "cli", Dir: r.Dir, Backend: backend, BackendEnv: slices.Clone(env)}
	if backend == "local" {
		paths, err := localPaths(absRoot, r)
		if err != nil {
			return Unit{}, err
		}
		u.LocalPaths = paths
	}
	return u, nil
}

// localPaths resolves the state path and workspace dir of a local backend
// against the canonical root directory, the way Terraform resolves them
// against the working directory -chdir names.
func localPaths(absRoot string, r tfroots.Root) (*LocalPaths, error) {
	dir, err := filepath.EvalSymlinks(filepath.Join(absRoot, filepath.FromSlash(r.Dir)))
	if err != nil {
		return nil, err
	}
	resolve := func(arg, def string) (string, error) {
		p := r.BackendArgs[arg]
		if p == "" {
			p = def
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		return canonicalPath(filepath.Clean(p))
	}
	state, err := resolve("path", defaultStatePath)
	if err != nil {
		return nil, err
	}
	wsDir, err := resolve("workspace_dir", defaultWorkspaceDir)
	if err != nil {
		return nil, err
	}
	return &LocalPaths{StatePath: state, WorkspaceDir: wsDir}, nil
}

// canonicalPath resolves the symlinks of the longest existing prefix of the
// absolute path p and keeps the rest, which need not exist yet.
func canonicalPath(p string) (string, error) {
	rest := ""
	for cur := p; ; {
		real, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(real, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		// cur exists but does not resolve: a dangling symlink, whose target cannot be canonical
		if _, lerr := os.Lstat(cur); lerr == nil {
			return "", fmt.Errorf("%s: dangling symlink", cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// parseWorkspaceList reads the stdout of `workspace list`: one workspace per
// line behind a two-character marker, "* " for the selected one, then a blank
// line. Any other line, or a list without exactly one selected workspace, is
// refused: the list is the checked scope.
func parseWorkspaceList(out []byte) ([]string, error) {
	var names []string
	selected := 0
	seen := make(map[string]bool)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		name, ok := strings.CutPrefix(line, "* ")
		if ok {
			selected++
		} else {
			name, ok = strings.CutPrefix(line, "  ")
		}
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return nil, fmt.Errorf("unexpected line %q", line)
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, errors.New("no workspace listed")
	}
	if selected != 1 {
		return nil, fmt.Errorf("%d workspaces marked selected, want 1", selected)
	}
	return names, nil
}
