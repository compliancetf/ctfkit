package tfexec

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Call is one row of the Terraform argv table (phase-3 Normative tables,
// E7). Only the constructors below build one, and Session.Run checks every
// argv against the table again before it runs, so no other subcommand or
// flag can reach terraform.
//
// Argv is held in template form: "<tf>" is the sealed terraform copy,
// "-chdir=<dir>" the configuration directory, "<owned>/" the owned run root.
type Call struct {
	row       string
	argv      []string
	init      bool     // an init row: local backend keys appended, provider sealing follows
	workspace *string  // nil: the session's workspace; "": TF_WORKSPACE unset
	extra     []string // COMPLIANCETF_* of ctfkit apply
}

func call(row string, args ...string) Call {
	return Call{row: row, argv: append([]string{"<tf>", "-chdir=<dir>"}, args...)}
}

// Version is A1.
func Version() Call { return Call{row: "A1", argv: []string{"<tf>", "version", "-json"}} }

// Init is A2; with a local backend the session appends the canonical paths.
func Init() Call {
	c := call("A2", "init", "-input=false", "-lockfile=readonly")
	c.init = true
	return c
}

// Plan is A3; terraform writes <owned>/planfile.
func Plan() Call { return call("A3", "plan", "-input=false", "-out=<owned>/planfile") }

// Show is A5, A8 and A11: show -json of a sealed copy.
func Show(s Sealed) Call { return call("A5", "show", "-json", s.template()) }

// Apply is A6 as ctfkit apply runs it today: without -lock=false, so
// terraform takes the backend lock itself.
// shortcut: A6's -lock=false comes with a ctfkit-held native lock, which is
// planned; until then terraform's own lock is the stricter interim.
func Apply(s Sealed, env ...string) Call {
	c := call("A6", "apply", "-input=false", s.template())
	c.extra = env
	return c
}

// StatePull is A7 and A12; stdout is the state.
func StatePull() Call { return call("A7", "state", "pull") }

// WorkspaceList is A9, with TF_WORKSPACE unset.
func WorkspaceList() Call { return call("A9", "workspace", "list").In("") }

// MigratePlan is A10; name is pre or post, terraform writes <owned>/<name>.tfplan.
func MigratePlan(name string) Call {
	return call("A10", "plan", "-input=false", "-detailed-exitcode", "-out=<owned>/"+name+".tfplan")
}

// ReplaceProvider is A13.
func ReplaceProvider(from, to, lockTimeout string) Call {
	return call("A13", "state", "replace-provider", "-auto-approve", "-lock=true", "-lock-timeout="+lockTimeout, from, to)
}

// ProvidersLock is A14.
func ProvidersLock(to string, platforms ...string) Call {
	args := []string{"providers", "lock"}
	for _, p := range platforms {
		args = append(args, "-platform="+p)
	}
	return call("A14", append(args, to)...)
}

// WorkspaceNew is A16, with TF_WORKSPACE unset.
func WorkspaceNew(name string) Call { return call("A16", "workspace", "new", name).In("") }

// Schema is A17.
func Schema() Call { return call("A17", "providers", "schema", "-json") }

// In runs the call with TF_WORKSPACE set to workspace ("" unsets it). A9
// and A16 always run with it unset (Session.env).
func (c Call) In(workspace string) Call {
	c.workspace = &workspace
	return c
}

// rows is the argv table. A token in angle brackets is a placeholder kind;
// "<platform>+" is one or more -platform=<os_arch> flags.
var rows = []struct{ row, tmpl string }{
	{"A1", "<tf> version -json"},
	{"A2", "<tf> -chdir=<dir> init -input=false -lockfile=readonly"},
	{"A2", "<tf> -chdir=<dir> init -input=false -lockfile=readonly -backend-config=path=<abs> -backend-config=workspace_dir=<abs>"},
	{"A3", "<tf> -chdir=<dir> plan -input=false -out=<owned>/planfile"},
	{"A4", "<tf> -chdir=<dir> plan -input=false -destroy -out=<owned>/planfile"},
	{"A5", "<tf> -chdir=<dir> show -json <sealed>"},
	{"A6", "<tf> -chdir=<dir> apply -input=false <sealed>"},
	{"A7", "<tf> -chdir=<dir> state pull"},
	{"A9", "<tf> -chdir=<dir> workspace list"},
	{"A10", "<tf> -chdir=<dir> plan -input=false -detailed-exitcode -out=<owned>/<prepost>.tfplan"},
	{"A13", "<tf> -chdir=<dir> state replace-provider -auto-approve -lock=true -lock-timeout=<duration> <provider> <provider>"},
	{"A14", "<tf> -chdir=<dir> providers lock <platform>+ <provider>"},
	{"A15", "<tf> -chdir=<dir> init -input=false -lockfile=readonly -get=false"},
	{"A15", "<tf> -chdir=<dir> init -input=false -lockfile=readonly -get=false -backend-config=path=<abs> -backend-config=workspace_dir=<abs>"},
	{"A16", "<tf> -chdir=<dir> workspace new <workspace>"},
	{"A17", "<tf> -chdir=<dir> providers schema -json"},
}

var (
	reProvider  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*/[a-z0-9_-]+/[a-z0-9_-]+$`)
	rePlatform  = regexp.MustCompile(`^-platform=[a-z0-9]+_[a-z0-9]+$`)
	reDuration  = regexp.MustCompile(`^[0-9]{1,5}(ms|s|m)$`)
	reWorkspace = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,89}$`)
	reSealed    = regexp.MustCompile(`^<owned>/sealed/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

// ErrOffTable is returned for an argv that is no row of the table.
var ErrOffTable = errors.New("not a row of the terraform argv table")

// Check returns the table row argv (template form) matches, or ErrOffTable.
func Check(argv []string) (string, error) {
	for _, r := range rows {
		if match(strings.Fields(r.tmpl), argv) {
			return r.row, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrOffTable, strings.Join(argv, " "))
}

func match(tmpl, argv []string) bool {
	i := 0
	for _, t := range tmpl {
		if t == "<platform>+" {
			n := 0
			for i < len(argv) && rePlatform.MatchString(argv[i]) {
				i, n = i+1, n+1
			}
			if n == 0 {
				return false
			}
			continue
		}
		if i >= len(argv) || !token(t, argv[i]) {
			return false
		}
		i++
	}
	return i == len(argv)
}

// token matches one argv token against one template token.
func token(t, a string) bool {
	if pre, kind, ok := strings.Cut(t, "<"); ok && strings.HasSuffix(kind, ">") && !strings.Contains(t, "<owned>/") {
		rest, ok := strings.CutPrefix(a, pre)
		if !ok {
			return false
		}
		switch kind {
		case "tf>", "dir>":
			return rest == "<"+kind
		case "abs>":
			return filepath.IsAbs(rest) && filepath.Clean(rest) == rest && !strings.Contains(rest, "<")
		case "duration>":
			return reDuration.MatchString(rest)
		case "provider>":
			return reProvider.MatchString(rest)
		case "workspace>":
			return reWorkspace.MatchString(rest)
		case "sealed>":
			return reSealed.MatchString(rest)
		}
		return false
	}
	if p, ok := strings.CutSuffix(t, "<prepost>.tfplan"); ok {
		return a == p+"pre.tfplan" || a == p+"post.tfplan"
	}
	return t == a
}

// Row is the argv table row the call was built for. Session.Run decides on
// the row Check matches, never on this label.
func (c Call) Row() string { return c.row }

// Template is the call's argv in template form.
func (c Call) Template() []string { return slices.Clone(c.argv) }
