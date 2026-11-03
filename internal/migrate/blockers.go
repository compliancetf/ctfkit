package migrate

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
)

// Blocked is one blocked[] entry of the plan file: what keeps a dir from
// migrating until a human acts.
type Blocked struct {
	Kind   string `json:"kind"`
	Dir    string `json:"dir"`
	Detail string `json:"detail"`
}

// Blocked kinds this package reports, with BlockedNoWrapperRelease
// (ResolveWrapper). module_provenance (PM-T29), terragrunt_template (PM-T19)
// and missing_baseline (PM-T27) arrive with their tasks.
const (
	BlockedRemoteModule    = "remote_module"
	BlockedJSONConfig      = "json_config"
	BlockedFloorViolations = "floor_violations"
)

// PlanExitCode is the exit code of `migrate plan` once the plan file is
// written: 1 when anything is blocked, else 0.
func PlanExitCode(blocked []Blocked) int {
	if len(blocked) > 0 {
		return 1
	}
	return 0
}

// Blockers returns the configuration blockers of the units under root, in
// the dirs Rewrite edits: every remote module call (remote_module) and every
// .tf.json file whose required_providers binds a wrapped type to
// hashicorp/<t> (json_config). Sorted by dir, kind and detail.
//
// shortcut: a remote module blocks whether or not it requires a wrapped
// provider, since that is known only once init materialized it; upgrade when
// --vendor-modules (PM-T06) reads the module from the owned TF_DATA_DIR.
func Blockers(root string, units []Unit, providers []Provider) ([]Blocked, error) {
	if len(providers) == 0 {
		return nil, nil
	}
	dirs, err := moduleDirs(root, units)
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	from, to := upstreamNames(providers)
	var out []Blocked
	for _, d := range dirs {
		files, err := readDir(root, d.dir)
		if err != nil {
			return nil, fmt.Errorf("migrate: %s: %w", d.dir, err)
		}
		for _, f := range files {
			for _, b := range f.syntax.Blocks {
				if b.Type != "module" {
					continue
				}
				if len(b.Labels) == 0 {
					return nil, fmt.Errorf("migrate: %s: module block without a name", f.rel)
				}
				src, ok := moduleSource(b.Body.Attributes)
				if !ok || strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../") {
					continue
				}
				src = describeSource(src)
				if attr, ok := b.Body.Attributes["version"]; ok {
					if v, ok := literalString(attr.Expr); ok && versionConstraint.MatchString(v) {
						src += ", version " + v
					}
				}
				out = append(out, Blocked{Kind: BlockedRemoteModule, Dir: d.dir, Detail: fmt.Sprintf(
					"module.%s (%s) is a remote module and may require %s; Terraform will not pass a %s configuration to it",
					b.Labels[0], src, from, to)})
			}
		}
		entries, err := readJSONEntries(root, d.dir)
		if err != nil {
			return nil, fmt.Errorf("migrate: %s: %w", d.dir, err)
		}
		var blockedFiles []string
		for _, e := range entries {
			if _, ok := wrappedBy(e.name, e.source, e.hasSource, providers); (ok || e.opaque) && !slices.Contains(blockedFiles, e.file) {
				blockedFiles = append(blockedFiles, e.file)
				out = append(out, Blocked{Kind: BlockedJSONConfig, Dir: d.dir,
					Detail: fmt.Sprintf("edit %s by hand; ctfkit migrate does not rewrite JSON configuration", e.file)})
			}
		}
	}
	sortBlocked(out)
	return out, nil
}

func sortBlocked(b []Blocked) {
	slices.SortFunc(b, func(x, y Blocked) int {
		return cmp.Or(strings.Compare(x.Dir, y.Dir), strings.Compare(x.Kind, y.Kind), strings.Compare(x.Detail, y.Detail))
	})
}

// describeSource names a remote module source for blocked[] without its
// text: a source can carry credentials anywhere (userinfo, query, a
// malformed mix of both) and blocked[] is shared. A registry address
// ([host/]namespace/name/system, system lowercase as Terraform requires, a
// charset that cannot hold a secret) is kept as is; any other source is reduced to its getter and URL scheme plus a
// sha256 of the whole string, enough to tell sources apart and match them.
func describeSource(src string) string {
	if registryAddr.MatchString(src) && !vcsShortcut(src) {
		if strings.Count(src, "/") == 2 {
			src = "registry.terraform.io/" + src
		}
		return "registry: " + src
	}
	var class []string
	rest := src
	if g, r, ok := strings.Cut(rest, "::"); ok && sourceToken.MatchString(g) {
		class, rest = append(class, g), r
	}
	if s, _, ok := strings.Cut(rest, "://"); ok && sourceToken.MatchString(s) {
		class = append(class, s)
	}
	if len(class) == 0 {
		class = []string{"remote"}
	}
	return fmt.Sprintf("source: %s sha256:%x", strings.Join(class, "::"), sha256.Sum256([]byte(src)))
}

// vcsShortcut reports a github.com or bitbucket.org source: Terraform reads
// those hosts as VCS shortcuts, never as a module registry.
func vcsShortcut(src string) bool {
	host, _, _ := strings.Cut(strings.ToLower(src), "/")
	return host == "github.com" || host == "bitbucket.org"
}

var (
	registryAddr = regexp.MustCompile(`^([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+/)?[A-Za-z0-9][A-Za-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9_-]*/[a-z0-9]+$`)
	sourceToken  = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,15}$`)
	// a version constraint: digits, letters, operators; anything else is dropped
	versionConstraint = regexp.MustCompile(`^[0-9A-Za-z.,<>=~! -]+$`)
)

func moduleSource(attrs hclsyntax.Attributes) (string, bool) {
	attr, ok := attrs["source"]
	if !ok {
		return "", false
	}
	return literalString(attr.Expr)
}

// upstreamNames are the short provider addresses of the diagnostics, for
// example "hashicorp/aws" and "compliancetf/aws", joined with " or ".
func upstreamNames(providers []Provider) (from, to string) {
	var f, t []string
	for _, p := range providers {
		f = append(f, "hashicorp/"+p.Type)
		parts := strings.Split(p.To, "/")
		t = append(t, strings.Join(parts[max(0, len(parts)-2):], "/"))
	}
	return strings.Join(f, " or "), strings.Join(t, " or ")
}

// jsonEntry is one required_providers entry of a .tf.json file.
type jsonEntry struct {
	file, name, source string
	hasSource          bool
	opaque             bool // the entry does not evaluate: its source is unknown
}

// readJSONEntries returns the required_providers entries of the .tf.json
// files of dir, in file order.
//
// shortcut: module calls and resources in .tf.json are not read, so a local
// module called only from JSON is not rewritten; upgrade when an estate needs it.
func readJSONEntries(root, dir string) ([]jsonEntry, error) {
	des, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
	if err != nil {
		return nil, err
	}
	var out []jsonEntry
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".tf.json") || strings.HasPrefix(de.Name(), ".") {
			continue // Terraform ignores hidden files
		}
		rel := path.Join(dir, de.Name())
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // a .tf.json file of a dir under the scan root
		if err != nil {
			return nil, err
		}
		f, diags := hcljson.Parse(src, rel)
		if diags.HasErrors() {
			return nil, fmt.Errorf("%s does not parse: %s", rel, diags.Error())
		}
		top, _, diags := f.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "terraform"}}})
		if diags.HasErrors() {
			return nil, fmt.Errorf("%s: %s", rel, diags.Error())
		}
		for _, tb := range top.Blocks {
			tc, _, diags := tb.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "required_providers"}}})
			if diags.HasErrors() {
				return nil, fmt.Errorf("%s: %s", rel, diags.Error())
			}
			for _, rb := range tc.Blocks {
				attrs, diags := rb.Body.JustAttributes()
				if diags.HasErrors() {
					return nil, fmt.Errorf("%s: required_providers: %s", rel, diags.Error())
				}
				names := make([]string, 0, len(attrs))
				for n := range attrs {
					names = append(names, n)
				}
				slices.Sort(names)
				for _, n := range names {
					e := jsonEntry{file: rel, name: n}
					// a non-nil context makes hcljson read strings as templates, so
					// "${var.x}" fails to evaluate instead of passing as a literal
					v, diags := attrs[n].Expr.Value(&hcl.EvalContext{})
					e.opaque = diags.HasErrors()
					if !e.opaque && v.Type().IsObjectType() && v.Type().HasAttribute("source") {
						if s := v.GetAttr("source"); s.IsKnown() && !s.IsNull() && s.Type().Equals(cty.String) {
							e.source, e.hasSource = s.AsString(), true
						}
					}
					out = append(out, e)
				}
			}
		}
	}
	return out, nil
}
