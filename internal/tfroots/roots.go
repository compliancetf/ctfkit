// Package tfroots tells the deployable roots of a configuration from its
// reusable modules. The scan analyzers and ctfkit migrate share it, so both
// mean the same directory by "root".
package tfroots

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A directory of a classified archive is a deployable root or a reusable
// module, decided from the configuration alone. No file outside the archive is
// read and no module source is fetched.
//
// A directory has root evidence when one of its files declares a backend or
// cloud block in terraform{}, or a top-level provider block. A
// required_providers entry, configuration_aliases included, is not evidence:
// every module declares those. A module call is an edge from the calling
// directory to a directory of the archive, and it counts only when the caller
// has root evidence, so a wrapper or a module that calls ../ never demotes
// the directory it calls.
//
// The first rule that matches decides:
//
//  0. a directory with a file that does not parse is a root;
//  1. a backend or cloud block makes it a root;
//  2. a call from a directory with root evidence makes it a module, the scan
//     root included;
//  3. the scan root is a root;
//  4. a provider block makes it a root;
//  5. anything else is a module.
//
// Every miss errs toward reporting except three, which the rule help names:
// an uncalled deployable directory with no root evidence, a deployable
// directory another root of the same scan calls, and a module's unbounded
// constraint reaching a root that declares none.

// dirFacts is what the classifier reads from the files of one directory.
type dirFacts struct {
	unparseable bool
	backend     bool // a backend or cloud block in terraform{}
	provider    bool // a top-level provider block
	sources     []string

	backendType string            // the backend label, "cloud" for a cloud block
	backendArgs map[string]string // literal primitive arguments of the backend block, as strings
	backendErr  error             // a malformed backend block or a non-literal argument; sticky
}

func (d *dirFacts) rootEvidence() bool { return d.backend || d.provider }

var (
	topSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: "provider", LabelNames: []string{"name"}},
		{Type: "module", LabelNames: []string{"name"}},
	}}
	terraformSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{
		{Type: "backend", LabelNames: []string{"type"}},
		{Type: "cloud"},
	}}
	moduleSchema = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "source"}}}
)

// noVariables is the context every value here is evaluated in: no variables
// and no functions, so only a literal comes through. It must not be nil: the
// JSON syntax reads a string as a template only when it is given a context.
var noVariables = &hcl.EvalContext{}

// Root is a directory the rules above classify as a deployable root.
type Root struct {
	// Dir is archive-relative and slash-separated, "." for the scan root.
	Dir string
	// Backend is the backend type, "cloud" for a cloud block, empty when the
	// root declares neither (Terraform then uses the local backend).
	Backend string
	// BackendArgs holds the literal primitive arguments of the backend block
	// as strings, such as path and workspace_dir of a local backend.
	BackendArgs map[string]string
	// Unparseable marks a root by rule 0: a file of it does not parse, so
	// Backend says nothing.
	Unparseable bool
}

// Roots returns the roots of the archive in Dir order. A backend argument that
// is not a literal is an error: Terraform allows none there, and a
// caller binding state paths must not guess them.
func Roots(archive *ctfkit.ConfigArchive) ([]Root, error) {
	dirs, children := classify(archive)
	names := make([]string, 0, len(dirs))
	for dir := range dirs {
		names = append(names, dir)
	}
	sort.Strings(names) // the first error reported is the same every run
	var roots []Root
	for _, dir := range names {
		facts := dirs[dir]
		// before the module skip: a malformed backend may be why dir looks like a module
		if facts.backendErr != nil {
			return nil, fmt.Errorf("%s: %w", dir, facts.backendErr)
		}
		if children[dir] {
			continue
		}
		roots = append(roots, Root{Dir: dir, Backend: facts.backendType, BackendArgs: facts.backendArgs, Unparseable: facts.unparseable})
	}
	return roots, nil
}

// ModuleDirs returns the directories of the archive that the rules above
// classify as reusable modules, keyed the way origin's parseConfig keys a
// requirement: path.Dir of the archive-relative file path, "." for the scan
// root.
func ModuleDirs(archive *ctfkit.ConfigArchive) map[string]bool {
	_, children := classify(archive)
	return children
}

// classify reads every directory of the archive and returns its facts and the
// set of directories that are reusable modules.
func classify(archive *ctfkit.ConfigArchive) (map[string]*dirFacts, map[string]bool) {
	dirs := make(map[string]*dirFacts)
	for _, file := range archive.Files {
		dir := path.Dir(file.Path)
		facts := dirs[dir]
		if facts == nil {
			facts = &dirFacts{}
			dirs[dir] = facts
		}
		facts.read(file)
	}

	called := make(map[string]bool)
	for dir, facts := range dirs {
		if facts.unparseable || !facts.rootEvidence() {
			continue
		}
		for _, source := range facts.sources {
			target, ok := localTarget(dir, source)
			if ok && target != dir && dirs[target] != nil {
				called[target] = true
			}
		}
	}

	children := make(map[string]bool)
	for dir, facts := range dirs {
		switch {
		case facts.unparseable, facts.backend:
		case called[dir]:
			children[dir] = true
		case dir == ".", facts.provider:
		default:
			children[dir] = true
		}
	}
	return dirs, children
}

// read adds what one configuration file declares. A file that does not parse
// marks its directory and contributes nothing else.
func (d *dirFacts) read(file ctfkit.ConfigFile) {
	parsed, diags := parser.ParseConfigFile(file.Bytes, file.Path)
	if parsed == nil && !diags.HasErrors() {
		return // not a configuration file
	}
	if diags.HasErrors() || parsed == nil {
		d.unparseable = true
		return
	}
	content, _, diags := parsed.Body.PartialContent(topSchema)
	if diags.HasErrors() {
		d.unparseable = true
		return
	}
	for _, block := range content.Blocks {
		switch block.Type {
		case "provider":
			d.provider = true
		case "terraform":
			inner, _, diags := block.Body.PartialContent(terraformSchema)
			if diags.HasErrors() && d.backendErr == nil {
				d.backendErr = errors.New("a backend or cloud block is malformed")
			}
			if inner != nil && len(inner.Blocks) > 1 && d.backendErr == nil {
				d.backendErr = errors.New("a terraform block declares more than one backend or cloud block")
			}
			if inner != nil && len(inner.Blocks) > 0 {
				d.backend = true
				// shortcut: across files the one sorting last wins, *_override.tf
				// merging is not modeled; Terraform itself rejects two.
				d.readBackend(inner.Blocks[0])
			}
		case "module":
			if source := moduleSource(block.Body); source != "" {
				d.sources = append(d.sources, source)
			}
		}
	}
}

// readBackend records the type and the literal arguments of a backend
// or cloud block, primitives converted the way Terraform converts them; a
// backend block it cannot read or a non-literal argument sets backendErr,
// which a later block never clears.
func (d *dirFacts) readBackend(block *hcl.Block) {
	d.backendType = "cloud"
	if block.Type == "backend" {
		d.backendType = block.Labels[0]
		if d.backendType == "" && d.backendErr == nil {
			d.backendErr = errors.New("a backend block has an empty type")
		}
	}
	d.backendArgs = nil
	attrs, diags := block.Body.JustAttributes()
	if diags.HasErrors() {
		if d.backendType == "local" && d.backendErr == nil {
			d.backendErr = fmt.Errorf("backend %q block has more than literal arguments", d.backendType)
		}
		return // nested blocks elsewhere (cloud, remote workspaces {}): nothing migrate binds
	}
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value, diags := attrs[name].Expr.Value(noVariables)
		if diags.HasErrors() || !value.IsWhollyKnown() {
			if d.backendErr == nil {
				d.backendErr = fmt.Errorf("backend %q argument %s is not a literal", d.backendType, name)
			}
			continue
		}
		if value.IsNull() {
			continue
		}
		if !value.Type().IsPrimitiveType() {
			if d.backendType == "local" && d.backendErr == nil {
				// every local argument is a path migrate binds; never default it
				d.backendErr = fmt.Errorf("backend %q argument %s is not a string", d.backendType, name)
			}
			continue // list or map arguments of other backends: nothing to bind
		}
		str, err := convert.Convert(value, cty.String)
		if err != nil {
			continue // unreachable: every primitive converts to string
		}
		if d.backendArgs == nil {
			d.backendArgs = make(map[string]string)
		}
		d.backendArgs[name] = str.AsString()
	}
}

// moduleSource is the literal source of a module block, empty when it is
// absent or not a literal string.
func moduleSource(body hcl.Body) string {
	content, _, _ := body.PartialContent(moduleSchema)
	if content == nil {
		return ""
	}
	attr, ok := content.Attributes["source"]
	if !ok {
		return ""
	}
	value, diags := attr.Expr.Value(noVariables)
	if diags.HasErrors() || value.IsNull() || !value.IsKnown() || value.Type() != cty.String {
		return ""
	}
	return value.AsString()
}

// localTarget resolves a local module source against the directory of the
// file that calls it and returns the archive-relative directory it names.
//
// A source is local when it starts with ./ or ../ once backslashes are turned
// into slashes, the rule of Terraform and OpenTofu alike: both list exactly
// "./", "../", ".\" and "..\" as moduleSourceLocalPrefixes and normalize "\"
// to "/" before path.Clean (hashicorp/terraform
// internal/getmodules/moduleaddrs/source_parsing.go at db4eef44; opentofu/opentofu
// internal/addrs/module_source.go at a7af95c1). Every other source, a
// registry or remote //subdir included, is not local. A path that leaves the
// scan root is not followed, because nothing outside the archive is read.
func localTarget(dir, source string) (string, bool) {
	source = strings.ReplaceAll(source, `\`, "/")
	if !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") {
		return "", false
	}
	target := path.Join(dir, source)
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", false
	}
	return target, true
}
