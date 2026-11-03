package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// Provider is one providers[] entry of the plan file: the wrapped type, its
// FROM and TO addresses and the constraints the rewrite writes.
type Provider struct {
	Type             string `json:"type"`
	From             string `json:"from"`
	To               string `json:"to"`
	UpstreamVersion  string `json:"upstream_version"`
	WrapperVersion   string `json:"wrapper_version"`
	RootConstraint   string `json:"root_constraint"`
	ModuleConstraint string `json:"module_constraint"`
}

// Edit is one edits[] entry of the plan file. Content is the file after the
// edit; apply writes it once the file still hashes to SHA256Before.
type Edit struct {
	File         string  `json:"file"`
	SHA256Before *string `json:"sha256_before"`
	SHA256After  string  `json:"sha256_after"`
	Reason       string  `json:"reason"`
	Content      []byte  `json:"-"`
}

// upstreamHosts are the registry hosts of a hashicorp/<t> source address:
// Terraform's default and OpenTofu's (B7).
var upstreamHosts = []string{"registry.terraform.io", "registry.opentofu.org"}

// versionsFile is where an implied provider gets its required_providers entry.
const versionsFile = "versions.tf"

// Rewrite computes the config edits for the units under root: every
// required_providers entry naming hashicorp/<t> of a wrapped type, in the
// units' dirs and in the local modules (./, ../ sources) they reach, gets the
// wrapper source and keeps its version constraint (version parity: wrapper
// X.Y.Z proxies upstream X.Y.Z); an entry without one gets the root or module
// constraint, and an implied provider gets an entry in versions.tf. Nothing is written; edits are sorted by file.
// Remote modules and .tf.json files are left alone; Blockers lists them.
func Rewrite(root string, units []Unit, providers []Provider) ([]Edit, error) {
	dirs, err := moduleDirs(root, units)
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	var edits []Edit
	for _, d := range dirs {
		e, err := rewriteDir(root, d, providers)
		if err != nil {
			return nil, fmt.Errorf("migrate: %s: %w", d.dir, err)
		}
		edits = append(edits, e...)
	}
	slices.SortFunc(edits, func(a, b Edit) int { return strings.Compare(a.File, b.File) })
	return edits, nil
}

// modDir is a directory of configuration the rewrite touches: a unit dir
// (root constraint) or a local module dir (module constraint).
type modDir struct {
	dir  string // slash-separated, relative to root
	root bool
}

// moduleDirs returns the unit dirs, then every local module dir they reach,
// each once; a dir that is both is a root.
func moduleDirs(root string, units []Unit) ([]modDir, error) {
	seen := map[string]bool{}
	var out []modDir
	for _, u := range units {
		if !seen[u.Dir] {
			seen[u.Dir] = true
			out = append(out, modDir{dir: u.Dir, root: true})
		}
	}
	for i := 0; i < len(out); i++ {
		calls, err := localModuleCalls(root, out[i].dir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", out[i].dir, err)
		}
		for _, c := range calls {
			if !seen[c] {
				seen[c] = true
				out = append(out, modDir{dir: c})
			}
		}
	}
	return out, nil
}

// localModuleCalls returns the dirs, relative to root, of the module calls in
// dir whose source is a local path.
func localModuleCalls(root, dir string) ([]string, error) {
	files, err := readDir(root, dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range files {
		for _, b := range f.syntax.Blocks {
			if b.Type != "module" {
				continue
			}
			attr, ok := b.Body.Attributes["source"]
			if !ok {
				continue
			}
			src, ok := literalString(attr.Expr)
			if !ok || !strings.HasPrefix(src, "./") && !strings.HasPrefix(src, "../") {
				continue
			}
			name := strings.Join(b.Labels, ".")
			target := path.Clean(path.Join(dir, src))
			if target == ".." || strings.HasPrefix(target, "../") {
				return nil, fmt.Errorf("module.%s: local source %s is outside the scan root", name, src)
			}
			if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(target))); err != nil || !st.IsDir() {
				return nil, fmt.Errorf("module.%s: local source %s is not a directory", name, src)
			}
			out = append(out, target)
		}
	}
	return out, nil
}

// tfFile is one .tf file of a dir, parsed twice: hclsyntax to read, hclwrite
// to edit with the original bytes kept.
type tfFile struct {
	rel    string // slash-separated, relative to root
	src    []byte
	syntax *hclsyntax.Body
	write  *hclwrite.File
}

// readDir parses the .tf files of dir in name order. .tf.json is not read.
func readDir(root, dir string) ([]*tfFile, error) {
	if err := underRoot(root, dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
	if err != nil {
		return nil, err
	}
	var out []*tfFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tf") || strings.HasPrefix(e.Name(), ".") {
			continue // Terraform ignores hidden files
		}
		if !e.Type().IsRegular() {
			// apply would write through a symlink, possibly outside the scan root
			return nil, fmt.Errorf("%s is not a regular file", path.Join(dir, e.Name()))
		}
		rel := path.Join(dir, e.Name())
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // a .tf file of a dir under the scan root
		if err != nil {
			return nil, err
		}
		f, err := parseFile(rel, src)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// underRoot refuses a dir reached through a symlink below root: its edits
// could be written outside the scan root, or twice to one file under two names.
func underRoot(root, dir string) error {
	realRoot, err := realAbs(root)
	if err != nil {
		return err
	}
	real, err := realAbs(filepath.Join(root, filepath.FromSlash(dir)))
	if err != nil {
		return err
	}
	if real != filepath.Join(realRoot, filepath.FromSlash(dir)) {
		return fmt.Errorf("%s is reached through a symlink; migrate does not follow symlinks", dir)
	}
	return nil
}

func realAbs(p string) (string, error) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	return filepath.Abs(r)
}

func parseFile(rel string, src []byte) (*tfFile, error) {
	sf, diags := hclsyntax.ParseConfig(src, rel, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s does not parse: %s", rel, diags.Error())
	}
	wf, diags := hclwrite.ParseConfig(src, rel, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s does not parse: %s", rel, diags.Error())
	}
	body, ok := sf.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("%s: not native HCL syntax", rel)
	}
	return &tfFile{rel: rel, src: src, syntax: body, write: wf}, nil
}

// rewriteDir returns the edits of one module dir.
func rewriteDir(root string, d modDir, providers []Provider) ([]Edit, error) {
	files, err := readDir(root, d.dir)
	if err != nil {
		return nil, err
	}
	kind := "module"
	if d.root {
		kind = "root"
	}
	reasons := map[*tfFile][]string{}
	declared := map[string]bool{}
	var reqFile *tfFile // first non-override file with a required_providers block
	for _, f := range files {
		for _, tb := range f.write.Body().Blocks() {
			if tb.Type() != "terraform" {
				continue
			}
			for _, rb := range tb.Body().Blocks() {
				if rb.Type() != "required_providers" {
					continue
				}
				if reqFile == nil && !isOverride(f.rel) {
					reqFile = f
				}
				attrs := rb.Body().Attributes()
				for _, name := range slices.Sorted(maps.Keys(attrs)) {
					attr := attrs[name]
					declared[name] = true
					p, ok := wrappedEntry(name, attr, providers)
					if !ok {
						continue
					}
					version, added, rerr := rewriteEntry(rb.Body(), name, attr, p.To, constraint(p, d.root))
					if rerr != nil {
						return nil, fmt.Errorf("%s: required_providers %s: %w", f.rel, name, rerr)
					}
					reasons[f] = append(reasons[f], fmt.Sprintf("required_providers %s source rewritten to %s, %s (%s)", name, p.To, versionReason(version, added), kind))
				}
			}
		}
	}

	// a name a .tf.json file declares is not implied: a second entry would not load
	jsonEntries, err := readJSONEntries(root, d.dir)
	if err != nil {
		return nil, err
	}
	for _, e := range jsonEntries {
		declared[e.name] = true
	}
	var implied []Provider
	used := usedProviderNames(files)
	for _, p := range providers {
		if used[p.Type] && !declared[p.Type] {
			implied = append(implied, p)
		}
	}
	var created *tfFile
	if len(implied) > 0 {
		// A module may have only one required_providers configuration
		// (Terraform: "Duplicate required providers configuration").
		vf := reqFile
		if vf == nil {
			vf = findFile(files, path.Join(d.dir, versionsFile))
		}
		if vf == nil {
			if vf, err = parseFile(path.Join(d.dir, versionsFile), []byte{}); err != nil {
				return nil, err
			}
			created = vf
		}
		var entries strings.Builder
		for _, p := range implied {
			fmt.Fprintf(&entries, "%s = {\nsource = %q\nversion = %q\n}\n", p.Type, p.To, constraint(p, d.root))
			reasons[vf] = append(reasons[vf], fmt.Sprintf("implied provider %s: required_providers entry added for %s, version %s (%s)", p.Type, p.To, constraint(p, d.root), kind))
		}
		// one call: appended tokens are not blocks addEntry could find again
		if err := addEntry(vf.write, entries.String()); err != nil {
			return nil, fmt.Errorf("%s: %w", vf.rel, err)
		}
		if created != nil {
			files = append(files, created)
		}
	}

	var edits []Edit
	for _, f := range files {
		rs, ok := reasons[f]
		if !ok {
			continue
		}
		out := f.write.Bytes()
		if f == created {
			out = hclwrite.Format(out)
		}
		if _, diags := hclsyntax.ParseConfig(out, f.rel, hcl.InitialPos); diags.HasErrors() {
			return nil, fmt.Errorf("internal: rewritten %s does not parse: %s", f.rel, diags.Error())
		}
		e := Edit{File: f.rel, SHA256After: hashHex(out), Reason: strings.Join(rs, "; "), Content: out}
		if f != created {
			before := hashHex(f.src)
			e.SHA256Before = &before
		}
		edits = append(edits, e)
	}
	return edits, nil
}

func constraint(p Provider, root bool) string {
	if root {
		return p.RootConstraint
	}
	return p.ModuleConstraint
}

// isOverride reports a Terraform override file, merged into the module rather
// than holding its own required_providers configuration.
func isOverride(rel string) bool {
	name := path.Base(rel)
	return name == "override.tf" || strings.HasSuffix(name, "_override.tf")
}

func findFile(files []*tfFile, rel string) *tfFile {
	for _, f := range files {
		if f.rel == rel {
			return f
		}
	}
	return nil
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// wrappedEntry reports the provider a required_providers entry binds to
// hashicorp/<t> of a wrapped type: an explicit source on any upstream host, or
// none (legacy string or object without source), which implies hashicorp/<name>.
func wrappedEntry(name string, attr *hclwrite.Attribute, providers []Provider) (Provider, bool) {
	src, hasSource := entrySource(attr)
	return wrappedBy(name, src, hasSource, providers)
}

// wrappedBy is wrappedEntry over the entry's local name and literal source.
func wrappedBy(name, src string, hasSource bool, providers []Provider) (Provider, bool) {
	for _, p := range providers {
		if hasSource && isUpstream(src, p.Type) || !hasSource && strings.EqualFold(name, p.Type) {
			return p, true
		}
	}
	return Provider{}, false
}

// entrySource returns the literal source of a required_providers entry.
func entrySource(attr *hclwrite.Attribute) (string, bool) {
	expr, diags := hclsyntax.ParseExpression(attr.Expr().BuildTokens(nil).Bytes(), "", hcl.InitialPos)
	if diags.HasErrors() {
		return "", false
	}
	obj, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return "", false
	}
	for _, item := range obj.Items {
		if k, ok := objectKey(item.KeyExpr); ok && k == "source" {
			return literalString(item.ValueExpr)
		}
	}
	return "", false
}

func objectKey(e hclsyntax.Expression) (string, bool) {
	if k, ok := e.(*hclsyntax.ObjectConsKeyExpr); ok {
		if name := hcl.ExprAsKeyword(k.Wrapped); name != "" {
			return name, true
		}
		return literalString(k.Wrapped)
	}
	return "", false
}

func literalString(e hcl.Expression) (string, bool) {
	v, diags := e.Value(nil)
	if diags.HasErrors() || !v.IsKnown() || v.IsNull() || !v.Type().Equals(cty.String) {
		return "", false
	}
	return v.AsString(), true
}

// isUpstream reports whether src is hashicorp/<typ> with no host or an
// upstream host. Provider addresses compare case-insensitively.
func isUpstream(src, typ string) bool {
	parts := strings.Split(strings.ToLower(src), "/")
	if len(parts) == 3 {
		if !slices.Contains(upstreamHosts, parts[0]) {
			return false
		}
		parts = parts[1:]
	}
	return len(parts) == 2 && parts[0] == "hashicorp" && parts[1] == strings.ToLower(typ)
}

// usedProviderNames returns the provider local names the dir's resources,
// data sources, provider blocks and module providers maps refer to.
func usedProviderNames(files []*tfFile) map[string]bool {
	used := map[string]bool{}
	for _, f := range files {
		for _, b := range f.syntax.Blocks {
			switch b.Type {
			case "resource", "data", "ephemeral":
				if attr, ok := b.Body.Attributes["provider"]; ok {
					if tr, diags := hcl.AbsTraversalForExpr(attr.Expr); !diags.HasErrors() {
						used[tr.RootName()] = true
					}
				} else if len(b.Labels) > 0 {
					name, _, _ := strings.Cut(b.Labels[0], "_")
					used[name] = true
				}
			case "provider":
				if len(b.Labels) > 0 {
					used[b.Labels[0]] = true
				}
			case "module":
				attr, ok := b.Body.Attributes["providers"]
				if !ok {
					continue
				}
				if obj, ok := attr.Expr.(*hclsyntax.ObjectConsExpr); ok {
					for _, item := range obj.Items {
						if tr, diags := hcl.AbsTraversalForExpr(item.ValueExpr); !diags.HasErrors() {
							used[tr.RootName()] = true
						}
					}
				}
			}
		}
	}
	return used
}

// rewriteEntry sets the source of one required_providers entry and keeps
// everything else in it (version, configuration_aliases, comments). An entry
// without a version gets defVersion. A legacy string entry, which is the
// version constraint, becomes the object form with that constraint. It
// returns the entry's version constraint and whether it was added.
func rewriteEntry(body *hclwrite.Body, name string, attr *hclwrite.Attribute, source, defVersion string) (version string, added bool, err error) {
	toks := attr.Expr().BuildTokens(nil)
	var obj hclwrite.Tokens
	if len(toks) > 0 && toks[0].Type == hclsyntax.TokenOBrace {
		_, _, hasVersion := findObjectKey(toks, "version")
		obj = setObjectKeys(toks, source, defVersion)
		if version, err = checkObjectKeys(obj, source, defVersion, !hasVersion); err != nil {
			return "", false, err
		}
		added = !hasVersion
	} else {
		expr, diags := hclsyntax.ParseExpression(toks.Bytes(), "", hcl.InitialPos)
		var ok bool
		if !diags.HasErrors() {
			version, ok = literalString(expr)
		}
		if !ok {
			return "", false, errors.New("legacy entry is not a literal version constraint")
		}
		obj = hclwrite.Tokens{
			tok(hclsyntax.TokenOBrace, "{"), tok(hclsyntax.TokenNewline, "\n"),
		}
		obj = append(obj, keyLine("source", source)...)
		obj = append(obj, keyLine("version", version)...)
		obj = append(obj, tok(hclsyntax.TokenCBrace, "}"))
	}
	expr, err := formatExpr(obj.Bytes(), attrIndent(attr))
	if err != nil {
		return "", false, err
	}
	body.SetAttributeRaw(name, expr)
	return version, added, nil
}

// versionReason describes the version constraint of a rewritten entry for
// edits[]. The plan file is shared: constraint text taken from the
// configuration is quoted only when it is constraint-shaped.
func versionReason(version string, added bool) string {
	if added {
		return "version " + version + " added"
	}
	if versionConstraint.MatchString(version) {
		return "version " + version + " kept"
	}
	return "version kept"
}

// setObjectKeys replaces the value of the top-level source key of an object
// constructor's tokens and inserts source, or version with defVersion, when
// absent. An existing version is kept as written.
func setObjectKeys(toks hclwrite.Tokens, source, defVersion string) hclwrite.Tokens {
	out := slices.Clone(toks)
	srcEnd := -1
	for _, kv := range []struct{ key, val string }{{"source", source}, {"version", defVersion}} {
		start, end, found := findObjectKey(out, kv.key)
		switch {
		case found && kv.key == "version":
		case found:
			out = slices.Replace(out, start, end, quoted(kv.val, out[start].SpacesBefore)...)
			_, srcEnd, _ = findObjectKey(out, "source")
		case kv.key == "source":
			// insert as the first item
			out = slices.Insert(out, 1, insertItem(out, 1, kv.key, kv.val)...)
			_, srcEnd, _ = findObjectKey(out, "source")
		default:
			out = slices.Insert(out, srcEnd, insertItem(out, srcEnd, kv.key, kv.val)...)
		}
	}
	return out
}

// checkObjectKeys refuses a rewritten object that does not hold exactly one
// source key with the new value and one literal version key (with defVersion
// when it was inserted): a key spelling the token scan did not find
// ("sour\u0063e", a comment before =) would leave the old key next to an
// inserted one. It returns the version constraint.
func checkObjectKeys(obj hclwrite.Tokens, source, defVersion string, inserted bool) (string, error) {
	expr, diags := hclsyntax.ParseExpression(obj.Bytes(), "", hcl.InitialPos)
	if diags.HasErrors() {
		return "", errors.New(diags.Error())
	}
	cons, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return "", errors.New("not an object")
	}
	seen := map[string]int{}
	var version string
	for _, item := range cons.Items {
		k, ok := objectKey(item.KeyExpr)
		if !ok || k != "source" && k != "version" {
			continue
		}
		seen[k]++
		v, ok := literalString(item.ValueExpr)
		if !ok || k == "source" && v != source || k == "version" && inserted && v != defVersion {
			return "", fmt.Errorf("unsupported %s key form; write it as %s = \"...\"", k, k)
		}
		if k == "version" {
			version = v
		}
	}
	for _, k := range []string{"source", "version"} {
		if seen[k] != 1 {
			return "", fmt.Errorf("unsupported %s key form; write it as %s = \"...\"", k, k)
		}
	}
	return version, nil
}

// insertItem returns the tokens of `key = "val"` to insert before toks[at]:
// on its own line when toks[at] starts or ends a line, else comma-separated.
func insertItem(toks hclwrite.Tokens, at int, key, val string) hclwrite.Tokens {
	item := append(hclwrite.Tokens{tok(hclsyntax.TokenIdent, key), tok(hclsyntax.TokenEqual, "=")}, quoted(val, 1)...)
	if toks[at].Type == hclsyntax.TokenNewline {
		return append(hclwrite.Tokens{tok(hclsyntax.TokenNewline, "\n")}, item...)
	}
	if t := toks[at-1].Type; t == hclsyntax.TokenNewline || t == hclsyntax.TokenComment {
		return append(item, tok(hclsyntax.TokenNewline, "\n"))
	}
	if toks[at-1].Type == hclsyntax.TokenOBrace {
		return append(item, tok(hclsyntax.TokenComma, ","))
	}
	return append(hclwrite.Tokens{tok(hclsyntax.TokenComma, ",")}, item...)
}

// findObjectKey returns the token range [start, end) of the value of a
// top-level key of an object constructor.
func findObjectKey(toks hclwrite.Tokens, key string) (start, end int, found bool) {
	depth := 0
	for i := 0; i < len(toks); i++ {
		switch toks[i].Type {
		case hclsyntax.TokenOBrace, hclsyntax.TokenOBrack, hclsyntax.TokenOParen, hclsyntax.TokenTemplateInterp, hclsyntax.TokenTemplateControl:
			depth++
			continue
		case hclsyntax.TokenCBrace, hclsyntax.TokenCBrack, hclsyntax.TokenCParen, hclsyntax.TokenTemplateSeqEnd:
			depth--
			continue
		}
		if depth != 1 {
			continue
		}
		// the key is an identifier or a quoted string ("source" = ...)
		last := i
		switch {
		case toks[i].Type == hclsyntax.TokenIdent && string(toks[i].Bytes) == key:
		case toks[i].Type == hclsyntax.TokenOQuote && i+2 < len(toks) && toks[i+1].Type == hclsyntax.TokenQuotedLit &&
			string(toks[i+1].Bytes) == key && toks[i+2].Type == hclsyntax.TokenCQuote:
			last = i + 2
		default:
			continue
		}
		if last+1 >= len(toks) {
			continue
		}
		if prev := toks[i-1].Type; prev != hclsyntax.TokenOBrace && prev != hclsyntax.TokenNewline && prev != hclsyntax.TokenComma && prev != hclsyntax.TokenComment {
			continue
		}
		if next := toks[last+1].Type; next != hclsyntax.TokenEqual && next != hclsyntax.TokenColon {
			continue
		}
		start = last + 2
		for start < len(toks) && toks[start].Type == hclsyntax.TokenComment && !strings.HasSuffix(string(toks[start].Bytes), "\n") {
			start++ // an inline /* */ comment before the value stays
		}
		d := 0
		for end = start; end < len(toks); end++ {
			t := toks[end].Type
			if d == 0 && (t == hclsyntax.TokenNewline || t == hclsyntax.TokenComma || t == hclsyntax.TokenCBrace || t == hclsyntax.TokenComment) {
				break
			}
			switch t {
			case hclsyntax.TokenOBrace, hclsyntax.TokenOBrack, hclsyntax.TokenOParen, hclsyntax.TokenTemplateInterp, hclsyntax.TokenTemplateControl:
				d++
			case hclsyntax.TokenCBrace, hclsyntax.TokenCBrack, hclsyntax.TokenCParen, hclsyntax.TokenTemplateSeqEnd:
				d--
			}
		}
		return start, end, true
	}
	return 0, 0, false
}

func tok(t hclsyntax.TokenType, s string) *hclwrite.Token {
	return &hclwrite.Token{Type: t, Bytes: []byte(s)}
}

func quoted(s string, spaces int) hclwrite.Tokens {
	lit := strconv.Quote(s)
	return hclwrite.Tokens{
		{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`), SpacesBefore: spaces},
		tok(hclsyntax.TokenQuotedLit, lit[1:len(lit)-1]),
		tok(hclsyntax.TokenCQuote, `"`),
	}
}

func keyLine(key, val string) hclwrite.Tokens {
	line := append(hclwrite.Tokens{tok(hclsyntax.TokenIdent, key), tok(hclsyntax.TokenEqual, "=")}, quoted(val, 1)...)
	return append(line, tok(hclsyntax.TokenNewline, "\n"))
}

// attrIndent is the indentation of the line an attribute starts on.
func attrIndent(attr *hclwrite.Attribute) string {
	toks := attr.BuildTokens(nil)
	if len(toks) == 0 {
		return ""
	}
	return strings.Repeat(" ", toks[0].SpacesBefore)
}

// formatExpr formats an expression the way terraform fmt does at the given
// line indentation and returns its tokens.
func formatExpr(src []byte, indent string) (hclwrite.Tokens, error) {
	lines := strings.Split(string(hclwrite.Format(src)), "\n")
	for i := 1; i < len(lines); i++ {
		if lines[i] != "" {
			lines[i] = indent + lines[i]
		}
	}
	f, diags := hclwrite.ParseConfig([]byte("x = "+strings.Join(lines, "\n")+"\n"), "", hcl.InitialPos)
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	return f.Body().GetAttribute("x").Expr().BuildTokens(nil), nil
}

// addEntry adds the entries (`<name> = { source, version }` lines) to the
// file's required_providers, adding the required_providers block or the
// terraform block when absent.
func addEntry(f *hclwrite.File, entry string) error {
	var tb *hclwrite.Block
	for _, b := range f.Body().Blocks() {
		if b.Type() != "terraform" {
			continue
		}
		if tb == nil {
			tb = b
		}
		if rb := b.Body().FirstMatchingBlock("required_providers", nil); rb != nil {
			multiline(rb.Body())
			return appendFragment(rb.Body(), entry, blockIndent(rb)+"  ")
		}
	}
	if tb != nil {
		multiline(tb.Body())
		return appendFragment(tb.Body(), "required_providers {\n"+entry+"}\n", blockIndent(tb)+"  ")
	}
	text := "terraform {\nrequired_providers {\n" + entry + "}\n}\n"
	if src := f.Bytes(); len(src) > 0 {
		text = "\n" + text
		if src[len(src)-1] != '\n' {
			text = "\n" + text
		}
	}
	return appendFragment(f.Body(), text, "")
}

// multiline turns a single-line block body (`terraform {}`,
// `terraform { required_version = "x" }`) into one that starts and ends with
// a newline, so a nested block can be appended to it.
func multiline(body *hclwrite.Body) {
	toks := body.BuildTokens(nil)
	if len(toks) > 0 && toks[0].Type != hclsyntax.TokenNewline {
		body.Clear()
		body.AppendUnstructuredTokens(append(hclwrite.Tokens{tok(hclsyntax.TokenNewline, "\n")}, toks...))
	}
	if n := len(toks); n == 0 || toks[n-1].Type != hclsyntax.TokenNewline {
		body.AppendNewline()
	}
}

func blockIndent(b *hclwrite.Block) string {
	toks := b.BuildTokens(nil)
	if len(toks) == 0 {
		return ""
	}
	return strings.Repeat(" ", toks[0].SpacesBefore)
}

// appendFragment formats a body fragment, indents it and appends it to body.
func appendFragment(body *hclwrite.Body, text, indent string) error {
	lines := strings.Split(string(hclwrite.Format([]byte(text))), "\n")
	for i := range lines {
		if lines[i] != "" {
			lines[i] = indent + lines[i]
		}
	}
	f, diags := hclwrite.ParseConfig([]byte(strings.Join(lines, "\n")), "", hcl.InitialPos)
	if diags.HasErrors() {
		return errors.New(diags.Error())
	}
	toks := f.BuildTokens(nil)
	if n := len(toks); n > 0 && toks[n-1].Type == hclsyntax.TokenEOF {
		toks = toks[:n-1]
	}
	body.AppendUnstructuredTokens(toks)
	return nil
}
