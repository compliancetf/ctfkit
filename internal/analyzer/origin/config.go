package origin

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// defaultRegistry is the host a provider source without one resolves to.
const defaultRegistry = "registry.terraform.io"

// equivalentRegistries are hosts that serve the same default namespace. OpenTofu
// records "registry.opentofu.org" in a plan where Terraform records
// "registry.terraform.io", so an allowlist written for one must match the
// other.
var equivalentRegistries = []string{"registry.opentofu.org"}

// config is the part of a configuration archive this package reads. It is
// parsed with hcl/v2 syntax only: nothing is evaluated beyond literals.
type config struct {
	required  []requiredProvider
	providers []providerBlock
	resources []resource
	modules   []module
}

type requiredProvider struct {
	dir      string
	local    string
	source   string
	version  string
	location ctfkit.Location
}

type providerBlock struct {
	dir      string
	local    string
	location func(source string) ctfkit.Location
}

type resource struct {
	dir      string
	file     string
	region   *ctfkit.Region
	typ      string
	provider string // local provider name from the provider argument, empty when absent
	location ctfkit.Location
}

type module struct {
	source   string
	version  string
	location ctfkit.Location
}

type providerUse struct {
	source   string
	location ctfkit.Location
}

// noVariables is the context every value here is evaluated in: no variables
// and no functions, so only a literal comes through. It must not be nil: the
// JSON syntax reads a string as a template only when it is given a context,
// and with nil it would return "${var.ref}" as literal text where native
// syntax reports it as not a literal.
var noVariables = &hcl.EvalContext{}

// Schemas of the blocks and attributes this package reads, shared by the
// native and the JSON syntax.
var (
	configSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: "provider", LabelNames: []string{"name"}},
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "module", LabelNames: []string{"name"}},
	}}
	requiredProvidersSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "required_providers"}}}
	providerAttrSchema      = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "alias"}}}
	resourceAttrSchema      = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "provider"}}}
	moduleAttrSchema        = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "source"}, {Name: "version"}}}
)

// parseConfig reads every configuration file of the archive, in either
// syntax. A file that does not parse contributes the blocks that did:
// configuration validity is terraform's answer to give, never a finding here.
func parseConfig(archive *ctfkit.ConfigArchive) config {
	var c config
	for _, file := range archive.Files {
		parsed, _ := parser.ParseConfigFile(file.Bytes, file.Path)
		if parsed == nil || parsed.Body == nil {
			continue
		}
		content, _, _ := parsed.Body.PartialContent(configSchema)
		if content == nil {
			continue
		}
		dir := path.Dir(file.Path)
		for _, block := range content.Blocks {
			c.addBlock(dir, file.Path, block)
		}
	}
	return c
}

// attributes reads the attributes schema names from body, ignoring the rest.
func attributes(body hcl.Body, schema *hcl.BodySchema) hcl.Attributes {
	content, _, _ := body.PartialContent(schema)
	if content == nil {
		return nil
	}
	return content.Attributes
}

func (c *config) addBlock(dir, file string, block *hcl.Block) {
	region := parser.BlockRegion(block)
	switch block.Type {
	case "terraform":
		content, _, _ := block.Body.PartialContent(requiredProvidersSchema)
		if content == nil {
			return
		}
		for _, inner := range content.Blocks {
			c.addRequired(dir, file, inner.Body)
		}
	case "provider":
		alias := literalString(attributes(block.Body, providerAttrSchema)["alias"])
		c.providers = append(c.providers, providerBlock{
			dir:   dir,
			local: block.Labels[0],
			location: func(source string) ctfkit.Location {
				address := providerAddress(source)
				if alias != "" {
					address += "." + alias
				}
				return location(file, region, address, ctfkit.LogicalLocationProvider)
			},
		})
	case "resource":
		r := resource{
			dir:      dir,
			file:     file,
			region:   region,
			typ:      block.Labels[0],
			location: resourceLocation(file, region, block.Labels[0]+"."+block.Labels[1]),
		}
		if attr, ok := attributes(block.Body, resourceAttrSchema)["provider"]; ok {
			if traversal, diags := hcl.AbsTraversalForExpr(attr.Expr); !diags.HasErrors() {
				r.provider = traversal.RootName()
			}
		}
		c.resources = append(c.resources, r)
	case "module":
		attrs := attributes(block.Body, moduleAttrSchema)
		c.modules = append(c.modules, module{
			source:   literalString(attrs["source"]),
			version:  literalString(attrs["version"]),
			location: location(file, region, "module."+block.Labels[0], ctfkit.LogicalLocationModule),
		})
	}
}

// addRequired reads one required_providers block. An entry is either the
// object form { source, version } or the legacy bare version string.
func (c *config) addRequired(dir, file string, body hcl.Body) {
	// A block also in the body makes JustAttributes report an error, but the
	// attributes it returns are still every entry. In JSON it already drops
	// "//" comment properties.
	attrs, _ := body.JustAttributes()
	for local, attr := range attrs {
		rp := requiredProvider{dir: dir, local: local}
		value, diags := attr.Expr.Value(noVariables)
		switch {
		case diags.HasErrors():
			// configuration_aliases = [aws.peer] holds provider references,
			// which do not evaluate without a context; read the literal
			// source and version beside them instead.
			var ok bool
			if rp.source, rp.version, ok = objectLiterals(attr.Expr); !ok {
				continue
			}
		case value.IsNull() || !value.IsKnown():
			continue
		case value.Type() == cty.String:
			rp.version = value.AsString()
		case value.Type().IsObjectType():
			var sourceOK, versionOK bool
			rp.source, sourceOK = objectString(value, "source")
			rp.version, versionOK = objectString(value, "version")
			if !sourceOK || !versionOK {
				continue // version = 6 is not "no version"; it is not read at all
			}
		default:
			continue
		}
		rp.source = normalizeSource(rp.source, local)
		rp.location = location(file, parser.RangeRegion(attr.Range), providerAddress(rp.source), ctfkit.LogicalLocationProvider)
		c.required = append(c.required, rp)
	}
	sortRequired(c.required)
}

// objectLiterals reads the source and version items of an object constructor
// one by one, so an item that is not a literal, such as configuration_aliases,
// does not hide them. It fails when expr is not an object constructor or when
// source or version is present but not a literal string: a value this package
// cannot read is never guessed.
func objectLiterals(expr hcl.Expression) (source, version string, ok bool) {
	obj, isObj := expr.(*hclsyntax.ObjectConsExpr)
	if !isObj {
		return "", "", false
	}
	for _, item := range obj.Items {
		key, diags := item.KeyExpr.Value(noVariables)
		if diags.HasErrors() || key.IsNull() || !key.IsKnown() || key.Type() != cty.String {
			// A key that is not a literal could be source or version.
			return "", "", false
		}
		name := key.AsString()
		if name != "source" && name != "version" {
			continue
		}
		v, vd := item.ValueExpr.Value(noVariables)
		if vd.HasErrors() || v.IsNull() || !v.IsKnown() || v.Type() != cty.String {
			return "", "", false
		}
		if name == "source" {
			source = v.AsString()
		} else {
			version = v.AsString()
		}
	}
	return source, version, true
}

// providerUses lists every provider source the configuration names, in the
// order Provider reports the first of each: required_providers entries, then
// provider blocks, then resources whose type or provider argument implies one.
func (c config) providerUses() []providerUse {
	sources := make(map[string]string) // dir + local name -> source
	uses := make([]providerUse, 0, len(c.required)+len(c.providers)+len(c.resources))
	for _, rp := range c.required {
		sources[rp.dir+"\x00"+rp.local] = rp.source
		uses = append(uses, providerUse{source: rp.source, location: rp.location})
	}
	resolve := func(dir, local string) string {
		if s, ok := sources[dir+"\x00"+local]; ok {
			return s
		}
		return normalizeSource("", local)
	}
	for _, pb := range c.providers {
		source := resolve(pb.dir, pb.local)
		uses = append(uses, providerUse{source: source, location: pb.location(source)})
	}
	for _, r := range c.resources {
		local := r.provider
		if local == "" {
			local, _, _ = strings.Cut(r.typ, "_")
		}
		uses = append(uses, providerUse{source: resolve(r.dir, local), location: r.location})
	}
	return uses
}

// normalizeSource turns a required_providers source into its fully qualified
// form. An empty source is the legacy implied one, hashicorp/<local name>.
func normalizeSource(source, local string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		source = "hashicorp/" + strings.ToLower(local)
	}
	first, _, _ := strings.Cut(source, "/")
	if !strings.Contains(first, ".") {
		source = defaultRegistry + "/" + source
	}
	return source
}

// canonical is the comparison form of a source or allowlist entry: lower case,
// with an equivalent default registry host folded into defaultRegistry.
func canonical(source string) string {
	source = strings.ToLower(source)
	for _, host := range equivalentRegistries {
		if rest, ok := strings.CutPrefix(source, host+"/"); ok {
			return defaultRegistry + "/" + rest
		}
		if source == host {
			return defaultRegistry
		}
	}
	return source
}

// allowlist is Settings.AllowedProviders in comparison form. A nil allowlist
// means the setting is empty and every provider is allowed.
type allowlist []string

func newAllowlist(entries []string) allowlist {
	var out allowlist
	for _, e := range entries {
		e = strings.Trim(strings.TrimSpace(e), "/")
		if e == "" {
			continue
		}
		if first, _, _ := strings.Cut(e, "/"); !strings.Contains(first, ".") {
			e = defaultRegistry + "/" + e
		}
		out = append(out, canonical(e))
	}
	return out
}

// permits reports whether source equals an entry or sits under it as a host
// or namespace prefix.
func (a allowlist) permits(source string) bool {
	s := canonical(source)
	for _, e := range a {
		if s == e || strings.HasPrefix(s, e+"/") {
			return true
		}
	}
	return false
}

// gitShorthands are the source prefixes Terraform fetches with git.
var gitShorthands = []string{"git::", "git@", "github.com/", "bitbucket.org/"}

func isGitSource(source string) bool {
	for _, p := range gitShorthands {
		if strings.HasPrefix(source, p) {
			return true
		}
	}
	return false
}

// gitRef is the ref query argument of a git source, empty when absent.
func gitRef(source string) string {
	_, query, ok := strings.Cut(source, "?")
	if !ok {
		return ""
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	return values.Get("ref")
}

// commitSHA is a full SHA-1 or SHA-256 git object id.
var commitSHA = regexp.MustCompile(`^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)

func isCommitSHA(ref string) bool { return commitSHA.MatchString(ref) }

// isRegistrySource reports whether a module source is a registry address:
// [host/]namespace/name/system, optionally followed by //subdir or a query.
// Local paths, forced getters, URLs and git shorthands are not.
func isRegistrySource(source string) bool {
	if source == "" || strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") ||
		strings.HasPrefix(source, "/") || strings.Contains(source, "::") ||
		strings.Contains(source, "://") || isGitSource(source) {
		return false
	}
	address, _, _ := strings.Cut(source, "?")
	address, _, _ = strings.Cut(address, "//")
	parts := strings.Split(address, "/")
	switch len(parts) {
	case 3:
		return !strings.Contains(parts[0], ".")
	case 4:
		// A private registry host may have no dot, for example one reached
		// through split-horizon DNS, so any four-part address counts.
		return true
	default:
		return false
	}
}

func providerAddress(source string) string {
	return fmt.Sprintf("provider[%q]", source)
}

// displaySource is a module source as a message shows it, through the one
// redaction every analyzer uses (ctfkit.RedactSource): no query, since a git
// query can carry sshkey=, and no userinfo. The ref a message needs is passed
// on its own.
func displaySource(source string) string {
	return ctfkit.RedactSource(source)
}

// location is a file, the lines the block or entry spans in it, and one
// logical address.
func location(file string, region *ctfkit.Region, address, kind string) ctfkit.Location {
	loc := ctfkit.Location{LogicalLocations: []ctfkit.LogicalLocation{{
		FullyQualifiedName: address, Kind: kind,
	}}}
	if file != "" {
		loc.PhysicalLocation = &ctfkit.PhysicalLocation{ArtifactLocation: ctfkit.ArtifactLocation{URI: file}, Region: region}
	}
	return loc
}

func resourceLocation(file string, region *ctfkit.Region, address string) ctfkit.Location {
	return location(file, region, address, ctfkit.LogicalLocationResource)
}

// literalString is the value of an attribute that is a literal string, empty
// otherwise. Expressions are never evaluated.
func literalString(attr *hcl.Attribute) string {
	if attr == nil {
		return ""
	}
	value, diags := attr.Expr.Value(noVariables)
	if diags.HasErrors() || value.IsNull() || !value.IsKnown() || value.Type() != cty.String {
		return ""
	}
	return value.AsString()
}

// objectString is the string attribute key of object: empty and ok when it
// is absent or null, not ok when it holds anything but a known string.
func objectString(object cty.Value, key string) (string, bool) {
	if !object.Type().HasAttribute(key) {
		return "", true
	}
	v := object.GetAttr(key)
	switch {
	case v.IsNull():
		return "", true
	case !v.IsKnown() || v.Type() != cty.String:
		return "", false
	}
	return v.AsString(), true
}

// sortRequired orders entries by directory and local name, because
// attribute map iteration has no order.
func sortRequired(rs []requiredProvider) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].dir != rs[j].dir {
			return rs[i].dir < rs[j].dir
		}
		return rs[i].local < rs[j].local
	})
}

// Requirement is one required_providers entry of a configuration archive, as
// the ctf.origin rules read it.
type Requirement struct {
	// Dir is the archive-relative directory of the file, "." for the root.
	Dir string
	// Source is the fully qualified source, lower case; an entry with no
	// source is the implied hashicorp/<local name>.
	Source string
	// Location is the entry's file, lines and provider address.
	Location ctfkit.Location
}

// RequiredProviders lists every required_providers entry of the archive in
// directory and local name order, for the ctf.lock rules to share this
// package's reading of them.
func RequiredProviders(archive *ctfkit.ConfigArchive) []Requirement {
	required := parseConfig(archive).required
	out := make([]Requirement, 0, len(required))
	for _, rp := range required {
		out = append(out, Requirement{Dir: rp.dir, Source: rp.source, Location: rp.location})
	}
	return out
}

// ImpliedRequirements lists, once per directory and local name, the provider
// blocks and resources whose local name has no required_providers entry in
// their directory: Terraform resolves them to hashicorp/<local name>. The
// location is the first such block.
func ImpliedRequirements(archive *ctfkit.ConfigArchive) []Requirement {
	c := parseConfig(archive)
	declared := map[string]bool{}
	for _, rp := range c.required {
		declared[rp.dir+"\x00"+rp.local] = true
	}
	var out []Requirement
	add := func(dir, local string, loc ctfkit.Location) {
		key := dir + "\x00" + local
		if declared[key] {
			return
		}
		declared[key] = true
		out = append(out, Requirement{Dir: dir, Source: normalizeSource("", local), Location: loc})
	}
	for _, pb := range c.providers {
		add(pb.dir, pb.local, pb.location(normalizeSource("", pb.local)))
	}
	for _, r := range c.resources {
		local := r.provider
		if local == "" {
			local, _, _ = strings.Cut(r.typ, "_")
		}
		add(r.dir, local, r.location)
	}
	return out
}
