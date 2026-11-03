// Package rulepack holds the Terraform provider knowledge analyzers read as
// data: versioned rule packs, one directory per provider major version, under
// rules/<provider>/v<major>/, embedded in the binary like the release catalog.
//
// A pack is:
//
//   - provider.yaml: the provider source it describes, the prefix its resource
//     types share, the policy dialect its rules may use, and the attributes
//     that carry its tags.
//   - controls.yaml, optional: per resource type and attribute, the catalog
//     controls about that attribute.
//   - identities.yaml, optional: the identity catalog, the forms identity
//     values take and the forms each resource attribute holds.
//   - every other *.yaml file: the rules of one sensitive-change class, each a
//     resource type list, an attribute, a predicate name with its arguments, a
//     level and an optional message template.
//   - schema.json: the trimmed provider schema the pack is validated against,
//     which cmd/rulepackgen regenerates. It is not embedded.
//
// rules/defaults.yaml holds the tag attributes used for a provider no pack
// describes. The package validates the structure of a pack; which predicate
// names and arguments exist is the business of the analyzer that runs them.
// docs/rule-packs.md is the author's guide.
package rulepack

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	tfjson "github.com/hashicorp/terraform-json"
	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Only the YAML is embedded; each pack's schema.json is for the tests and the
// generator.
//
//go:embed rules/*.yaml rules/*/*/*.yaml
var embedded embed.FS

// Root is the directory of the embedded file system that holds the packs.
const Root = "rules"

// Levels are the finding levels a rule may name.
var Levels = []string{ctfkit.LevelError, ctfkit.LevelWarning, ctfkit.LevelNote}

// Set is a loaded, immutable set of packs.
type Set struct {
	packs              []*Pack
	defaults           Tags
	noRules            []string
	programDataSources []string
}

// Pack is the rules and facts of one provider major version.
type Pack struct {
	// Name is the pack directory relative to rules/, for example "aws/v6".
	Name string
	// Major is the provider major version the pack is for.
	Major int
	// Source is the provider source without its registry host, for example
	// "hashicorp/aws". A plan's provider address matches it whatever the
	// registry host, so a mirror or the OpenTofu registry selects the pack too.
	Source string
	// ResourcePrefix is the prefix every resource type of the provider has.
	ResourcePrefix string
	// Dialect names the provider plug-in whose predicates the rules may use in
	// addition to the generic ones, empty for none.
	Dialect string
	// Tags names the attributes that carry the provider's tags.
	Tags Tags
	// Rules are every rule of the pack, in file-name then file order.
	Rules []*Rule
	// Identities is the pack's identity catalog, nil when the pack has no
	// identities.yaml.
	Identities *Identities

	controls map[string]map[string][]ctfkit.ControlID
	index    map[string]map[string][]*Rule
}

// Tags names the attributes a provider keeps tags in.
type Tags struct {
	// Attribute is the resource's own tag map, for example "tags".
	Attribute string `yaml:"attribute"`
	// Effective is the provider-computed map that merges in provider-level
	// defaults, for example "tags_all". Empty when the provider has none.
	Effective string `yaml:"effective"`
	// ProviderDefault is the path of the provider configuration's default
	// tags, dot separated through nested blocks, for example
	// "default_tags.tags". Empty when the provider has none.
	ProviderDefault string `yaml:"provider_default"`
}

// Rule is one sensitive-change rule. A rule written with attributes, or with
// kinds, is expanded at load time: Attribute is always the single attribute
// and Types always lists the types.
type Rule struct {
	// Class is the class the rule's file declares.
	Class string `yaml:"-"`
	// File is the pack-relative file that declares the rule.
	File string `yaml:"-"`
	// Types are the resource types the rule applies to.
	Types []string `yaml:"types"`
	// Kinds maps each resource type to the word a message uses for it. A rule
	// that sets kinds applies to exactly those types.
	Kinds map[string]string `yaml:"kinds"`
	// Attribute is the attribute the rule reads.
	Attribute string `yaml:"attribute"`
	// Attributes is shorthand for one rule per attribute.
	Attributes []string `yaml:"attributes"`
	// Predicate names the check, for example turned_off.
	Predicate string `yaml:"predicate"`
	// Level is the level of a finding the rule raises.
	Level string `yaml:"level"`
	// Message is the finding text template, empty for the predicate's own.
	// {address}, {attributes} and {kind} are its placeholders.
	Message string `yaml:"message"`
	// When lists attribute values the planned object must have for the rule
	// to run at all.
	When map[string]string `yaml:"when"`

	// Predicate arguments. Each predicate reads the ones docs/rule-packs.md
	// lists for it.
	Values          []string  `yaml:"values"`
	Unset           []string  `yaml:"unset"`
	OrRemoved       bool      `yaml:"or_removed"`
	AsString        bool      `yaml:"as_string"`
	Flag            string    `yaml:"flag"`
	ZeroIsUnlimited bool      `yaml:"zero_is_unlimited"`
	IPv4            string    `yaml:"ipv4"`
	IPv6            string    `yaml:"ipv6"`
	Ports           []string  `yaml:"ports"`
	NotePorts       []float64 `yaml:"note_ports"`
	Field           string    `yaml:"field"`
	ServiceLevel    string    `yaml:"service_level"`
}

// Kind is the word a message uses for resourceType, empty when the rule names
// none.
func (r *Rule) Kind(resourceType string) string { return r.Kinds[resourceType] }

// For returns the rules of one class that apply to one resource type, in pack
// order.
func (p *Pack) For(class, resourceType string) []*Rule { return p.index[class][resourceType] }

// Controls returns the catalog controls about one attribute of a resource
// type, nil when the pack names none.
func (p *Pack) Controls(resourceType, attribute string) []ctfkit.ControlID {
	return p.controls[resourceType][attribute]
}

// ControlAttributes returns every "type.attribute" key controls.yaml names,
// sorted.
func (p *Pack) ControlAttributes() []string {
	var out []string
	for t, attrs := range p.controls {
		for a := range attrs {
			out = append(out, t+"."+a)
		}
	}
	sort.Strings(out)
	return out
}

// Packs returns every pack of the set, ordered by source then major.
func (s *Set) Packs() []*Pack { return s.packs }

// Select picks the pack for a provider address as a plan records it, such as
// "registry.terraform.io/hashicorp/aws". The lock file's version picks the
// major; with no lock file entry, or no pack for the locked major, the newest
// pack of that provider is used. A provider no pack describes returns nil.
func (s *Set) Select(provider string, lock *ctfkit.Lockfile) *Pack {
	key := sourceKey(provider)
	if key == "" {
		return nil
	}
	var newest *Pack
	for _, p := range s.packs {
		if p.Source == key && (newest == nil || p.Major > newest.Major) {
			newest = p
		}
	}
	if newest == nil {
		return nil
	}
	if major, ok := lockedMajor(key, lock); ok {
		for _, p := range s.packs {
			if p.Source == key && p.Major == major {
				return p
			}
		}
	}
	return newest
}

// TagsFor returns the tag attributes of a provider: its pack's, or the
// defaults for a provider no pack describes.
func (s *Set) TagsFor(provider string, lock *ctfkit.Lockfile) Tags {
	if p := s.Select(provider, lock); p != nil {
		return p.Tags
	}
	return s.defaults
}

// ResourcePrefixes returns the resource type prefix of every pack, sorted
// and deduplicated.
func (s *Set) ResourcePrefixes() []string {
	var out []string
	for _, p := range s.packs {
		if !slices.Contains(out, p.ResourcePrefix) {
			out = append(out, p.ResourcePrefix)
		}
	}
	sort.Strings(out)
	return out
}

// ProgramDataSources returns the data source types defaults.yaml lists under
// program_data_sources: those that run a local program when they are read.
// The slice is a copy.
func (s *Set) ProgramDataSources() []string { return slices.Clone(s.programDataSources) }

// Unpacked returns the provider addresses of the managed resources a plan
// changes that no pack describes, sorted and deduplicated. A provider that
// manages no infrastructure, which defaults.yaml lists under no_rules, is
// expected to have no pack and is left out.
func (s *Set) Unpacked(plan *tfjson.Plan) []string {
	var out []string
	for _, provider := range changedProviders(plan) {
		if s.Select(provider, nil) == nil && !slices.Contains(s.noRules, sourceKey(provider)) {
			out = append(out, provider)
		}
	}
	return out
}

// Fallbacks returns one line for each provider of a plan's changed managed
// resources whose lock file major has no pack, naming the locked major and
// the pack Select uses instead, for example "hashicorp/aws 5.x has no rule
// pack; checked with aws/v6". Sorted.
func (s *Set) Fallbacks(plan *tfjson.Plan, lock *ctfkit.Lockfile) []string {
	var out []string
	for _, provider := range changedProviders(plan) {
		key := sourceKey(provider)
		major, locked := lockedMajor(key, lock)
		p := s.Select(provider, lock)
		if !locked || p == nil || p.Major == major {
			continue
		}
		line := fmt.Sprintf("%s %d.x has no rule pack; checked with %s", key, major, p.Name)
		if !slices.Contains(out, line) {
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return out
}

// changedProviders returns the provider addresses of the managed resources a
// plan creates, updates, deletes or replaces, sorted and deduplicated.
func changedProviders(plan *tfjson.Plan) []string {
	if plan == nil {
		return nil
	}
	var out []string
	for _, rc := range plan.ResourceChanges {
		if rc == nil || rc.Change == nil || rc.Mode != tfjson.ManagedResourceMode || rc.ProviderName == "" {
			continue
		}
		if a := rc.Change.Actions; !a.Create() && !a.Update() && !a.Delete() && !a.Replace() {
			continue
		}
		if !slices.Contains(out, rc.ProviderName) {
			out = append(out, rc.ProviderName)
		}
	}
	sort.Strings(out)
	return out
}

// sourceKey reduces a provider address to namespace/type, lower case. A bare
// type, as very old plans record it, is in the hashicorp namespace, which is
// Terraform's own default.
func sourceKey(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return ""
	}
	parts := strings.Split(provider, "/")
	if len(parts) == 1 {
		return "hashicorp/" + parts[0]
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

// lockedMajor is the major version the lock file pins for a source key.
func lockedMajor(key string, lock *ctfkit.Lockfile) (int, bool) {
	if lock == nil {
		return 0, false
	}
	for _, lp := range lock.Providers {
		if sourceKey(lp.Source) != key {
			continue
		}
		major, _, _ := strings.Cut(strings.TrimPrefix(lp.Version, "v"), ".")
		n, err := strconv.Atoi(major)
		return n, err == nil
	}
	return 0, false
}

// Embedded returns the packs compiled into the binary. A build whose embedded
// packs do not load is broken at the source, so it fails loudly.
func Embedded() *Set { return embeddedSet() }

var embeddedSet = sync.OnceValue(func() *Set {
	s, err := Parse(embedded)
	if err != nil {
		panic(fmt.Sprintf("the embedded rule packs do not load: %v", err))
	}
	return s
})

// FS returns the embedded file system, rooted above rules/.
func FS() fs.FS { return embedded }

// Parse loads every pack under rules/ of fsys.
func Parse(fsys fs.FS) (*Set, error) {
	s := &Set{}
	var defaults struct {
		Tags               Tags     `yaml:"tags"`
		NoRules            []string `yaml:"no_rules"`
		ProgramDataSources []string `yaml:"program_data_sources"`
	}
	if err := decode(fsys, path.Join(Root, "defaults.yaml"), &defaults); err != nil {
		return nil, err
	}
	if defaults.Tags.Attribute == "" {
		return nil, errors.New("rules/defaults.yaml: tags.attribute is required")
	}
	if slices.Contains(defaults.ProgramDataSources, "") {
		return nil, errors.New("rules/defaults.yaml: program_data_sources holds an empty type")
	}
	s.defaults = defaults.Tags
	s.programDataSources = defaults.ProgramDataSources
	for _, source := range defaults.NoRules {
		s.noRules = append(s.noRules, sourceKey(source))
	}

	providers, err := fs.ReadDir(fsys, Root)
	if err != nil {
		return nil, err
	}
	for _, provider := range providers {
		if !provider.IsDir() {
			continue
		}
		majors, err := fs.ReadDir(fsys, path.Join(Root, provider.Name()))
		if err != nil {
			return nil, err
		}
		for _, major := range majors {
			name := provider.Name() + "/" + major.Name()
			p, err := parsePack(fsys, name)
			if err != nil {
				return nil, fmt.Errorf("pack %s: %w", name, err)
			}
			s.packs = append(s.packs, p)
		}
	}

	sort.Slice(s.packs, func(i, j int) bool {
		if s.packs[i].Source != s.packs[j].Source {
			return s.packs[i].Source < s.packs[j].Source
		}
		return s.packs[i].Major < s.packs[j].Major
	})
	for i := 1; i < len(s.packs); i++ {
		if a, b := s.packs[i-1], s.packs[i]; a.Source == b.Source && a.Major == b.Major {
			return nil, fmt.Errorf("packs %s and %s both describe %s v%d", a.Name, b.Name, a.Source, a.Major)
		}
	}
	return s, nil
}

func parsePack(fsys fs.FS, name string) (*Pack, error) {
	majorDir := path.Base(name)
	major, err := strconv.Atoi(strings.TrimPrefix(majorDir, "v"))
	if !strings.HasPrefix(majorDir, "v") || err != nil || major < 0 {
		return nil, fmt.Errorf("directory %s is not v<major>", majorDir)
	}
	dir := path.Join(Root, name)

	var meta struct {
		Source         string `yaml:"source"`
		ResourcePrefix string `yaml:"resource_prefix"`
		Dialect        string `yaml:"dialect"`
		Tags           Tags   `yaml:"tags"`
	}
	if err = decode(fsys, path.Join(dir, "provider.yaml"), &meta); err != nil {
		return nil, err
	}
	if strings.Count(meta.Source, "/") != 1 || meta.Source != strings.ToLower(meta.Source) {
		return nil, fmt.Errorf("provider.yaml: source %q is not a lower-case namespace/type", meta.Source)
	}
	if meta.ResourcePrefix == "" {
		return nil, errors.New("provider.yaml: resource_prefix is required")
	}
	if meta.Tags.Attribute == "" {
		return nil, errors.New("provider.yaml: tags.attribute is required")
	}
	p := &Pack{
		Name: name, Major: major, Source: meta.Source, ResourcePrefix: meta.ResourcePrefix,
		Dialect: meta.Dialect, Tags: meta.Tags,
		controls: map[string]map[string][]ctfkit.ControlID{}, index: map[string]map[string][]*Rule{},
	}

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		file := e.Name()
		switch {
		case e.IsDir() || path.Ext(file) != ".yaml" || file == "provider.yaml":
		case file == "controls.yaml":
			err = p.parseControls(fsys, path.Join(dir, file))
		case file == IdentitiesFile:
			err = p.parseIdentities(fsys, path.Join(dir, file))
		default:
			err = p.parseRules(fsys, dir, file)
		}
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *Pack) parseControls(fsys fs.FS, file string) error {
	var doc struct {
		Controls map[string]map[string][]ctfkit.ControlID `yaml:"controls"`
	}
	if err := decode(fsys, file, &doc); err != nil {
		return err
	}
	for t, attrs := range doc.Controls {
		if !strings.HasPrefix(t, p.ResourcePrefix) {
			return fmt.Errorf("controls.yaml: %s does not start with %s", t, p.ResourcePrefix)
		}
		for a, ids := range attrs {
			if a == "" || len(ids) == 0 {
				return fmt.Errorf("controls.yaml: %s.%s names no control", t, a)
			}
		}
	}
	p.controls = doc.Controls
	return nil
}

func (p *Pack) parseRules(fsys fs.FS, dir, file string) error {
	var doc struct {
		Class string  `yaml:"class"`
		Rules []*Rule `yaml:"rules"`
	}
	if err := decode(fsys, path.Join(dir, file), &doc); err != nil {
		return err
	}
	if doc.Class == "" || len(doc.Rules) == 0 {
		return fmt.Errorf("%s: class and rules are required", file)
	}
	for i, r := range doc.Rules {
		where := fmt.Sprintf("%s: rule %d", file, i+1)
		if err := p.check(r); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		for _, one := range expand(r) {
			one.Class, one.File = doc.Class, file
			p.Rules = append(p.Rules, one)
			if p.index[doc.Class] == nil {
				p.index[doc.Class] = map[string][]*Rule{}
			}
			for _, t := range one.Types {
				p.index[doc.Class][t] = append(p.index[doc.Class][t], one)
			}
		}
	}
	return nil
}

// check holds a rule to the structure every predicate shares.
func (p *Pack) check(r *Rule) error {
	switch {
	case r.Predicate == "":
		return errors.New("predicate is required")
	case !slices.Contains(Levels, r.Level):
		return fmt.Errorf("level %q is not one of %s", r.Level, strings.Join(Levels, ", "))
	case len(r.Types) > 0 && len(r.Kinds) > 0:
		return errors.New("set types or kinds, not both")
	case len(r.Types) == 0 && len(r.Kinds) == 0:
		return errors.New("types or kinds is required")
	case r.Attribute != "" && len(r.Attributes) > 0:
		return errors.New("set attribute or attributes, not both")
	}
	for t, kind := range r.Kinds {
		if kind == "" {
			return fmt.Errorf("kind of %s is empty", t)
		}
		r.Types = append(r.Types, t)
	}
	sort.Strings(r.Types)
	for _, t := range r.Types {
		if !strings.HasPrefix(t, p.ResourcePrefix) {
			return fmt.Errorf("type %s does not start with %s", t, p.ResourcePrefix)
		}
	}
	return nil
}

// expand returns one rule per attribute of a rule written with attributes.
func expand(r *Rule) []*Rule {
	if len(r.Attributes) == 0 {
		return []*Rule{r}
	}
	out := make([]*Rule, 0, len(r.Attributes))
	for _, a := range r.Attributes {
		one := *r
		one.Attribute, one.Attributes = a, nil
		out = append(out, &one)
	}
	return out
}

// decode reads one YAML file strictly: an unknown key is an error, so a
// misspelled argument never turns a rule off quietly.
func decode(fsys fs.FS, file string, into any) error {
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err = dec.Decode(into); err != nil {
		return fmt.Errorf("%s: %w", path.Base(file), err)
	}
	return nil
}
