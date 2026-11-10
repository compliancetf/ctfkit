package rulepack_test

import (
	"strings"
	"testing"
	"testing/fstest"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const (
	defaultsYAML = "tags: {attribute: tags, effective: tags_all, provider_default: default_tags.tags}\n"
	providerV1   = "source: bobthecorp/demo\nresource_prefix: demo_\ntags: {attribute: labels}\n"
	rulesYAML    = "class: public_exposure\nrules:\n  - {types: [demo_bucket], attributes: [a, b], predicate: turned_on, level: error}\n"
)

// packFS is a pack tree with two majors of one provider.
func packFS() fstest.MapFS {
	return fstest.MapFS{
		"rules/defaults.yaml":          {Data: []byte(defaultsYAML)},
		"rules/demo/v1/provider.yaml":  {Data: []byte(providerV1)},
		"rules/demo/v1/rules.yaml":     {Data: []byte(rulesYAML)},
		"rules/demo/v1/controls.yaml":  {Data: []byte("controls: {demo_bucket: {a: [demo_bucket_a]}}\n")},
		"rules/demo/v2/provider.yaml":  {Data: []byte(providerV1)},
		"rules/demo/v2/schema.json":    {Data: []byte("{}")},
		"rules/demo/v10/provider.yaml": {Data: []byte(strings.Replace(providerV1, "labels", "tags", 1))},
	}
}

func TestSelect(t *testing.T) {
	set, err := rulepack.Parse(packFS())
	if err != nil {
		t.Fatal(err)
	}
	lock := func(source, version string) *ctfkit.Lockfile {
		return &ctfkit.Lockfile{Providers: []ctfkit.LockedProvider{{Source: source, Version: version}}}
	}
	cases := []struct {
		name, provider string
		lock           *ctfkit.Lockfile
		want           string
	}{
		{"newest without a lock file", "registry.terraform.io/bobthecorp/demo", nil, "demo/v10"},
		{"any registry host", "registry.opentofu.org/bobthecorp/demo", nil, "demo/v10"},
		{"case is not significant", "Registry.Terraform.io/BobTheCorp/Demo", nil, "demo/v10"},
		{"locked major", "registry.terraform.io/bobthecorp/demo", lock("registry.terraform.io/bobthecorp/demo", "1.4.2"), "demo/v1"},
		{"locked major with no pack", "registry.terraform.io/bobthecorp/demo", lock("registry.terraform.io/bobthecorp/demo", "3.0.0"), "demo/v10"},
		{"lock of another provider", "registry.terraform.io/bobthecorp/demo", lock("registry.terraform.io/hashicorp/random", "1.0.0"), "demo/v10"},
		{"unknown provider", "registry.terraform.io/hashicorp/random", nil, ""},
		{"empty provider", "", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			if p := set.Select(tc.provider, tc.lock); p != nil {
				got = p.Name
			}
			if got != tc.want {
				t.Errorf("Select(%q) = %q, want %q", tc.provider, got, tc.want)
			}
		})
	}

	if got := set.TagsFor("registry.terraform.io/hashicorp/random", nil); got.Attribute != "tags" || got.ProviderDefault != "default_tags.tags" {
		t.Errorf("an unknown provider gets %+v, want the defaults", got)
	}
	if got := set.TagsFor("bobthecorp/demo", lock("bobthecorp/demo", "1.0.0")); got.Attribute != "labels" {
		t.Errorf("demo v1 tags are %+v, want labels", got)
	}
	if got := set.ResourcePrefixes(); len(got) != 1 || got[0] != "demo_" {
		t.Errorf("ResourcePrefixes = %q, want [demo_]", got)
	}
}

func TestRulesExpandAndIndex(t *testing.T) {
	set, err := rulepack.Parse(packFS())
	if err != nil {
		t.Fatal(err)
	}
	p := set.Select("bobthecorp/demo", &ctfkit.Lockfile{Providers: []ctfkit.LockedProvider{{Source: "bobthecorp/demo", Version: "1.0.0"}}})
	rules := p.For("public_exposure", "demo_bucket")
	if len(rules) != 2 || rules[0].Attribute != "a" || rules[1].Attribute != "b" || rules[0].Class != "public_exposure" {
		t.Fatalf("For = %+v, want the a and b rules of public_exposure", rules)
	}
	if got := p.Controls("demo_bucket", "a"); len(got) != 1 || got[0] != "demo_bucket_a" {
		t.Errorf("Controls = %v, want [demo_bucket_a]", got)
	}
	if got := p.For("wildcard_iam", "demo_bucket"); len(got) != 0 {
		t.Errorf("another class returned %d rules", len(got))
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]struct {
		file, data, want string
	}{
		"unknown argument": {"rules/demo/v1/rules.yaml", strings.Replace(rulesYAML, "level: error", "level: error, severity: high", 1), "severity"},
		"unknown level":    {"rules/demo/v1/rules.yaml", strings.Replace(rulesYAML, "error", "fatal", 1), "level"},
		"type of another provider": {"rules/demo/v1/rules.yaml", strings.Replace(rulesYAML, "demo_bucket", "other_bucket", 1),
			"does not start with demo_"},
		"no predicate":         {"rules/demo/v1/rules.yaml", strings.Replace(rulesYAML, "predicate: turned_on, ", "", 1), "predicate"},
		"source with a host":   {"rules/demo/v1/provider.yaml", strings.Replace(providerV1, "bobthecorp/demo", "registry.terraform.io/bobthecorp/demo", 1), "namespace/type"},
		"not a major":          {"rules/demo/latest/provider.yaml", providerV1, "v<major>"},
		"two packs, one major": {"rules/demo2/v1/provider.yaml", providerV1, "both describe"},
		"empty program data source": {"rules/defaults.yaml", defaultsYAML + "program_data_sources: ['']\n",
			"program_data_sources"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fsys := packFS()
			fsys[tc.file] = &fstest.MapFile{Data: []byte(tc.data)}
			_, err := rulepack.Parse(fsys)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Parse error = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

func change(provider string, actions ...tfjson.Action) *tfjson.ResourceChange {
	return &tfjson.ResourceChange{Mode: tfjson.ManagedResourceMode, ProviderName: provider,
		Change: &tfjson.Change{Actions: actions}}
}

// The external and local_command data sources run a program at plan time,
// local_command also as an ephemeral resource and an action, and the embedded
// defaults say so; the accessors hand out copies.
func TestProgramDataSources(t *testing.T) {
	got := rulepack.Embedded().ProgramDataSources()
	if strings.Join(got, ",") != "external,local_command" {
		t.Fatalf("ProgramDataSources = %q, want [external local_command]", got)
	}
	if eph := rulepack.Embedded().ProgramEphemeralResources(); strings.Join(eph, ",") != "local_command" {
		t.Errorf("ProgramEphemeralResources = %q, want [local_command]", eph)
	}
	if act := rulepack.Embedded().ProgramActions(); strings.Join(act, ",") != "local_command" {
		t.Errorf("ProgramActions = %q, want [local_command]", act)
	}
	got[0] = "changed"
	if rulepack.Embedded().ProgramDataSources()[0] != "external" {
		t.Error("ProgramDataSources returned the set's own slice")
	}
}

// TestUnpacked records which providers a scan notes as unchecked: one with no
// pack that manages infrastructure, not one on the no_rules list and not one
// whose resources the plan does not change.
func TestUnpacked(t *testing.T) {
	plan := &tfjson.Plan{ResourceChanges: []*tfjson.ResourceChange{
		change("registry.terraform.io/hashicorp/aws", tfjson.ActionCreate),
		change("registry.terraform.io/hashicorp/azurerm", tfjson.ActionCreate),
		change("registry.terraform.io/hashicorp/azurerm", tfjson.ActionUpdate),
		change("registry.terraform.io/hashicorp/azuread", tfjson.ActionNoop),
		change("registry.terraform.io/hashicorp/random", tfjson.ActionCreate),
		change("registry.opentofu.org/hashicorp/local", tfjson.ActionDelete),
		change("terraform.io/builtin/terraform", tfjson.ActionCreate),
	}}
	got := rulepack.Embedded().Unpacked(plan)
	want := []string{"registry.terraform.io/hashicorp/azurerm"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Unpacked = %q, want %q", got, want)
	}
}

// TestFallbacks records the note for a lock file major that has no pack.
func TestFallbacks(t *testing.T) {
	set, err := rulepack.Parse(packFS())
	if err != nil {
		t.Fatal(err)
	}
	plan := &tfjson.Plan{ResourceChanges: []*tfjson.ResourceChange{
		change("registry.terraform.io/bobthecorp/demo", tfjson.ActionCreate),
		change("registry.terraform.io/bobthecorp/demo", tfjson.ActionUpdate),
	}}
	lock := func(version string) *ctfkit.Lockfile {
		return &ctfkit.Lockfile{Providers: []ctfkit.LockedProvider{{Source: "registry.terraform.io/bobthecorp/demo", Version: version}}}
	}
	cases := map[string]struct {
		lock *ctfkit.Lockfile
		want string
	}{
		"locked major has no pack": {lock("3.2.0"), "bobthecorp/demo 3.x has no rule pack; checked with demo/v10"},
		"locked major has a pack":  {lock("1.0.0"), ""},
		"no lock file":             {nil, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := strings.Join(set.Fallbacks(plan, tc.lock), "|"); got != tc.want {
				t.Errorf("Fallbacks = %q, want %q", got, tc.want)
			}
		})
	}
}

const identitiesYAML = "scope: [region]\nforms:\n  name: {pattern: '^[a-z]+$'}\n  arn: {pattern: '^arn:.+$'}\n" +
	"attributes:\n  demo_bucket: {name: [name]}\n"

// TestIdentities classifies by the attribute's declared forms first, then by
// any other form with a literal prefix; an attribute or value outside them
// misses, also a value only an undeclared prefix-less form (name) matches.
func TestIdentities(t *testing.T) {
	fsys := packFS()
	fsys["rules/demo/v1/identities.yaml"] = &fstest.MapFile{Data: []byte(identitiesYAML + "  demo_queue: {arn: [arn]}\n")}
	set, err := rulepack.Parse(fsys)
	if err != nil {
		t.Fatal(err)
	}
	c := set.Select("bobthecorp/demo", &ctfkit.Lockfile{Providers: []ctfkit.LockedProvider{{Source: "bobthecorp/demo", Version: "1.0.0"}}}).Identities
	for _, tc := range []struct{ typ, attr, value, form string }{
		{"demo_bucket", "name", "logs", "name"}, {"demo_bucket", "name", "arn:demo:logs", "arn"},
		{"demo_bucket", "name", "Logs", ""}, {"demo_bucket", "other", "logs", ""},
		{"demo_queue", "arn", "arn:demo:jobs", "arn"}, {"demo_queue", "arn", "jobs", ""},
	} {
		if form, ok := c.Classify(tc.typ, tc.attr, tc.value); form != tc.form || ok != (tc.form != "") {
			t.Errorf("Classify(%s.%s, %s) = %q %v, want %q", tc.typ, tc.attr, tc.value, form, ok, tc.form)
		}
	}
	// An alternation cannot escape the anchors: '^[a-z]+$|^arn:.+$' style
	// patterns match whole values only.
	fsys["rules/demo/v1/identities.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(identitiesYAML, "'^[a-z]+$'", "'^logs|archive$'", 1))}
	alt, err := rulepack.Parse(fsys)
	if err != nil {
		t.Fatal(err)
	}
	ac := alt.Select("bobthecorp/demo", &ctfkit.Lockfile{Providers: []ctfkit.LockedProvider{{Source: "bobthecorp/demo", Version: "1.0.0"}}}).Identities
	if form, ok := ac.Classify("demo_bucket", "name", "logs-extra"); ok {
		t.Errorf("alternation matched a fragment as %q", form)
	}
	if got := strings.Join(c.Attributes(), " "); got != "demo_bucket.name demo_queue.arn" || strings.Join(c.Scope, " ") != "region" {
		t.Errorf("attributes %q scope %v", got, c.Scope)
	}
}

// TestReferencedTypes counts the types identities.yaml names, so the schema
// snapshot keeps the identity attributes of types no rule or control names.
func TestReferencedTypes(t *testing.T) {
	fsys := packFS()
	fsys["rules/demo/v1/identities.yaml"] = &fstest.MapFile{Data: []byte(identitiesYAML + "  demo_queue: {arn: [arn]}\n")}
	set, err := rulepack.Parse(fsys)
	if err != nil {
		t.Fatal(err)
	}
	lock := &ctfkit.Lockfile{Providers: []ctfkit.LockedProvider{{Source: "bobthecorp/demo", Version: "1.0.0"}}}
	if got := strings.Join(set.Select("bobthecorp/demo", lock).ReferencedTypes(), " "); got != "demo_bucket demo_queue" {
		t.Errorf("ReferencedTypes = %q, want demo_bucket demo_queue", got)
	}
	// A pack without identities.yaml counts its rules and controls only.
	lock.Providers[0].Version = "2.0.0"
	if got := strings.Join(set.Select("bobthecorp/demo", lock).ReferencedTypes(), " "); got != "" {
		t.Errorf("v2 ReferencedTypes = %q, want none", got)
	}
}

func TestIdentitiesRejects(t *testing.T) {
	for name, tc := range map[string]struct{ data, want string }{
		"unanchored":   {strings.Replace(identitiesYAML, "'^[a-z]+$'", "'[a-z]+'", 1), "anchored"},
		"bad pattern":  {strings.Replace(identitiesYAML, "'^[a-z]+$'", "'^[a-z+$'", 1), "form name"},
		"unknown form": {strings.Replace(identitiesYAML, "[name]}", "[path]}", 1), "unknown form"},
		"other type":   {strings.Replace(identitiesYAML, "demo_bucket", "other_bucket", 1), "does not start with demo_"},
		"no forms":     {"attributes: {demo_bucket: {name: [name]}}\n", "required"},
		"unknown key":  {identitiesYAML + "fold_case: true\n", "fold_case"},
	} {
		t.Run(name, func(t *testing.T) {
			fsys := packFS()
			fsys["rules/demo/v1/identities.yaml"] = &fstest.MapFile{Data: []byte(tc.data)}
			if _, err := rulepack.Parse(fsys); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Parse error = %v, want one naming %q", err, tc.want)
			}
		})
	}
}
