package sensitivechange

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/compliancetf/ctfkit/internal/rulepack"
)

// packRoot is the directory above rules/, on disk, where the snapshots are.
const packRoot = "../../rulepack"

// TestSchemaSnapshots holds every embedded pack to its provider's schema
// snapshot: each resource type and attribute a rule or controls.yaml names
// must exist, with a kind the rule's predicate can read. The weekly
// rule-pack-schemas workflow runs it after regenerating the snapshots, so a
// provider rename fails here, naming the rule, instead of a rule going quiet.
func TestSchemaSnapshots(t *testing.T) {
	for _, p := range rulepack.Embedded().Packs() {
		t.Run(p.Name, func(t *testing.T) {
			snap, err := rulepack.ReadSnapshot(os.DirFS(packRoot), p.Name)
			if err != nil {
				t.Fatalf("every pack needs a schema snapshot; run scripts/refresh-rule-pack-schemas.sh: %v", err)
			}
			for _, problem := range schemaProblems(p, snap) {
				t.Error(problem)
			}
		})
	}
}

// TestSchemaProblemsNameTheRule records that a missing type, a missing
// attribute and an attribute of the wrong kind each fail, naming the rule.
func TestSchemaProblemsNameTheRule(t *testing.T) {
	snap := &rulepack.Snapshot{Provider: "registry.terraform.io/bobthecorp/demo", Version: "1.0.0",
		Resources: map[string]map[string]any{
			"demo_db":  {"public": "bool", "retention": "string", "rule": map[string]any{"enabled": "bool"}},
			"demo_log": {"enabled": "bool"},
		}}
	cases := map[string]struct {
		rule, want string
	}{
		"renamed type":          {`{types: [demo_database], attribute: public, predicate: turned_on, level: error}`, "demo_database is not in"},
		"renamed attribute":     {`{types: [demo_db], attribute: publicly_accessible, predicate: turned_on, level: error}`, "demo_db.publicly_accessible is not in"},
		"wrong kind":            {`{types: [demo_db], attribute: retention, predicate: shortened, level: error}`, "is string, shortened reads number"},
		"missing block flag":    {`{types: [demo_db], attribute: rule, predicate: block_removed, flag: on, level: error}`, "demo_db.rule.on is not in"},
		"missing unset":         {`{types: [demo_db], attribute: retention, predicate: value_in, values: [x], unset: [arn], message: m, level: error}`, "demo_db.arn is not in"},
		"type of a second rule": {`{types: [demo_log, demo_gone], attribute: enabled, predicate: turned_off, level: error}`, "demo_gone is not in"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			set, err := rulepack.Parse(fstest.MapFS{
				"rules/defaults.yaml":         {Data: []byte("tags: {attribute: tags}\n")},
				"rules/demo/v1/provider.yaml": {Data: []byte("source: bobthecorp/demo\nresource_prefix: demo_\ntags: {attribute: tags}\n")},
				"rules/demo/v1/rules.yaml":    {Data: []byte("class: public_exposure\nrules:\n  - " + tc.rule + "\n")},
			})
			if err != nil {
				t.Fatal(err)
			}
			problems := schemaProblems(set.Packs()[0], snap)
			if len(problems) != 1 || !strings.Contains(problems[0], tc.want) || !strings.Contains(problems[0], "rules.yaml") {
				t.Errorf("problems = %q, want one naming rules.yaml and %q", problems, tc.want)
			}
		})
	}
}

// reads is the attribute kinds each predicate can read.
var reads = map[string][]string{
	"turned_off":             {rulepack.KindBool},
	"turned_on":              {rulepack.KindBool},
	"removed":                {rulepack.KindString, rulepack.KindList, rulepack.KindMap},
	"block_removed":          {rulepack.KindObject},
	"narrowed":               {rulepack.KindList},
	"shortened":              {rulepack.KindNumber},
	"value_in":               {rulepack.KindString},
	"open_cidr":              {rulepack.KindObject},
	"policy_any_principal":   {rulepack.KindString},
	"policy_wildcard_action": {rulepack.KindString, rulepack.KindObject},
}

// schemaProblems lists every reference of a pack that its snapshot does not
// hold with a kind the reading predicate accepts.
func schemaProblems(p *rulepack.Pack, snap *rulepack.Snapshot) []string {
	var out []string
	source := snap.Provider + " " + snap.Version
	for _, r := range p.Rules {
		for _, typ := range r.Types {
			problem := func(format string, args ...any) {
				out = append(out, fmt.Sprintf("%s/%s: %s rule on %s: %s", p.Name, r.File, r.Predicate, typ, fmt.Sprintf(format, args...)))
			}
			if _, ok := snap.Resources[typ]; !ok {
				problem("resource type %s is not in %s", typ, source)
				continue
			}
			need := func(attr string, kinds ...string) {
				kind, ok := snap.Kind(typ, attr)
				switch {
				case !ok:
					problem("%s.%s is not in %s", typ, attr, source)
				case len(kinds) > 0 && !slices.Contains(kinds, kind):
					problem("%s.%s is %s, %s reads %s", typ, attr, kind, r.Predicate, strings.Join(kinds, " or "))
				}
			}
			if r.Attribute != "" {
				kinds := reads[r.Predicate]
				if r.AsString {
					kinds = []string{rulepack.KindString}
				}
				need(r.Attribute, kinds...)
			}
			// Fields read inside the attribute when it is a nested block, or
			// on the resource itself when there is no attribute.
			field := func(name string, kinds ...string) {
				if r.Attribute != "" {
					name = r.Attribute + "." + name
				}
				need(name, kinds...)
			}
			if r.Flag != "" {
				field(r.Flag, rulepack.KindBool)
			}
			if r.Field != "" {
				field(r.Field, rulepack.KindString)
			}
			for _, cidr := range []string{r.IPv4, r.IPv6} {
				if cidr != "" {
					field(cidr, rulepack.KindList, rulepack.KindString)
				}
			}
			for _, port := range r.Ports {
				field(port, rulepack.KindNumber)
			}
			for _, u := range r.Unset {
				need(u)
			}
			for attr := range r.When {
				need(attr, rulepack.KindString)
			}
		}
	}
	for _, key := range p.ControlAttributes() {
		typ, attr, _ := strings.Cut(key, ".")
		if _, ok := snap.Kind(typ, attr); !ok {
			out = append(out, fmt.Sprintf("%s/controls.yaml: %s is not in %s", p.Name, key, source))
		}
	}
	return out
}
