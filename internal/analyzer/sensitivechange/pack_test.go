package sensitivechange

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/compliancetf/ctfkit/internal/rulepack"
)

// TestEmbeddedPacksCheck holds every embedded pack to the predicates and
// arguments this build has.
func TestEmbeddedPacksCheck(t *testing.T) {
	for _, p := range rulepack.Embedded().Packs() {
		if err := checkPack(p); err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
		if len(p.Rules) == 0 {
			t.Errorf("%s has no rules", p.Name)
		}
	}
}

// TestCheckPackRejects records the rules a pack must follow beyond its YAML
// structure: each is a rule that would otherwise never fire, or fire with a
// broken message.
func TestCheckPackRejects(t *testing.T) {
	cases := map[string]struct {
		rule, dialect, want string
	}{
		"unknown predicate":      {`{types: [demo_x], attribute: a, predicate: turned_sideways, level: error}`, "", "does not exist"},
		"unknown class":          {`{types: [demo_x], attribute: a, predicate: turned_on, level: error}`, "", "class"},
		"missing attribute":      {`{types: [demo_x], predicate: turned_on, level: error}`, "", "needs attribute"},
		"value_in with no text":  {`{types: [demo_x], attribute: a, predicate: value_in, values: [x], level: error}`, "", "message"},
		"unknown placeholder":    {`{types: [demo_x], attribute: a, predicate: turned_on, level: error, message: "{address} {value}"}`, "", "{value}"},
		"replaced with no kinds": {`{types: [demo_x], predicate: replaced, level: error}`, "", "kinds"},
		"deleted with no kinds":  {`{types: [demo_x], predicate: deleted, level: error}`, "", "kinds"},
		"note_ports, no ports":   {`{types: [demo_x], predicate: open_cidr, ipv4: c, note_ports: [80], level: error}`, "", "ports"},
		"dialect not built":      {`{types: [demo_x], attribute: a, predicate: turned_on, level: error}`, "cobol", "dialect"},
		"dialect predicate without the dialect": {
			`{types: [demo_x], attribute: policy, predicate: policy_any_principal, level: error}`, "", "does not exist"},
		"argument of another predicate": {`{types: [demo_x], attribute: a, predicate: turned_on, or_removed: true, level: error}`, "", "turned_on does not read or_removed"},
		"values on turned_off":          {`{types: [demo_x], attribute: a, predicate: turned_off, values: [x], level: error}`, "", "turned_off does not read values"},
		"attribute on deleted":          {`{types: [demo_x], attribute: a, predicate: deleted, message: gone, level: error}`, "", "deleted does not read attribute"},
		"as_string on turned_on":        {`{types: [demo_x], attribute: a, predicate: turned_on, as_string: true, level: error}`, "", "turned_on does not read as_string"},
		"flag on removed":               {`{types: [demo_x], attribute: a, predicate: removed, flag: on, level: error}`, "", "removed does not read flag"},
		"wildcard with no service level": {
			`{types: [demo_x], attribute: policy, predicate: policy_wildcard_action, level: error}`, "aws", "service_level"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			class := "public_exposure"
			if name == "unknown class" {
				class = "mischief"
			}
			provider := "source: bobthecorp/demo\nresource_prefix: demo_\ntags: {attribute: tags}\n"
			if tc.dialect != "" {
				provider += "dialect: " + tc.dialect + "\n"
			}
			set, err := rulepack.Parse(fstest.MapFS{
				"rules/defaults.yaml":         {Data: []byte("tags: {attribute: tags}\n")},
				"rules/demo/v1/provider.yaml": {Data: []byte(provider)},
				"rules/demo/v1/rules.yaml":    {Data: []byte("class: " + class + "\nrules:\n  - " + tc.rule + "\n")},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = checkPack(set.Packs()[0])
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("checkPack error = %v, want one naming %q", err, tc.want)
			}
		})
	}
}
