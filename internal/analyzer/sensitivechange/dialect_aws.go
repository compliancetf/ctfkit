package sensitivechange

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/compliancetf/ctfkit/internal/rulepack"
)

// The aws dialect: IAM policy documents held as JSON strings. This is the
// semantics a rule file cannot express, the Statement grammar and the
// Principal "AWS" key, so it is Go; which resource types and attributes hold
// a policy is data, in the pack.
func init() {
	dialects["aws"] = map[string]predicate{
		"policy_any_principal":   policyAnyPrincipal,
		"policy_wildcard_action": policyWildcardAction,
	}
	arguments["policy_any_principal"] = []string{"attribute", "message"}
	arguments["policy_wildcard_action"] = []string{"attribute", "field", "service_level", "message"}
	dialectChecks["policy_wildcard_action"] = func(r *rulepack.Rule) error {
		if !slices.Contains(rulepack.Levels, r.ServiceLevel) {
			return fmt.Errorf("policy_wildcard_action needs service_level")
		}
		return nil
	}
}

const (
	msgAnyPrincipal = "{address} allows any principal with no Condition in {attributes}"
	msgAdmin        = "{address} allows every action on every resource with no Condition in {attributes}"
	msgServiceAdmin = "{address} allows a service-wide action wildcard on every resource with no Condition in {attributes}"
)

// policyAnyPrincipal reports a policy document attribute with an Allow
// statement to any principal and no Condition.
func policyAnyPrincipal(c change, r *rulepack.Rule) []hit {
	if c.isUnknown(r.Attribute) {
		return nil
	}
	for _, s := range statements(c.after[r.Attribute]) {
		if s.allowsUnconditionally() && s.anyPrincipal() {
			return []hit{newHit(c, r, r.Level, message(r, msgAnyPrincipal), r.Attribute)}
		}
	}
	return nil
}

// serviceWildcard matches a service-wide action wildcard such as s3:*.
var serviceWildcard = regexp.MustCompile(`^[A-Za-z0-9-]+:\*$`)

// policyWildcardAction reports a policy that allows every action on every
// resource with no Condition at the rule's level, and one that allows a
// service-wide wildcard such as s3:* at service_level. With field, the
// attribute is a nested block list and each element's field is a document.
func policyWildcardAction(c change, r *rulepack.Rule) []hit {
	if c.isUnknown(r.Attribute) {
		return nil
	}
	docs := []any{c.after[r.Attribute]}
	if r.Field != "" {
		docs = nil
		for _, p := range list(c.after[r.Attribute]) {
			docs = append(docs, obj(p)[r.Field])
		}
	}

	var admin, service bool
	for _, doc := range docs {
		for _, s := range statements(doc) {
			if !s.allowsUnconditionally() || !slices.Contains(strs(s.Resource), "*") {
				continue
			}
			actions := strs(s.Action)
			admin = admin || slices.Contains(actions, "*")
			service = service || slices.ContainsFunc(actions, serviceWildcard.MatchString)
		}
	}
	switch {
	case admin:
		return []hit{newHit(c, r, r.Level, message(r, msgAdmin), r.Attribute)}
	case service:
		return []hit{newHit(c, r, r.ServiceLevel, msgServiceAdmin, r.Attribute)}
	}
	return nil
}

type statement struct {
	Effect    string
	Principal any
	Action    any
	Resource  any
	Condition any
}

func (s statement) allowsUnconditionally() bool {
	return s.Effect == "Allow" && isEmpty(s.Condition)
}

func (s statement) anyPrincipal() bool {
	if s.Principal == "*" {
		return true
	}
	return slices.Contains(strs(obj(s.Principal)["AWS"]), "*")
}

// statements parses a policy document held as a JSON string. A document that
// does not parse has no statements: this analyzer does not guess.
func statements(doc any) []statement {
	text, _ := doc.(string)
	var parsed struct {
		Statement json.RawMessage
	}
	if text == "" || json.Unmarshal([]byte(text), &parsed) != nil {
		return nil
	}
	var many []statement
	if json.Unmarshal(parsed.Statement, &many) == nil {
		return many
	}
	var one statement
	if json.Unmarshal(parsed.Statement, &one) == nil {
		return []statement{one}
	}
	return nil
}
