package rulepack

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// IdentitiesFile is the identity catalog of a pack: the forms an identity
// value takes and the forms each resource attribute holds.
const IdentitiesFile = "identities.yaml"

// Identities is a pack's identity catalog, which ctf.graph.companion reads to
// decide whether two resources name the same object. Two values link only
// when they are known and in the same form; the catalog says which form a
// value is in.
type Identities struct {
	// Scope lists the resource attributes that must agree for two resources
	// to share an account and region, beyond sharing a provider
	// configuration. In hashicorp/aws v6 that is the per-resource region.
	Scope []string

	forms map[string]*regexp.Regexp
	// prefixed names the forms whose pattern starts with a literal, such as
	// arn: or vpc-, sorted: the only forms a value can be read as when its
	// attribute does not declare them.
	prefixed []string
	attrs    map[string]map[string][]string
}

// Classify returns the identity form of value as attribute attr of
// resourceType holds it: the first of the attribute's declared forms whose
// pattern matches, else the first other form with a literal prefix that
// matches, in name order, so an ARN where a name is declared is still
// recognized as an ARN (an alias). A form with no literal prefix, such as a
// bucket name, also matches ids of other kinds (a VPC id, a WAF classic
// UUID), so it is never matched outside its declaring attributes. It reports
// false, a catalog miss, when the attribute is not in the catalog or the
// value matches no form it may be read as.
func (c *Identities) Classify(resourceType, attr, value string) (string, bool) {
	if c == nil {
		return "", false
	}
	declared, ok := c.attrs[resourceType][attr]
	if !ok {
		return "", false
	}
	for _, name := range declared {
		if c.forms[name].MatchString(value) {
			return name, true
		}
	}
	for _, name := range c.prefixed {
		if !slices.Contains(declared, name) && c.forms[name].MatchString(value) {
			return name, true
		}
	}
	return "", false
}

// Forms returns the forms an attribute declares, in match order, nil when the
// catalog does not name the attribute.
func (c *Identities) Forms(resourceType, attr string) []string {
	if c == nil {
		return nil
	}
	return c.attrs[resourceType][attr]
}

// Attributes returns every "type.attribute" key the catalog names, sorted.
func (c *Identities) Attributes() []string {
	if c == nil {
		return nil
	}
	var out []string
	for t, attrs := range c.attrs {
		for a := range attrs {
			out = append(out, t+"."+a)
		}
	}
	sort.Strings(out)
	return out
}

func (p *Pack) parseIdentities(fsys fs.FS, file string) error {
	var doc struct {
		Scope []string `yaml:"scope"`
		Forms map[string]struct {
			Pattern string `yaml:"pattern"`
		} `yaml:"forms"`
		Attributes map[string]map[string][]string `yaml:"attributes"`
	}
	if err := decode(fsys, file, &doc); err != nil {
		return err
	}
	if len(doc.Forms) == 0 || len(doc.Attributes) == 0 {
		return errors.New(IdentitiesFile + ": forms and attributes are required")
	}
	c := &Identities{Scope: doc.Scope, forms: map[string]*regexp.Regexp{}, attrs: doc.Attributes}
	for name, f := range doc.Forms {
		// Anchored, so a pattern cannot match a fragment of a longer value.
		if !strings.HasPrefix(f.Pattern, "^") || !strings.HasSuffix(f.Pattern, "$") {
			return fmt.Errorf("%s: form %s: pattern must be anchored with ^ and $", IdentitiesFile, name)
		}
		// Grouped, so an alternation cannot escape either anchor.
		re, err := regexp.Compile(`^(?:` + f.Pattern + `)$`)
		if err != nil {
			return fmt.Errorf("%s: form %s: %w", IdentitiesFile, name, err)
		}
		c.forms[name] = re
		// The literal prefix of the pattern without its leading ^, which
		// LiteralPrefix does not see through; an alternation has none.
		if lit, err := regexp.Compile(strings.TrimPrefix(f.Pattern, "^")); err == nil {
			if prefix, _ := lit.LiteralPrefix(); prefix != "" {
				c.prefixed = append(c.prefixed, name)
			}
		}
	}
	sort.Strings(c.prefixed)
	for t, attrs := range doc.Attributes {
		if !strings.HasPrefix(t, p.ResourcePrefix) {
			return fmt.Errorf("%s: %s does not start with %s", IdentitiesFile, t, p.ResourcePrefix)
		}
		for a, forms := range attrs {
			if a == "" || len(forms) == 0 {
				return fmt.Errorf("%s: %s.%s names no form", IdentitiesFile, t, a)
			}
			for _, f := range forms {
				if c.forms[f] == nil {
					return fmt.Errorf("%s: %s.%s names unknown form %q", IdentitiesFile, t, a, f)
				}
			}
		}
	}
	p.Identities = c
	return nil
}
