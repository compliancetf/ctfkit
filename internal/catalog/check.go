package catalog

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// document is the ctf.catalog/1 file as written. Unknown fields are ignored,
// so an additive minor bump needs no change here.
type document struct {
	Schema      string            `yaml:"schema"`
	Version     string            `yaml:"version"`
	Hosts       map[string]string `yaml:"hosts"`
	DefaultHost string            `yaml:"defaultHost"`
	Controls    []documentControl `yaml:"controls"`
	Modules     []documentModule  `yaml:"modules"`
	// NotApplicableClauses maps a framework id to the clauses of it no control
	// applies to, each with its reason. Optional.
	NotApplicableClauses map[string]map[string]string `yaml:"notApplicableClauses"`
}

type documentControl struct {
	ID                 string              `yaml:"id"`
	Name               string              `yaml:"name"`
	ResourceTypes      []string            `yaml:"resourceTypes"`
	ClausesByFramework map[string][]string `yaml:"clausesByFramework"`
	// Enforcement and NotApplicable are optional; a catalog without them
	// loads as before.
	Enforcement   *documentEnforcement `yaml:"enforcement"`
	NotApplicable map[string]string    `yaml:"notApplicable"`
}

type documentEnforcement struct {
	Layer  string `yaml:"layer"`
	Reason string `yaml:"reason"`
}

// enforcementLayers are the values enforcement.layer may take.
var enforcementLayers = map[string]bool{
	ctfkit.LayerProviderLocal:  true,
	ctfkit.LayerCompanionLocal: true,
	ctfkit.LayerGraph:          true,
	ctfkit.LayerRuntime:        true,
}

type documentModule struct {
	ResourceTypes []string `yaml:"resourceTypes"`
	Source        string   `yaml:"source"`
	Version       string   `yaml:"version"`
	Controls      []string `yaml:"controls"`
}

// hostPlaceholder is the token a module source carries where the host label of
// the remediation framework goes. It is a host label, not a framework id,
// which is what the hosts map translates.
const hostPlaceholder = "{host}"

// Check enforces the catalog rules that relate one part of the document to
// another. JSON Schema states the shape of each part; nothing in it can say
// that an id used here is defined over there, or that a value appears at most
// once across array entries, so those rules live in Go. It is the one
// implementation: the loader runs it on every file it reads, and schemacheck
// runs it on every catalog fixture.
//
// It returns one message per broken rule, naming the offending values, because
// a catalog that breaks two rules should report both. An empty result means
// the document is coherent.
func Check(b []byte) []string {
	var doc document
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return []string{fmt.Sprintf("cannot read the catalog: %v", err)}
	}
	return checkDocument(doc)
}

func checkDocument(doc document) []string {
	var msgs []string
	add := func(rule string, bad []string) {
		if len(bad) == 0 {
			return
		}
		sort.Strings(bad)
		msgs = append(msgs, rule+": "+strings.Join(bad, "; "))
	}

	// Control ids are the join key across prevent, detect and evidence, so a
	// duplicate id makes ControlsFor ambiguous.
	controlIDs := make(map[string]bool, len(doc.Controls))
	var dupControls []string
	for _, c := range doc.Controls {
		if controlIDs[c.ID] {
			dupControls = append(dupControls, c.ID)
			continue
		}
		controlIDs[c.ID] = true
	}
	add("a control id may be defined only once", dupControls)

	// A resource type repeated inside one entry would put the same control id
	// on the same resource twice, which ControlsFor would hand to an analyzer
	// as two controls. The schema states this for modules[]; it cannot state
	// it for controls[], so it is stated here.
	var dupControlTypes []string
	for _, c := range doc.Controls {
		seen := make(map[string]bool, len(c.ResourceTypes))
		for _, rt := range c.ResourceTypes {
			if seen[rt] {
				dupControlTypes = append(dupControlTypes, fmt.Sprintf("%s lists %s twice", c.ID, rt))
				continue
			}
			seen[rt] = true
		}
	}
	add("a resource type may appear only once in a controls[] entry", dupControlTypes)

	// A resource type in two modules entries leaves ModuleFor with no
	// tie-break.
	coveredBy := make(map[string]string, len(doc.Modules))
	var dupTypes []string
	for _, m := range doc.Modules {
		for _, rt := range m.ResourceTypes {
			if first, ok := coveredBy[rt]; ok {
				dupTypes = append(dupTypes, fmt.Sprintf("%s is covered by both %s and %s", rt, first, m.Source))
				continue
			}
			coveredBy[rt] = m.Source
		}
	}
	add("a resource type may appear in at most one modules[] entry", dupTypes)

	// A module claiming a control the catalog does not define would put an id
	// on a finding that nothing else can resolve.
	var unknownControls []string
	for _, m := range doc.Modules {
		for _, id := range m.Controls {
			if !controlIDs[id] {
				unknownControls = append(unknownControls, fmt.Sprintf("%s lists %s", m.Source, id))
			}
		}
	}
	add("a modules[] control id must be defined in controls[]", unknownControls)

	// defaultHost is a framework id looked up in hosts, so an id that is not a
	// key there leaves remediation with no host at all.
	if _, ok := doc.Hosts[doc.DefaultHost]; !ok {
		msgs = append(msgs, fmt.Sprintf("defaultHost must be a key of hosts: %s is not", doc.DefaultHost))
	}

	// A clause map keyed by a framework the catalog cannot host would put a
	// framework on a finding that no remediation host exists for.
	var unknownFrameworks []string
	for _, c := range doc.Controls {
		for fw := range c.ClausesByFramework {
			if _, ok := doc.Hosts[fw]; !ok {
				unknownFrameworks = append(unknownFrameworks, fmt.Sprintf("%s maps clauses for %s", c.ID, fw))
			}
		}
	}
	add("every clausesByFramework key must be a key of hosts", unknownFrameworks)

	// One placeholder is one substitution. Two would need a rule for what the
	// second one becomes, and there is none.
	var multiPlaceholder []string
	for _, m := range doc.Modules {
		if n := strings.Count(m.Source, hostPlaceholder); n > 1 {
			multiPlaceholder = append(multiPlaceholder, fmt.Sprintf("%s carries %d", m.Source, n))
		}
	}
	add("a source may carry "+hostPlaceholder+" at most once", multiPlaceholder)

	// An enforcement layer outside the enum would reach a reader as a layer
	// nobody defined.
	var badLayers []string
	for _, c := range doc.Controls {
		if c.Enforcement != nil && !enforcementLayers[c.Enforcement.Layer] {
			badLayers = append(badLayers, fmt.Sprintf("%s has %q", c.ID, c.Enforcement.Layer))
		}
	}
	add("enforcement.layer must be one of provider-local, companion-local, graph, runtime", badLayers)

	return msgs
}
