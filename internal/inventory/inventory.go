// Package inventory turns a loaded module inventory into the coverage record
// the report projections render: which served builds this configuration
// instantiates, which controls each of them enforces, which controls are
// delegated to a scope that was never instantiated, and which instances are
// not evidence at all.
//
// It is a pure data model. It reads no file, produces no finding and decides
// nothing about severity: the analyzer turns parts of this record into
// findings and the renderers turn all of it into bytes. Everything here is
// ordered, so two runs over the same input produce the same bytes.
//
// The vocabulary is closed and it is the one the specification fixes. A
// control is enforced, delegated, not applicable or waived. A resource is
// attested, tested, unattested or not applicable. There are no severities, no
// weights, no percentages, no score and no grade, in this package or in
// anything rendered from it. A test never upgrades a resource to enforced: a
// passing test is evidence of behavior and a manifest is evidence of a
// built-in control, and the record must not blur them.
package inventory

import (
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// ControlStatus is how a served build answers for one control. The four
// values below are the whole vocabulary.
type ControlStatus string

const (
	// ControlEnforced means an instantiated instance of this build holds the
	// control's evidence in its own manifest.
	ControlEnforced ControlStatus = "enforced"
	// ControlDelegated means a manifest says the evidence lives in another
	// scope and no instantiated instance of this build governs that scope, so
	// this configuration has no evidence the control is enforced.
	ControlDelegated ControlStatus = "delegated"
	// ControlNotApplicable means the build evaluated the control and found no
	// resource of its target type, so there was nothing to enforce it on. A
	// build normally says that by counting the control in
	// build.controls_not_applicable and listing no control entry for it, so
	// this status is reached only by a manifest that does both.
	ControlNotApplicable ControlStatus = "not_applicable"
	// ControlWaived means an exception covers the control. It is part of the
	// vocabulary the renderers share; this package never assigns it, because
	// an exception is applied to findings and not to a manifest record.
	ControlWaived ControlStatus = "waived"
)

// ResourceCoverage is how the root configuration's own resource blocks are
// covered. It is the second half of the closed vocabulary.
type ResourceCoverage string

const (
	// CoverageAttested means a manifest covers the resource. It belongs to
	// the vocabulary the renderers share; the root's own resource blocks are
	// declared by the configuration rather than by a served module, so this
	// package never assigns it to them.
	CoverageAttested ResourceCoverage = "attested"
	// CoverageTested means the root's own imported test run covers the
	// resources. It is evidence of behavior and never of a built-in control.
	CoverageTested ResourceCoverage = "tested"
	// CoverageUnattested means the root declares resources and no imported
	// run covers them.
	CoverageUnattested ResourceCoverage = "unattested"
	// CoverageNotApplicable means the root declares no resources of its own,
	// which is a different statement from declaring some and testing none.
	CoverageNotApplicable ResourceCoverage = "not-applicable"
)

// ErrNoInventory is returned when Build is called without a module inventory.
// The inventory is read at init, so a nil one means the caller ran before
// post_init: that is a caller defect and never a finding.
var ErrNoInventory = errors.New("no module inventory")

// packageScopePath is the scope path of a package-root manifest. A control's
// applies_in entries are relative to it.
const packageScopePath = "."

// rootConfigSuffixes are the configuration file names whose resource blocks
// this package counts, native syntax and JSON alike.
var rootConfigSuffixes = []string{".tf", ".tofu", ".tf.json", ".tofu.json"}

// Inventory is the whole coverage record of one root.
type Inventory struct {
	// Builds are the served builds this configuration instantiates, ordered
	// by source and then version.
	Builds []ServedBuild `json:"builds"`
	// InstancesWithoutManifest are the module instances that carry no
	// manifest, ordered by key. They are listed as not-evidence and never
	// omitted, because a reader who cannot see them would read the rest as
	// the whole configuration.
	InstancesWithoutManifest []Instance `json:"instancesWithoutManifest"`
	// RootResources is what the root configuration declares itself, which no
	// served module answers for.
	RootResources RootResources `json:"rootResources"`
}

// ServedBuild is one served build, `(registry_source, version)`, and every
// instance of it in this configuration.
type ServedBuild struct {
	// Source is the compliance.tf source the build was served from, through
	// ctfkit.RedactSource.
	Source string `json:"source"`
	// Version is the served version.
	Version string `json:"version"`
	// Keys are the module call keys of every instance of this build, in
	// ascending byte order.
	Keys []string `json:"keys"`
	// Frameworks are the framework ids the build enforced controls for, in
	// manifest order, spelled as the manifest and the control catalog spell them.
	Frameworks []string `json:"frameworks"`
	// Controls are the union of the controls every instance's manifest lists,
	// in ascending byte order of the control id.
	Controls []Control `json:"controls"`
	// NotApplicable is how many controls the build evaluated and found no
	// resource of their target type for. It is nil when no manifest of this
	// build recorded the classification, which is not the same statement as
	// zero: zero asserts that the build evaluated every catalog control and
	// found none inapplicable, and a subtree manifest carries no such record.
	NotApplicable *int `json:"notApplicable"`
	// Superseded maps a weaker control id to the stricter one that replaced
	// it. Empty rather than nil when the build superseded nothing.
	Superseded map[string]string `json:"superseded"`
	// OperationalRules are the operational rules applied to the build's
	// package, in manifest order. Empty rather than nil when there are none.
	OperationalRules []OperationalRule `json:"operationalRules"`
	// Degraded are the reasons the full org posture could not be applied, in
	// manifest order rather than sorted, because the producer's order is what
	// was recorded. Empty rather than nil when the posture was not degraded.
	Degraded []string `json:"degraded"`
	// FrameworkNames maps a catalog framework id to the display name the
	// manifest gave it, for the Markdown column headers. It is not part of
	// the receipt.
	FrameworkNames map[string]string `json:"-"`
}

// Control is what one build answers for one control, after delegation has
// been resolved against the instances this configuration actually has.
type Control struct {
	// ID is the catalog control id.
	ID string `json:"id"`
	// Status is the resolved status, which is not the raw manifest status: a
	// delegated control whose scope is instantiated here reads as enforced.
	Status ControlStatus `json:"status"`
	// SatisfiedIn are the instance keys that hold the evidence, in ascending
	// byte order. It is empty, never nil, for a control nothing in this
	// configuration enforces.
	SatisfiedIn []string `json:"satisfiedIn"`
	// ClausesByFramework maps a catalog framework id to the clauses this
	// control satisfies in it, as whole manifest sentences.
	ClausesByFramework map[string][]string `json:"clausesByFramework"`
	// SupportingClausesByFramework is, per framework, the clauses of
	// ClausesByFramework the manifest marked as supporting evidence only, in
	// listed order. Nil when the manifest does not classify (before schema
	// 3.4), which is unknown rather than full; a framework missing from the
	// map is unknown for that framework.
	SupportingClausesByFramework map[string][]string `json:"supportingClausesByFramework,omitzero"`
	// Name is the human readable control name, for the Markdown table. It is
	// not part of the receipt.
	Name string `json:"-"`
	// DelegatedTo are the scope paths a manifest delegated this control to,
	// in ascending byte order, nil when no manifest delegated it. The
	// analyzer names the scope when the delegation is unresolved, and nothing
	// else downstream reads a manifest. It is not part of the receipt.
	DelegatedTo []string `json:"-"`
}

// OperationalRule is one operational rule the build applied to its package.
type OperationalRule struct {
	// Rule is the rule id, for example "example/prevent_destroy_data".
	Rule string `json:"rule"`
	// Outcome is what the rule did on this build.
	Outcome string `json:"outcome"`
}

// Instance names a module instance that carries no manifest.
type Instance struct {
	// Key is the module call key from modules.json.
	Key string `json:"key"`
	// Source is the source string as the configuration wrote it, through
	// ctfkit.RedactSource: no query, no userinfo. The Markdown
	// and receipt projections list it as it stands here.
	Source string `json:"source"`
	// DeclaresNoResources carries the loader's reading that the module's own
	// directory has no resource block. The analyzer reads it; it is not part
	// of the receipt.
	DeclaresNoResources bool `json:"-"`
}

// RootResources is what the root configuration declares on its own account.
type RootResources struct {
	// Declared is the number of resource blocks in the root configuration
	// itself. A nested local module is a separate configuration and is not
	// counted here.
	Declared int `json:"declared"`
	// Coverage is how those resource blocks are covered.
	Coverage ResourceCoverage `json:"coverage"`
}

// buildKey is what groups instances into one served build. It is the
// manifest's own identification of the build rather than the source string in
// modules.json, because a submodule call writes a different source for the
// same served build.
type buildKey struct {
	source  string
	version string
}

// Build produces the coverage record of one root from its loaded module
// inventory and its configuration.
//
// cfg may be nil, in which case the root is reported as declaring no
// resources of its own: a caller that did not read the configuration has no
// grounds to say otherwise. inv may not be nil.
func Build(inv *ctfkit.ModuleInventory, cfg *ctfkit.ConfigArchive) (*Inventory, error) {
	if inv == nil {
		return nil, ErrNoInventory
	}

	grouped, order := groupInstances(inv.Instances)

	builds := make([]ServedBuild, 0, len(order))
	for _, key := range order {
		builds = append(builds, buildRecord(key, grouped[key]))
	}

	return &Inventory{
		Builds:                   builds,
		InstancesWithoutManifest: instancesWithoutManifest(inv.Instances),
		RootResources:            rootResources(cfg, inv.Tests),
	}, nil
}

// groupInstances collects every instance that carries a manifest under its
// served build, and returns the build keys in the order the record lists
// them: by source, then by version.
func groupInstances(instances []ctfkit.ModuleInstance) (map[buildKey][]ctfkit.ModuleInstance, []buildKey) {
	grouped := make(map[buildKey][]ctfkit.ModuleInstance)
	for _, instance := range instances {
		if instance.Manifest == nil {
			continue
		}
		key := buildKey{
			source:  instance.Manifest.Module.RegistrySource,
			version: instance.Manifest.Module.Version,
		}
		grouped[key] = append(grouped[key], instance)
	}

	order := make([]buildKey, 0, len(grouped))
	for key := range grouped {
		// Instances of one build are put in key order once, here, so every
		// field derived from them below inherits that order and no later step
		// has to sort again.
		sort.Slice(grouped[key], func(i, j int) bool {
			return grouped[key][i].Key < grouped[key][j].Key
		})
		order = append(order, key)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].source != order[j].source {
			return order[i].source < order[j].source
		}

		return order[i].version < order[j].version
	})

	return grouped, order
}

// buildRecord turns the instances of one served build into its record.
func buildRecord(key buildKey, instances []ctfkit.ModuleInstance) ServedBuild {
	record := ServedBuild{
		// Builds are grouped by the source as the manifest wrote it; only the
		// rendered value is redacted, so two builds stay two builds.
		Source:           ctfkit.RedactSource(key.source),
		Version:          key.version,
		Keys:             make([]string, 0, len(instances)),
		Frameworks:       []string{},
		Superseded:       map[string]string{},
		OperationalRules: []OperationalRule{},
		Degraded:         []string{},
		FrameworkNames:   map[string]string{},
	}

	seenFramework := make(map[string]bool)
	for _, instance := range instances {
		manifest := instance.Manifest
		record.Keys = append(record.Keys, instance.Key)

		for _, framework := range manifest.Module.Frameworks {
			if seenFramework[framework] {
				continue
			}
			seenFramework[framework] = true
			record.Frameworks = append(record.Frameworks, framework)
			if name, ok := manifest.Module.FrameworkNames[framework]; ok {
				record.FrameworkNames[framework] = name
			}
		}
	}

	// The build-level records are facts about the build rather than about a
	// scope of it, and the producer stamps the same values into every manifest
	// of the build. One manifest therefore answers for all of them, and
	// collecting them from each instance in turn would report a degraded
	// posture of one reason three times on a build with three instances.
	answering := answeringManifest(instances)
	if answering.Build.ControlsNotApplicable != nil {
		count := len(answering.Build.ControlsNotApplicable)
		record.NotApplicable = &count
	}
	for weaker, stricter := range answering.Build.ControlsSuperseded {
		record.Superseded[weaker] = stricter
	}
	for _, rule := range answering.OperationalRules {
		record.OperationalRules = append(record.OperationalRules,
			OperationalRule{Rule: rule.Rule, Outcome: rule.Outcome})
	}
	record.Degraded = append(record.Degraded, answering.Posture.Degraded...)

	record.Controls = resolveControls(instances, notApplicableSet(instances))

	return record
}

// answeringManifest is the manifest that answers for the build-level records.
//
// Only a package-scope manifest carries them, so the package root of the build
// answers when this configuration instantiated it. A configuration that
// instantiated a subtree alone has no package manifest to ask, and the first
// instance in key order answers instead: its records are the absent ones, which
// is what the receipt has to say.
func answeringManifest(instances []ctfkit.ModuleInstance) *ctfkit.Manifest {
	for _, instance := range instances {
		if instance.Manifest.ScopePath == packageScopePath {
			return instance.Manifest
		}
	}

	return instances[0].Manifest
}

// notApplicableSet is every control id a manifest of this build declared out
// of scope.
func notApplicableSet(instances []ctfkit.ModuleInstance) map[string]bool {
	set := make(map[string]bool)
	for _, instance := range instances {
		for _, id := range instance.Manifest.Build.ControlsNotApplicable {
			set[id] = true
		}
	}

	return set
}

// controlAccumulator collects what every instance of a build said about one
// control before the status is decided.
type controlAccumulator struct {
	name string
	// clauses is the clause map of the first manifest that listed the
	// control, in instance key order.
	clauses map[string][]string
	// supporting is the supporting-clause subset read from that same
	// manifest entry, nil when it does not classify.
	supporting map[string][]string
	// enforcedBy maps an instance key to the scope path its manifest governs,
	// for every instance whose manifest holds the control's evidence.
	enforcedBy map[string]string
	// delegatedTo is every scope path a manifest delegated the control to.
	delegatedTo map[string]bool
}

// resolveControls unions the controls of every instance of one build and
// resolves each one against the instances this configuration has.
//
// A control is enforced when an instance of the build holds its evidence. A
// control a manifest delegated is enforced only when the instance holding the
// evidence governs one of the scopes named in applies_in: an instance that
// enforces it somewhere else does not answer for the delegation, and the
// control stays delegated with nothing satisfying it, which is what the
// analyzer reports.
func resolveControls(instances []ctfkit.ModuleInstance, notApplicable map[string]bool) []Control {
	accumulated := make(map[string]*controlAccumulator)
	for _, instance := range instances {
		scope := instance.Manifest.ScopePath
		if scope == "" {
			scope = packageScopePath
		}

		for _, entry := range instance.Manifest.Controls {
			accumulator, ok := accumulated[entry.ControlID]
			if !ok {
				accumulator = &controlAccumulator{
					name:        entry.Name,
					clauses:     copyClauses(entry.ClausesByFramework),
					supporting:  supportingSubset(entry.ClausesByFramework, entry.SupportingClausesByFramework),
					enforcedBy:  make(map[string]string),
					delegatedTo: make(map[string]bool),
				}
				accumulated[entry.ControlID] = accumulator
			}

			switch entry.Status {
			case ctfkit.ManifestControlEnforced:
				accumulator.enforcedBy[instance.Key] = scope
			case ctfkit.ManifestControlDelegated:
				for _, target := range entry.AppliesIn {
					accumulator.delegatedTo[target] = true
				}
			}
		}
	}

	controls := make([]Control, 0, len(accumulated))
	for id, accumulator := range accumulated {
		controls = append(controls, accumulator.resolve(id, notApplicable[id]))
	}
	sort.Slice(controls, func(i, j int) bool { return controls[i].ID < controls[j].ID })

	return controls
}

// resolve decides one control's status and the keys that satisfy it.
func (a *controlAccumulator) resolve(id string, notApplicable bool) Control {
	satisfiedIn := make([]string, 0, len(a.enforcedBy))
	for key, scope := range a.enforcedBy {
		// A build that delegated this control named where the evidence lives.
		// Only an instance governing one of those scopes resolves it.
		if len(a.delegatedTo) > 0 && !a.delegatedTo[scope] {
			continue
		}
		satisfiedIn = append(satisfiedIn, key)
	}
	sort.Strings(satisfiedIn)

	control := Control{
		ID:                           id,
		Status:                       ControlEnforced,
		SatisfiedIn:                  satisfiedIn,
		ClausesByFramework:           a.clauses,
		SupportingClausesByFramework: a.supporting,
		Name:                         a.name,
		DelegatedTo:                  sortedKeys(a.delegatedTo),
	}

	switch {
	case len(satisfiedIn) > 0:
		// Enforced wins: a manifest that holds the evidence outranks any
		// other record of the same control.
	case notApplicable:
		// The build evaluated the control and found nothing to enforce it on,
		// which is a stronger statement than naming a scope that was never
		// instantiated. No fixture records a control in both places.
		control.Status = ControlNotApplicable
	default:
		control.Status = ControlDelegated
	}

	return control
}

// instancesWithoutManifest lists every instance that carries no manifest, in
// key order.
func instancesWithoutManifest(instances []ctfkit.ModuleInstance) []Instance {
	without := make([]Instance, 0)
	for _, instance := range instances {
		if instance.Manifest != nil {
			continue
		}
		without = append(without, Instance{
			Key:                 instance.Key,
			Source:              ctfkit.RedactSource(instance.Source),
			DeclaresNoResources: instance.DeclaresNoResources,
		})
	}
	sort.Slice(without, func(i, j int) bool { return without[i].Key < without[j].Key })

	return without
}

// rootResources counts the resource blocks the root configuration declares
// itself and says how they are covered.
//
// The `tested` branch has no recorded fixture: the specification names the
// word and leaves the rule that selects it open, so an imported run with at
// least one run block is taken to cover the root's resources. It never
// upgrades them past tested.
func rootResources(cfg *ctfkit.ConfigArchive, tests *ctfkit.TestRun) RootResources {
	declared := countRootResources(cfg)

	switch {
	case declared == 0:
		return RootResources{Declared: 0, Coverage: CoverageNotApplicable}
	case tests != nil && tests.Runs > 0:
		return RootResources{Declared: declared, Coverage: CoverageTested}
	default:
		return RootResources{Declared: declared, Coverage: CoverageUnattested}
	}
}

// countRootResources counts the resource blocks of the root configuration
// files, which are the files directly in the root directory. A file under a
// subdirectory belongs to a nested local module, which is its own
// configuration and answers for its own resources.
func countRootResources(cfg *ctfkit.ConfigArchive) int {
	if cfg == nil {
		return 0
	}

	count := 0
	for _, file := range parser.PrimaryFiles(cfg.Files) {
		if strings.Contains(file.Path, "/") || !hasRootConfigSuffix(file.Path) {
			continue
		}

		// A file that does not parse contributes the blocks that did parse.
		// Configuration validity is terraform's answer to give, not this
		// package's, and a parse error here is never a finding.
		count += len(parser.ParseConfigContent(file.Bytes, file.Path).Resources)
	}

	return count
}

// hasRootConfigSuffix reports whether this file's resource blocks are counted.
func hasRootConfigSuffix(path string) bool {
	for _, suffix := range rootConfigSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}

	return false
}

// copyClauses copies a clause map keyed by the catalog framework id (the
// manifest's own spelling, which is the control catalog's). The clause strings
// are the manifest's own whole sentences; the receipt keeps them and the other
// projections shorten them.
func copyClauses(clauses map[string][]string) map[string][]string {
	copied := make(map[string][]string, len(clauses))
	for framework, entries := range clauses {
		// The slice is copied rather than aliased: the manifest belongs to the
		// caller, and nothing this package returns may be a window onto it.
		copied[framework] = append([]string(nil), entries...)
	}

	return copied
}

// supportingSubset is, per framework the manifest classified, its listed
// clauses filtered to the ones marked supporting, in listed order. Filtering
// the listed clauses rather than copying the marked ones means a manifest
// cannot hedge a clause it never claimed. A framework absent from supporting
// stays absent (unknown) instead of becoming an empty list, which would read
// as "nothing hedged there"; nil supporting (a manifest before schema 3.4)
// stays nil.
func supportingSubset(clauses, supporting map[string][]string) map[string][]string {
	if supporting == nil {
		return nil
	}

	subset := make(map[string][]string, len(supporting))
	for framework, marked := range supporting {
		listed, ok := clauses[framework]
		if !ok {
			continue
		}
		hedged := make([]string, 0, len(marked))
		for _, clause := range listed {
			if slices.Contains(marked, clause) {
				hedged = append(hedged, clause)
			}
		}
		subset[framework] = hedged
	}

	return subset
}

// sortedKeys returns the set's members in ascending byte order, nil when the
// set is empty, so an absent record stays absent rather than becoming empty.
func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}

	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}
