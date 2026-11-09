// Package coverage implements the ctf.coverage.manifest family: the post_init
// rules that read the compliance manifests init wrote into
// .terraform/modules and say, honestly, what this configuration has evidence
// for and what it does not.
//
// Six rules emit findings. A seventh, ctf.coverage.manifest_schema, is
// deliberately absent: an unsupported manifest schema major is an environment
// error the loader refuses before any analyzer runs, so it is an exit 2 and
// never a finding. Registering it here would turn a tool failure into a
// policy verdict.
//
// One Analyzer value implements one rule id, as the SDK contract requires,
// and every one of them reads the same coverage record: internal/inventory
// does the grouping and the delegation resolution, and nothing here repeats
// it. The values are stateless, so the family is pure and safe to run
// concurrently.
//
// The vocabulary is the one the specification fixes. No severities beyond the
// three SARIF levels, no weights, no percentages, no score and no grade. An
// instance without a manifest is reported as not-evidence and never omitted.
package coverage

import (
	"fmt"
	"sort"
	"strings"

	catalogpkg "github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The rule ids of the family. They are the SARIF ruleId, the exception join
// key and the taxonomy entry, so they never change once published.
const (
	ruleManifestMissing      = "ctf.coverage.manifest_missing"
	rulePostureDegraded      = "ctf.coverage.posture_degraded"
	ruleDelegationUnresolved = "ctf.coverage.delegation_unresolved"
	ruleObligationUnknown    = "ctf.coverage.obligation_unknown"
	ruleResourceUnattested   = "ctf.coverage.resource_unattested"
	ruleTestsFailed          = "ctf.coverage.tests_failed"
)

// Descriptors returns the tool.driver.rules entries of the family, for the
// runner to hand to the SARIF renderer. The texts are the recorded report
// fixtures' bytes.
func Descriptors() []sarif.RuleDescriptor {
	return []sarif.RuleDescriptor{
		{
			ID:               ruleManifestMissing,
			ShortDescription: "An instantiated module has no compliancetf-manifest.json",
			Level:            ctfkit.LevelError,
		},
		{
			ID:               rulePostureDegraded,
			ShortDescription: "The served build reports a degraded posture",
			Level:            ctfkit.LevelError,
		},
		{
			ID:               ruleDelegationUnresolved,
			ShortDescription: "A delegated control has no instantiated sibling scope enforcing it",
			Level:            ctfkit.LevelWarning,
		},
		{
			ID:               ruleObligationUnknown,
			ShortDescription: "A manifest obligation token is not in the shipped list",
			Level:            ctfkit.LevelNote,
		},
		{
			ID:               ruleResourceUnattested,
			ShortDescription: "The configuration declares its own resources and no imported test run covers them",
			Level:            ctfkit.LevelNote,
		},
		{
			ID:               ruleTestsFailed,
			ShortDescription: "Imported test results report failed or errored runs",
			Level:            ctfkit.LevelError,
		},
	}
}

// Message templates. They are analyzer constants formatted with module keys,
// control ids, scope paths, module sources and counts, and never with an
// attribute value read from a configuration or a plan. A module source passes
// ctfkit.RedactSource first, so its query and userinfo never reach a message.
const (
	msgManifestMissing = "Module instance %s (%s) has no compliancetf-manifest.json; " +
		"it is listed as not-evidence, never as covered"
	msgPostureDegraded      = "Served build %s %s reports a degraded posture: %s"
	msgDelegationUnresolved = "Control %s is delegated to scope %s of %s %s; " +
		"no instantiated module instance governs that scope, " +
		"so this configuration has no evidence the control is enforced"
	msgControlNotInCatalog = "; the control catalog %s does not hold this control id, " +
		"so the finding carries no control id"
	msgObligationUnknown = "Manifest obligation token %s is not in the list this ctfkit release ships; " +
		"the obligation is reported unchanged and never blocks"
	msgResourceUnattested = "This configuration declares %d resource block(s) of its own " +
		"and no imported test run covers them; they are unattested, not enforced"
	msgTestsFailed = "Imported test results report %d failed and %d errored run(s) of %d"
)

// schemaVersion is the findings format version every finding of this family
// carries in ctf.schema.
const schemaVersion = "1.0"

// modulesJSONPath is the file every finding of this family points at. The
// evidence is the module inventory as a whole rather than a line of
// configuration, so the location is the file init wrote and it carries no
// region. A finding about one module instance also names that instance as a
// module logical location; see moduleAddress.
const modulesJSONPath = ".terraform/modules/modules.json"

// rootConfigSuffixes are the configuration file names whose resource blocks a
// served equivalent is looked up from, native syntax and JSON alike. It
// matches what internal/inventory counts.
var rootConfigSuffixes = []string{".tf", ".tofu", ".tf.json", ".tofu.json"}

// Register adds every emitting rule of the family to r, at post_init.
//
// The registration order is the order a run collects findings in when two
// rules produce the same level, so it is the emission order the Markdown,
// receipt, SARIF and Spacelift projections all share.
func Register(r ctfkit.Registry) {
	ctfkit.MustRegister(r,
		ManifestMissing{},
		PostureDegraded{},
		DelegationUnresolved{},
		ObligationUnknown{},
		ResourceUnattested{},
		TestsFailed{},
	)
}

// analysis is the reading of one AnalyzerInput every rule works from: the
// coverage record internal/inventory built, plus the input it was built from,
// for the few facts the record does not carry.
type analysis struct {
	inventory *inventory.Inventory
	input     ctfkit.AnalyzerInput
}

// evaluate builds the coverage record for one rule invocation.
//
// It returns a nil analysis when the stage populated no module inventory,
// which is what every rule reports as no findings rather than as an error: an
// analyzer of this family selected at a stage before post_init has nothing to
// read, and that is the loader's contract rather than a malfunction.
func evaluate(in ctfkit.AnalyzerInput) (*analysis, error) {
	if in.Modules == nil {
		return nil, nil
	}

	record, err := inventory.Build(in.Modules, in.Config)
	if err != nil {
		return nil, fmt.Errorf("coverage: building the coverage record: %w", err)
	}

	return &analysis{inventory: record, input: in}, nil
}

// newFinding builds one finding of the family. Every rule goes through it, so
// the schema version, the stage, the kind and the location are stated once.
//
// moduleKey is the modules.json key of the one instance the finding is about,
// or empty when the finding is about a build, a token or the run. A set key
// becomes a module logical location, which is the finding's Subject and so the
// resource a rule-keyed exception entry is scoped to.
//
// Preventive follows the remediation: a compliance.tf module would have
// prevented the finding exactly when the catalog names one, and no other rule
// of the family has a preventive form.
func newFinding(ruleID, level, text, moduleKey string, controlIDs []ctfkit.ControlID,
	frameworks []ctfkit.FrameworkClauses, remediation *ctfkit.Remediation,
) (ctfkit.Finding, error) {
	location := ctfkit.Location{
		PhysicalLocation: &ctfkit.PhysicalLocation{
			ArtifactLocation: ctfkit.ArtifactLocation{URI: modulesJSONPath},
		},
	}
	if moduleKey != "" {
		location.LogicalLocations = []ctfkit.LogicalLocation{{
			FullyQualifiedName: moduleAddress(moduleKey),
			Kind:               ctfkit.LogicalLocationModule,
		}}
	}

	return ctfkit.NewFinding(ruleID, level, ctfkit.KindFail,
		ctfkit.Message{Text: text},
		[]ctfkit.Location{location},
		ctfkit.Properties{
			Schema:      schemaVersion,
			Stage:       ctfkit.PostInit,
			ControlIDs:  controlIDs,
			Frameworks:  frameworks,
			Preventive:  remediation != nil,
			Remediation: remediation,
		})
}

// moduleAddress is the configuration address of a modules.json key: "vpc" is
// module.vpc and the nested "s3_bucket.notification" is
// module.s3_bucket.module.notification. A module call name cannot contain a
// dot, so the split is exact. A key names a module call, never a count or
// for_each instance of it, so a waiver scoped to module.x covers every
// instance of x.
func moduleAddress(key string) string {
	return "module." + strings.ReplaceAll(key, ".", ".module.")
}

// frameworkClauses turns a control's manifest clause map into the
// ctf.frameworks list. The manifest carries whole clause sentences; this
// projection carries the leading clause identifier alone, which is the split
// the recorded fixtures freeze. The supporting subset rides along only for a
// framework the manifest classified, so an unclassified one stays unknown.
func frameworkClauses(control inventory.Control) []ctfkit.FrameworkClauses {
	out := make([]ctfkit.FrameworkClauses, 0, len(control.ClausesByFramework))
	for framework, clauses := range control.ClausesByFramework {
		entry := ctfkit.FrameworkClauses{ID: framework, Clauses: clauseIdentifiers(clauses)}
		if supporting, ok := control.SupportingClausesByFramework[framework]; ok {
			entry.SupportingClauses = clauseIdentifiers(supporting)
		}
		out = append(out, entry)
	}

	// NewFinding sorts the list and the clauses inside it, so nothing here
	// has to: two runs over the same manifest emit the same bytes.
	return out
}

// clauseIdentifiers shortens whole clause sentences to their identifiers,
// dropping duplicates. The result is never nil.
//
// Two sentences that share an identifier collapse into one. When one of them
// is full evidence and the other supporting, the identifier appears in both
// clauses and supportingClauses, so it reads as supporting only. That is a
// deliberate choice: it can only downgrade a claim, never raise one. No
// recorded manifest has the case.
func clauseIdentifiers(clauses []string) []string {
	identifiers := make([]string, 0, len(clauses))
	seen := make(map[string]bool, len(clauses))
	for _, clause := range clauses {
		identifier := catalogpkg.ClauseIdentifier(clause)
		if identifier == "" || seen[identifier] {
			continue
		}
		seen[identifier] = true
		identifiers = append(identifiers, identifier)
	}

	return identifiers
}

// servedEquivalent names the compliance.tf module that would have prevented a
// manifest-less instance from being unevidenced, or nil when the catalog
// names none.
//
// The lookup is by resource type, which is the only key the catalog offers
// and the only thing that can be read about an instance with no manifest: the
// instance's own configuration files are parsed and the first resource type
// the catalog covers answers. A remote instance whose source was never
// vendored into the archive has no files to read and therefore no
// equivalent, which is reported as no remediation rather than as a guess.
func (a *analysis) servedEquivalent(key string) *ctfkit.Remediation {
	catalog := a.input.Catalog
	if catalog == nil {
		return nil
	}

	for _, resourceType := range a.resourceTypesOf(key) {
		module, ok := catalog.ModuleFor(resourceType)
		if !ok {
			continue
		}
		return &ctfkit.Remediation{
			ModuleSource: strings.ReplaceAll(module.Source, "{host}", remediationHost(catalog, a.input.Metadata.Frameworks)),
			Version:      module.Version,
		}
	}

	return nil
}

// resourceTypesOf is the sorted set of resource types the instance's own
// configuration files declare. Only the files directly in the instance
// directory are read: a nested directory is a further module and answers for
// itself.
func (a *analysis) resourceTypesOf(key string) []string {
	dir := a.directoryOf(key)
	if dir == "" || a.input.Config == nil {
		return nil
	}

	seen := make(map[string]bool)
	for _, file := range parser.PrimaryFiles(a.input.Config.Files) {
		if !isDirectChild(dir, file.Path) {
			continue
		}

		// A file that does not parse contributes the blocks that did parse.
		// Configuration validity is terraform's answer to give, and a parse
		// error here is never a finding.
		for _, resource := range parser.ParseConfigContent(file.Bytes, file.Path).Resources {
			seen[resource.Type] = true
		}
	}

	types := make([]string, 0, len(seen))
	for resourceType := range seen {
		types = append(types, resourceType)
	}
	sort.Strings(types)

	return types
}

// directoryOf is the installed directory of a module instance, empty when the
// inventory holds no instance under that key.
func (a *analysis) directoryOf(key string) string {
	for _, instance := range a.input.Modules.Instances {
		if instance.Key == key {
			return instance.Dir
		}
	}

	return ""
}

// isDirectChild reports whether path is a configuration file sitting directly
// in dir, with no further directory between them.
func isDirectChild(dir, path string) bool {
	prefix := dir + "/"
	if dir == "." {
		prefix = ""
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}

	name := path[len(prefix):]
	if strings.Contains(name, "/") {
		return false
	}
	for _, suffix := range rootConfigSuffixes {
		if len(name) > len(suffix) && strings.HasSuffix(name, suffix) {
			return true
		}
	}

	return false
}

// remediationHost is the registry endpoint label substituted for the {host}
// placeholder of a catalog module source. The run's own framework wins when
// the catalog hosts it, and the catalog's default answers otherwise.
func remediationHost(catalog ctfkit.ControlCatalog, frameworks []string) string {
	hosts := catalog.Hosts()
	for _, framework := range frameworks {
		if label, ok := hosts[framework]; ok {
			return label
		}
	}

	fallback := catalog.DefaultHost()
	if label, ok := hosts[fallback]; ok {
		return label
	}

	return fallback
}
