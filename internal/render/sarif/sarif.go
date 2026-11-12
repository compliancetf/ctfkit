// Package sarif renders the findings of one ctfkit run as SARIF 2.1.0 with the
// compliance.tf findings format on top of it: a ctf.* property bag on every
// result and run-level ctf.* properties for the catalog version and the
// optional --watermark banner.
//
// The document is written by hand rather than through a SARIF library. Every
// byte is pinned by a fixture, the emitted subset is small, and a library that
// orders keys its own way or drops an unmodeled property would make the
// fixtures unreachable. What that costs is a hand-checked SARIF subset; the
// cff-1 schema is what checks it back.
package sarif

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// ruleIDPattern is the ruleId pattern of the published schemas, cff-1 and
// spacelift-1, which agree: ctf, a family segment with no underscore, then one
// or more underscore-bearing segments.
//
// It is deliberately not the SDK's own check. ctfkit.Finding.Validate uses a
// looser regexp that allows an underscore in the family segment, so a rule id
// such as ctf.s3_bucket.enabled passes the SDK and fails both published
// schemas. Rendering it would put a document the schema rejects in front of a
// dashboard, so the narrower of the two wins here. The divergence is a defect
// in the SDK regexp rather than a rule this renderer wants to own, and is
// reported separately. internal/render/spacelift carries the
// same guard for the same reason; the two converge when the SDK regexp is
// fixed.
var ruleIDPattern = regexp.MustCompile(`^ctf\.[a-z0-9]+(\.[a-z0-9_]+)+$`)

// schemaVersionPattern is the ctf.schema grammar of cff-1. The SDK checks only
// that the field is set, so its shape is checked here.
var schemaVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

// catalogVersionPattern is the ctf.catalogVersion.version grammar of cff-1 and
// catalog-1, which is semver.org's own.
var catalogVersionPattern = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
		`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// FileName is the name the projection takes on disk.
const FileName = "findings.sarif"

// SchemaURI is the $schema every rendered document carries, and the value
// cff-1 pins.
const SchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// sarifVersion is the only SARIF version ctfkit emits.
const sarifVersion = "2.1.0"

// informationURI is the driver's home, the same in every document.
const informationURI = "https://github.com/compliancetf/ctfkit"

// suppressionKindExternal is the SARIF suppression kind an exception registry
// entry produces: the waiver lives outside the source, in the registry.
const suppressionKindExternal = "external"

// Catalog origins cff-1 allows on ctf.catalogVersion. They are checked here
// rather than taken on trust because ctfkit.CatalogVersion.Provenance is a
// bare string: a fourth value, or a typo, would otherwise reach the file as a
// document the schema refuses.
const (
	originEmbedded = "embedded"
	originFile     = "file"
	originHome     = "home"
)

// Tool identifies the generator in tool.driver.
type Tool struct {
	// Name is the driver name, "ctfkit".
	Name string
	// Version is the generator version.
	Version string
}

// RuleDescriptor is one entry of tool.driver.rules: what a rule id means and
// what level it reports at by default.
//
// The renderer holds no table of its own. The analyzer families own their
// descriptors, the runner collects them, and this package emits the subset
// that fired. A finding whose rule id has no descriptor is an error rather
// than an invented description, because a dashboard shows the rule text beside
// the result and a placeholder there is worse than a failed render.
type RuleDescriptor struct {
	// ID is the rule id, the same string the findings carry.
	ID string
	// ShortDescription is the one-line meaning of the rule.
	ShortDescription string
	// Help is the rule's help text: when it does and does not report, and
	// what to do about its known misses. Empty omits the member.
	Help string
	// Level is the rule's default level.
	Level string
	// HelpURI is the documentation page of the rule, written as helpUri and
	// linked from the help text. Empty omits the member and the link.
	HelpURI string
}

// AnalyzerDocs is the base of the analyzer reference on the documentation
// site; an analyzer family appends the anchor of its section.
const AnalyzerDocs = "https://compliance.tf/docs/ctfkit/analyzers/"

// WithHelpURI returns ds with HelpURI set to uri on every descriptor that has
// none, so an analyzer family names its documentation section once.
func WithHelpURI(uri string, ds []RuleDescriptor) []RuleDescriptor {
	out := make([]RuleDescriptor, len(ds))
	for i, d := range ds {
		if d.HelpURI == "" {
			d.HelpURI = uri
		}
		out[i] = d
	}
	return out
}

// Input is everything the renderer needs. It takes findings rather than a
// receipt so that the SARIF file can be written from the same in-memory run as
// every other projection, with no ordering dependency between them.
type Input struct {
	// Tool identifies the generator.
	Tool Tool
	// Rules are the descriptors of every rule the run could report. Render
	// emits the ones that fired, sorted by id.
	Rules []RuleDescriptor
	// Findings are the run's findings in the order every projection shows
	// them, suppressed ones included: a waiver hides a finding from the gate,
	// not from the record. Ordering is the runner's job, through
	// ctfkit.SortFindings, so that every projection shows one order.
	Findings ctfkit.Findings
	// Metadata is the run context. RunID and Commit become the ctf.evidence
	// object; the rest is not part of this projection.
	Metadata ctfkit.RunMetadata
	// Catalog is the control catalog the run read, recorded at run level so a
	// reader can tell a finding produced from the embedded catalog from one
	// produced against a vendored file. A zero value is omitted.
	Catalog ctfkit.CatalogVersion
	// Watermark is the optional --watermark banner line, empty for none. It
	// is written as the run property ctf.watermark only when set.
	Watermark string
	// Notifications are run-level notices that are not findings, such as
	// ctf.catalog.stale. They are written as the toolExecutionNotifications of
	// the run's one invocation. None means no invocations key at all, so a run
	// without a notice renders the bytes it rendered before notices existed.
	Notifications []Notification
}

// Notification is a run-level notice: never a finding, never part of the exit
// code. DescriptorID names what kind of notice it is.
type Notification struct {
	DescriptorID string
	Level        string
	Text         string
}

// document is the file itself. Field order is key order throughout this file:
// encoding/json writes struct fields in declaration order, which is what keeps
// the rendered bytes stable without a hand-rolled encoder.
type document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool        tool           `json:"tool"`
	Invocations []invocation   `json:"invocations,omitempty"`
	Properties  *runProperties `json:"properties,omitempty"`
	Results     []result       `json:"results"`
}

// invocation is SARIF's record of one tool run. executionSuccessful is
// required by SARIF 2.1.0 on every invocation object; it is true because the
// renderer only runs for a completed analysis.
type invocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	Notifications       []notification `json:"toolExecutionNotifications"`
}

type notification struct {
	Descriptor descriptorRef  `json:"descriptor"`
	Level      string         `json:"level"`
	Message    ctfkit.Message `json:"message"`
}

type descriptorRef struct {
	ID string `json:"id"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	// Version is omitted rather than written empty: cff-1 gives it a minimum
	// length, and SARIF makes it optional, so a run whose generator version is
	// unknown says nothing rather than saying "".
	Version string `json:"version,omitempty"`
	Rules   []rule `json:"rules"`
}

// rule is one tool.driver.rules entry. name, fullDescription, help, helpUri
// and properties are what GitHub code scanning shows on an alert: the rule
// filter, the description beside the result, the help panel, and the tags and
// severity badge. cff-1 leaves SARIF objects open, so they validate there too.
type rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     ctfkit.Message `json:"shortDescription"`
	FullDescription      ctfkit.Message `json:"fullDescription"`
	Help                 ruleHelp       `json:"help"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration ruleConfig     `json:"defaultConfiguration"`
	Properties           ruleProperties `json:"properties"`
}

// ruleHelp is the multiformat help message: GitHub shows markdown when it is
// present and text otherwise.
type ruleHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

// ruleProperties is the rule property bag GitHub code scanning reads.
// SecuritySeverity is a decimal string from 0.1 to 10.0: GitHub labels 7.0 to
// 8.9 high, 4.0 to 6.9 medium and 0.1 to 3.9 low.
type ruleProperties struct {
	Tags             []string `json:"tags"`
	Precision        string   `json:"precision"`
	SecuritySeverity string   `json:"security-severity"`
}

// securitySeverity maps a rule's default level onto the GitHub severity
// badge. The level is the only severity ctfkit has; the scores sit in the
// middle of GitHub's bands so the badge reads high, medium or low.
var securitySeverity = map[string]string{
	ctfkit.LevelError:   "7.5",
	ctfkit.LevelWarning: "5.0",
	ctfkit.LevelNote:    "2.0",
}

// precisionVeryHigh is the precision of every ctfkit rule: the analyzers are
// deterministic reads of the configuration, the plan and the manifests.
const precisionVeryHigh = "very-high"

type ruleConfig struct {
	Level string `json:"level"`
}

type runProperties struct {
	Watermark      string          `json:"ctf.watermark,omitempty"`
	CatalogVersion *catalogVersion `json:"ctf.catalogVersion,omitempty"`
}

// catalogVersion is the run-level record of which catalog was read. Provenance
// is called origin on the wire, the spelling cff-1 froze.
type catalogVersion struct {
	Version string `json:"version"`
	Origin  string `json:"origin"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Kind                string            `json:"kind"`
	Message             ctfkit.Message    `json:"message"`
	Locations           []ctfkit.Location `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          properties        `json:"properties"`
	Suppressions        []suppression     `json:"suppressions,omitempty"`
}

// FingerprintKey names the one partialFingerprints entry ctfkit writes. A
// change to what the hash covers is a new version of the key, never a new
// value under this one.
const FingerprintKey = "ctfkitFindingHash/v1"

// fingerprints gives each finding a stable identity for SARIF consumers such
// as GitHub code scanning, which otherwise key an alert on its line: the
// sha256 of the rule id, the artifact uri, the subject (the address an
// exception names), the sorted control ids and the analyzer's discriminator.
// No line, column or message text goes in, so a block that moves, a count
// that changes or a served build that bumps its version keeps its alert.
// Findings that still share a key, such as two tokens on one module call,
// take an occurrence number in result order, as GitHub's own line hash does.
type fingerprints map[string]int

func (seen fingerprints) next(f ctfkit.Finding) map[string]string {
	controls := make([]string, len(f.Props.ControlIDs))
	for i, c := range f.Props.ControlIDs {
		controls[i] = string(c)
	}
	sort.Strings(controls)
	key := strings.Join([]string{
		f.RuleID, artifactURI(f), f.Subject(), strings.Join(controls, ","), f.Discriminator,
	}, "\x00")
	seen[key]++
	if n := seen[key]; n > 1 {
		key += fmt.Sprintf("\x00%d", n)
	}
	sum := sha256.Sum256([]byte(key))
	return map[string]string{FingerprintKey: hex.EncodeToString(sum[:])}
}

// artifactURI is the first physical location's uri, empty when there is none.
func artifactURI(f ctfkit.Finding) string {
	for _, l := range f.Locations {
		if l.PhysicalLocation != nil {
			return l.PhysicalLocation.ArtifactLocation.URI
		}
	}
	return ""
}

// properties is the ctf.* bag in the key order the report specification (Appendix C)
// freezes. It is written here rather than taken from
// ctfkit.Properties.MarshalJSON, which marshals through a map and so emits the
// keys in alphabetical order, and which has no place for ctf.evidence.
//
// ctf.attributes has no fixture, so its position among the optional keys is
// the one the findings format lists it in and is not frozen.
type properties struct {
	Schema      string                    `json:"ctf.schema"`
	Stage       string                    `json:"ctf.stage"`
	ControlIDs  []ctfkit.ControlID        `json:"ctf.controlIds"`
	Frameworks  []ctfkit.FrameworkClauses `json:"ctf.frameworks"`
	Preventive  bool                      `json:"ctf.preventive"`
	Evidence    *evidence                 `json:"ctf.evidence,omitempty"`
	Remediation *ctfkit.Remediation       `json:"ctf.remediation,omitempty"`
	Attributes  []string                  `json:"ctf.attributes,omitempty"`
	Exception   *ctfkit.ExceptionProperty `json:"ctf.exception,omitempty"`
}

// evidence names the run a finding came out of. It sits on the result rather
// than on the run, which is what cff-1 encodes (ctf.evidence is defined inside
// the result property bag and the run bag has no place for it), what
// the report specification (Appendix C) states, and what all seventeen recorded fixtures
// carry. The findings format carries a later sentence calling it run-level
// only; that sentence was never carried into the schema, the appendix or the
// fixtures, so following it would emit a document the schema refuses and break
// every recorded oracle. Reconciling the prose is the spec owner's call; until
// then the binding artifacts win and this comment is the record of why.
//
// Signature is always nil here and marshals as null: an open source run
// states what it saw and never that anybody vouched for it. The customer's CI
// signs the receipt and an enterprise countersigning service from
// compliance.tf countersigns it; the null is the place that signature would go.
type evidence struct {
	RunID     string  `json:"runId"`
	Commit    string  `json:"commit"`
	Signature *string `json:"signature"`
}

// suppression is the SARIF record of an approved waiver. It sits beside
// ctf.exception rather than replacing it: the property bag says what the
// registry decided, and this is the member a SARIF reader already knows how to
// act on.
type suppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// Render returns the bytes of the SARIF projection: two-space indent, trailing
// newline. It rejects an input that would produce a document the cff-1 schema
// refuses, because this file is read by a security dashboard that reports a
// parse problem to nobody.
func Render(in Input) ([]byte, error) {
	if in.Tool.Name == "" {
		return nil, fmt.Errorf("sarif: the tool driver has no name")
	}
	if err := checkWatermark(in.Watermark); err != nil {
		return nil, err
	}

	results, err := renderResults(in)
	if err != nil {
		return nil, err
	}
	rules, err := firedRules(in)
	if err != nil {
		return nil, err
	}
	catalog, err := renderCatalog(in.Catalog)
	if err != nil {
		return nil, err
	}
	invocations, err := renderInvocations(in.Notifications)
	if err != nil {
		return nil, err
	}

	doc := document{
		Schema:  SchemaURI,
		Version: sarifVersion,
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           in.Tool.Name,
				InformationURI: informationURI,
				Version:        in.Tool.Version,
				Rules:          rules,
			}},
			Invocations: invocations,
			Properties:  runProps(in.Watermark, catalog),
			Results:     results,
		}},
	}

	// HTML escaping is off: a remediation version constraint such as "~> 5.0"
	// is written as the recorded fixtures carry it, not as "~\u003e 5.0". The
	// document is read by SARIF consumers, never embedded in an HTML page.
	// Encode appends the trailing newline.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("sarif: marshal: %w", err)
	}
	return buf.Bytes(), nil
}

// renderResults turns the findings into result objects, checking each one at
// the emit boundary.
func renderResults(in Input) ([]result, error) {
	results := make([]result, 0, len(in.Findings))
	ev := renderEvidence(in.Metadata)
	seen := fingerprints{}

	for _, f := range in.Findings {
		// Finding.Validate is the shape check the SDK defines for exactly this
		// boundary: the rule id, the level and the kind against their frozen
		// sets. It does not look at the message, and the schema wants a
		// non-empty one, so that check stays here.
		if err := f.Validate(); err != nil {
			return nil, fmt.Errorf("sarif: %w", err)
		}
		if f.Message.Text == "" {
			return nil, fmt.Errorf("sarif: finding %q has an empty message", f.RuleID)
		}
		if err := checkAgainstSchema(f); err != nil {
			return nil, err
		}

		results = append(results, result{
			RuleID:              f.RuleID,
			Level:               f.Level,
			Kind:                f.Kind,
			Message:             f.Message,
			Locations:           f.Locations,
			PartialFingerprints: seen.next(f),
			Properties:          renderProperties(f, ev),
			Suppressions:        renderSuppressions(f),
		})
	}
	return results, nil
}

// renderProperties fills the ctf.* bag. The two required lists are emitted
// even when empty, as [] rather than null, so a reader never has to tell an
// absent key from a null one.
func renderProperties(f ctfkit.Finding, ev *evidence) properties {
	p := properties{
		Schema:      f.Props.Schema,
		Stage:       f.Props.Stage.String(),
		ControlIDs:  f.Props.ControlIDs,
		Frameworks:  f.Props.Frameworks,
		Preventive:  f.Props.Preventive,
		Evidence:    ev,
		Remediation: f.Props.Remediation,
		Attributes:  f.Props.Attributes,
		Exception:   f.Props.Exception,
	}
	if p.ControlIDs == nil {
		p.ControlIDs = []ctfkit.ControlID{}
	}
	p.Frameworks = renderFrameworks(f.Props.Frameworks)
	return p
}

// renderFrameworks normalizes the framework list and the clause list inside
// every entry, because cff-1 requires both to be arrays and a nil Go slice
// marshals as null. The entries are copied rather than normalized in place:
// the caller owns the finding, and a renderer that edited it would make the
// output of the next projection depend on which one ran first.
func renderFrameworks(in []ctfkit.FrameworkClauses) []ctfkit.FrameworkClauses {
	out := make([]ctfkit.FrameworkClauses, 0, len(in))
	for _, fw := range in {
		if fw.Clauses == nil {
			fw.Clauses = []string{}
		}
		out = append(out, fw)
	}
	return out
}

// renderEvidence returns the evidence object, or nil when the runner knew
// neither a run id nor a commit. An evidence object with two empty strings
// would claim a provenance nobody recorded.
func renderEvidence(m ctfkit.RunMetadata) *evidence {
	if m.RunID == "" && m.Commit == "" {
		return nil
	}
	return &evidence{RunID: m.RunID, Commit: m.Commit}
}

// renderSuppressions writes the SARIF suppression an allowed waiver earns. An
// expired waiver earns none: it keeps its ctf.exception metadata and still
// counts, which is what makes a lapsed review read differently from nobody
// having looked at it.
//
// The justification is the reason recorded on the registry entry, which
// ctfkit.Decide already copied into the property. The renderer derives the
// suppression rather than taking one as input because the two must agree, and
// a second input is a second place for them to disagree.
func renderSuppressions(f ctfkit.Finding) []suppression {
	// Suppressed implies a non-nil exception, so the property read below is
	// safe once it holds.
	if !f.Suppressed() {
		return nil
	}
	return []suppression{{
		Kind:          suppressionKindExternal,
		Justification: f.Props.Exception.Justification,
	}}
}

// firedRules is tool.driver.rules: one entry per rule id that appears in the
// results, sorted by id, and [] on a clean run. A dashboard reads this list to
// label the results, so listing a rule that did not fire would invent findings
// that are not there.
func firedRules(in Input) ([]rule, error) {
	// A repeated id is rejected rather than resolved by position: two
	// descriptors for one rule mean the emitted shortDescription would be a
	// property of slice order rather than of intent, and a dashboard shows
	// that text beside every result the rule produced.
	byID := make(map[string]RuleDescriptor, len(in.Rules))
	for _, d := range in.Rules {
		if _, ok := byID[d.ID]; ok {
			return nil, fmt.Errorf("sarif: two rule descriptors for %q", d.ID)
		}
		byID[d.ID] = d
	}

	seen := make(map[string]struct{}, len(in.Findings))
	ids := make([]string, 0, len(in.Findings))
	for _, f := range in.Findings {
		if _, ok := seen[f.RuleID]; ok {
			continue
		}
		seen[f.RuleID] = struct{}{}
		ids = append(ids, f.RuleID)
	}
	sort.Strings(ids)

	rules := make([]rule, 0, len(ids))
	for _, id := range ids {
		d, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("sarif: no rule descriptor for %q", id)
		}
		if d.ShortDescription == "" {
			return nil, fmt.Errorf("sarif: rule %q has no short description", id)
		}
		switch d.Level {
		case ctfkit.LevelNote, ctfkit.LevelWarning, ctfkit.LevelError:
		default:
			return nil, fmt.Errorf("sarif: rule %q has default level %q, want one of %s, %s, %s",
				id, d.Level, ctfkit.LevelNote, ctfkit.LevelWarning, ctfkit.LevelError)
		}

		short := ctfkit.Message{Text: d.ShortDescription}
		rules = append(rules, rule{
			ID:                   d.ID,
			Name:                 strings.TrimPrefix(d.ID, "ctf."),
			ShortDescription:     short,
			FullDescription:      short,
			Help:                 renderHelp(d),
			HelpURI:              d.HelpURI,
			DefaultConfiguration: ruleConfig{Level: d.Level},
			Properties: ruleProperties{
				Tags:             ruleTags(d.ID),
				Precision:        precisionVeryHigh,
				SecuritySeverity: securitySeverity[d.Level],
			},
		})
	}
	return rules, nil
}

// ruleTags are the filter tags of a rule: the product, the language and the
// rule family, the second segment of the id (coverage, policy, origin, ...).
func ruleTags(id string) []string {
	tags := []string{"compliance", "terraform"}
	if parts := strings.Split(id, "."); len(parts) > 2 {
		tags = append(tags, parts[1])
	}
	return tags
}

// renderHelp writes the help panel of a rule: what it reports, the rule's own
// help when it has one, how to waive a finding that is intended, and the
// documentation link. Text and markdown say the same; markdown adds the
// exception snippet and the link.
func renderHelp(d RuleDescriptor) ruleHelp {
	short := strings.TrimSuffix(d.ShortDescription, ".")
	text := []string{short + "."}
	md := []string{"**" + short + ".**"}
	if d.Help != "" {
		text = append(text, d.Help)
		md = append(md, d.Help)
	}
	const waiver = "When the finding is intended, record an exception with an approver and a review date " +
		"in the ctfkit exception registry; ctfkit then suppresses it until the review date passes."
	text = append(text, waiver)
	md = append(md, "### When the finding is intended", waiver,
		"```yaml\nexceptions:\n  - rule: "+d.ID+"\n    resource: <address in the finding>\n"+
			"    justification: <why>\n    approved_by: <approver>\n    review_date: \"YYYY-MM-DD\"\n```")
	if d.HelpURI != "" {
		text = append(text, "Documentation: "+d.HelpURI)
		md = append(md, "[ctfkit by compliance.tf: rule reference]("+d.HelpURI+")")
	}
	return ruleHelp{Text: strings.Join(text, " "), Markdown: strings.Join(md, "\n\n")}
}

// checkAgainstSchema holds a finding to the cff-1 constraints that
// ctfkit.Finding.Validate does not reach: the narrower rule id pattern, the
// ctf.schema grammar, and the several strings the schema gives a minimum
// length. Each one is a value the SDK accepts and the schema refuses, so
// without this the renderer would break its own promise to emit nothing a
// reader cannot validate.
//
// It duplicates the schema in Go rather than validating the rendered bytes
// against schema/cff-1.schema.json, because the schema files are not embedded
// in the binary and embedding them is a separate change. The package test
// validates every rendered fixture against the real schema, which is what
// holds the two in step.
func checkAgainstSchema(f ctfkit.Finding) error {
	if !ruleIDPattern.MatchString(f.RuleID) {
		return fmt.Errorf("sarif: rule id %q does not match the published pattern %s", f.RuleID, ruleIDPattern)
	}
	if !schemaVersionPattern.MatchString(f.Props.Schema) {
		return fmt.Errorf("sarif: finding %s has %s %q, which does not match %s",
			f.RuleID, ctfkit.PropertySchema, f.Props.Schema, schemaVersionPattern)
	}
	for _, id := range f.Props.ControlIDs {
		if id == "" {
			return fmt.Errorf("sarif: finding %s carries an empty control id", f.RuleID)
		}
	}
	for _, fw := range f.Props.Frameworks {
		if fw.ID == "" {
			return fmt.Errorf("sarif: finding %s carries a framework with no id", f.RuleID)
		}
		for _, clause := range fw.Clauses {
			if clause == "" {
				return fmt.Errorf("sarif: finding %s carries an empty clause in framework %s", f.RuleID, fw.ID)
			}
		}
		// A supporting clause hedges a clause the entry lists; one that is
		// empty or unlisted would add a mapping nothing made.
		for _, clause := range fw.SupportingClauses {
			if clause == "" || !slices.Contains(fw.Clauses, clause) {
				return fmt.Errorf("sarif: finding %s carries supporting clause %q that framework %s does not list",
					f.RuleID, clause, fw.ID)
			}
		}
	}
	for _, name := range f.Props.Attributes {
		if name == "" {
			return fmt.Errorf("sarif: finding %s carries an empty attribute name", f.RuleID)
		}
	}
	if r := f.Props.Remediation; r != nil && r.ModuleSource == "" {
		return fmt.Errorf("sarif: finding %s carries a remediation with no module source", f.RuleID)
	}
	if e := f.Props.Exception; e != nil && e.TTLSeconds < 0 {
		return fmt.Errorf("sarif: finding %s carries an exception with a negative ttl of %d",
			f.RuleID, e.TTLSeconds)
	}
	return checkLocations(f)
}

// checkLocations holds the location members to the minimum lengths and the
// one-based line and column numbers cff-1 asks for. A location is what sends a
// reader to the offending line, so an empty one is worse than none.
func checkLocations(f ctfkit.Finding) error {
	for _, l := range f.Locations {
		if err := checkPhysicalLocation(f.RuleID, l.PhysicalLocation); err != nil {
			return err
		}
		for _, ll := range l.LogicalLocations {
			if ll.FullyQualifiedName == "" {
				return fmt.Errorf("sarif: finding %s carries a logical location with no name", f.RuleID)
			}
		}
	}
	return nil
}

// checkPhysicalLocation holds the file and the region to what cff-1 allows: a
// non-empty uri, and line and column numbers SARIF counts from one.
func checkPhysicalLocation(ruleID string, p *ctfkit.PhysicalLocation) error {
	if p == nil {
		return nil
	}
	if p.ArtifactLocation.URI == "" {
		return fmt.Errorf("sarif: finding %s carries a location with an empty uri", ruleID)
	}
	if p.Region == nil {
		return nil
	}
	for _, n := range []int{p.Region.StartLine, p.Region.StartColumn, p.Region.EndLine, p.Region.EndColumn} {
		if n < 0 {
			return fmt.Errorf("sarif: finding %s carries a region with a negative position in %s",
				ruleID, p.ArtifactLocation.URI)
		}
	}
	return nil
}

// renderCatalog maps the recorded catalog onto the cff-1 spelling, or nil when
// the run recorded none.
func renderCatalog(c ctfkit.CatalogVersion) (*catalogVersion, error) {
	if c.Version == "" && c.Provenance == "" {
		return nil, nil
	}
	// One field set and the other empty is a caller that recorded half a
	// catalog. Dropping the object would lose what it did record without
	// saying so, and cff-1 requires both members, so it fails here instead.
	if !catalogVersionPattern.MatchString(c.Version) {
		return nil, fmt.Errorf("sarif: catalog version %q is not a semantic version", c.Version)
	}
	switch c.Provenance {
	case originEmbedded, originFile, originHome:
	default:
		return nil, fmt.Errorf("sarif: catalog provenance %q, want one of %s, %s, %s",
			c.Provenance, originEmbedded, originFile, originHome)
	}
	return &catalogVersion{Version: c.Version, Origin: c.Provenance}, nil
}

// runProps is the run-level property bag, or nil when the run has neither a
// banner nor a catalog version, so no empty bag is written.
func runProps(watermark string, catalog *catalogVersion) *runProperties {
	if watermark == "" && catalog == nil {
		return nil
	}
	return &runProperties{Watermark: watermark, CatalogVersion: catalog}
}

// checkWatermark holds the --watermark banner to the one printable line the
// cff-1 schema allows.
func checkWatermark(w string) error {
	if strings.ContainsFunc(w, unicode.IsControl) {
		return fmt.Errorf("sarif: watermark must be one printable line: %q", w)
	}
	return nil
}

// renderInvocations turns the run's notices into the one invocation that
// carries them, or into nothing when there are none. A notice without an id,
// a text or a known level is a caller bug, refused rather than written.
func renderInvocations(ns []Notification) ([]invocation, error) {
	if len(ns) == 0 {
		return nil, nil
	}
	out := make([]notification, 0, len(ns))
	for _, n := range ns {
		if n.DescriptorID == "" {
			return nil, fmt.Errorf("sarif: a run-level notification has no descriptor id")
		}
		switch n.Level {
		case ctfkit.LevelNote, ctfkit.LevelWarning, ctfkit.LevelError:
		default:
			return nil, fmt.Errorf("sarif: notification %s has level %q, want note, warning or error", n.DescriptorID, n.Level)
		}
		if n.Text == "" {
			return nil, fmt.Errorf("sarif: notification %s has no text", n.DescriptorID)
		}
		out = append(out, notification{
			Descriptor: descriptorRef{ID: n.DescriptorID},
			Level:      n.Level,
			Message:    ctfkit.Message{Text: ctfkit.StripUserinfo(n.Text)},
		})
	}
	return []invocation{{ExecutionSuccessful: true, Notifications: out}}, nil
}
