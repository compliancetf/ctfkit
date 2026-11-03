package ctfkit

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Findings is the ordered list an analyzer returns. Order is the analyzer's
// own; the runner sorts across analyzers before rendering.
type Findings []Finding

// Finding mirrors one result object of the compliance.tf findings format,
// which is SARIF 2.1.0 plus a ctf.* property bag. It marshals straight to that
// result object, property bag included.
//
// Analyzers build a Finding through NewFinding and treat it as read only
// afterwards. What a Finding may carry is a trust boundary, not a style rule:
// NewFinding accepts locations (uri, line), resource addresses and attribute
// names, and rejects attribute values, so no secret can reach a renderer;
// message templates are analyzer constants. Every projection is written to a
// file a CI system keeps, and a plan value may be a secret.
type Finding struct {
	// RuleID is the id of the analyzer that produced this finding.
	RuleID string
	// Level is the SARIF level: note, warning or error. A compliance failure
	// is LevelError; it is never a returned Go error.
	Level string
	// Kind is the SARIF kind: pass, fail, open or review.
	Kind string
	// Message is the text shown to a reader.
	Message Message
	// Locations are where the finding applies, empty when it is about the run
	// as a whole.
	Locations []Location
	// Props is the ctf.* bag as typed fields. It marshals to the property
	// names the findings format freezes.
	Props Properties
	// Discriminator tells apart two findings of one rule that share their
	// file, subject and controls, for example one per served module build.
	// It must be stable across runs: a module source without its version, an
	// obligation token, never message text, a count or a version. It feeds
	// the SARIF fingerprint only and is never written to any projection.
	// ValidateFor strips URL userinfo from it. Optional; most analyzers leave
	// it empty.
	Discriminator string
}

// SARIF levels used by Finding.Level.
const (
	// LevelNote is informational.
	LevelNote = "note"
	// LevelWarning is a problem that does not fail the run by default.
	LevelWarning = "warning"
	// LevelError is a compliance failure.
	LevelError = "error"
)

// SARIF kinds used by Finding.Kind.
const (
	// KindPass records that a check ran and the subject satisfied it.
	KindPass = "pass"
	// KindFail records that a check ran and the subject did not satisfy it.
	KindFail = "fail"
	// KindOpen records that the check could not decide.
	KindOpen = "open"
	// KindReview records that a human must decide.
	KindReview = "review"
)

// Property keys of the ctf.* bag. They are frozen by the findings format;
// nothing here renames one. Renderers use these constants rather than their
// own string literals.
const (
	// PropertySchema is the findings format version, "1.0" at launch.
	PropertySchema = "ctf.schema"
	// PropertyControlIDs holds the affected control ids. It is always present
	// and may be an empty list.
	PropertyControlIDs = "ctf.controlIds"
	// PropertyFrameworks holds the framework mappings, each an object with an
	// id and its clauses. An empty list means framework agnostic.
	PropertyFrameworks = "ctf.frameworks"
	// PropertyPreventive is true when a compliance.tf module would have
	// prevented this finding at source.
	PropertyPreventive = "ctf.preventive"
	// PropertyStage is the Stage the finding was produced at.
	PropertyStage = "ctf.stage"
	// PropertyAttributes holds the resource attribute names the finding is
	// about. Names only; a value never appears here.
	PropertyAttributes = "ctf.attributes"
	// PropertyRemediation points at the preventive fix, when one exists.
	PropertyRemediation = "ctf.remediation"
	// PropertyException carries exception metadata, advisory at this level.
	PropertyException = "ctf.exception"
	// PropertyEvidence carries the run identity for the evidence receipt. It
	// is a run-level property; no finding carries it.
	PropertyEvidence = "ctf.evidence"
	// PropertyWatermark is the SARIF run property that carries the optional
	// --watermark banner line. It is absent when no banner was set.
	PropertyWatermark = "ctf.watermark"
)

// Properties is the ctf.* bag of a finding as typed fields rather than a bare
// map, so a missing required key is a compile-time absence instead of a
// runtime surprise. Schema, Stage, ControlIDs, Frameworks and Preventive are
// always marshaled; the rest appear only when set.
//
// The struct is closed: there is no escape hatch for an unmodeled key. A bag
// that anything could add to is a bag no reader can rely on, and a key worth
// emitting is worth naming in the findings format first and adding here
// second. Build one with keyed fields, never with an unkeyed literal, so that
// a new field does not break the call site.
type Properties struct {
	// Schema is the findings format version, "1.0" at launch.
	Schema string
	// Stage is the stage the finding was produced at.
	Stage Stage
	// ControlIDs are the controls this finding is about, sorted by
	// NewFinding. It is marshaled even when empty, which is how a coverage or
	// origin finding that maps to no single control is expressed.
	ControlIDs []ControlID
	// Frameworks are the framework clauses the controls satisfy, sorted by
	// NewFinding. Empty means framework agnostic.
	Frameworks []FrameworkClauses
	// Preventive is true when a compliance.tf module would have prevented this
	// finding at source.
	Preventive bool
	// Attributes are the resource attribute names the finding is about, sorted
	// by NewFinding. Names only; an attribute value never appears in a
	// finding.
	Attributes []string
	// Remediation names the module that would have prevented the finding, nil
	// when the catalog names none.
	Remediation *Remediation
	// Exception carries what the exception registry said about this finding.
	// An analyzer leaves it nil and NewFinding rejects it when set: only the
	// runner decides that a waiver applies, and it says so with WithException.
	Exception *ExceptionProperty
}

// FrameworkClauses is one entry of the ctf.frameworks list: a framework id in
// the catalog spelling, for example "pci_dss_v40", and the clauses satisfied in
// it.
type FrameworkClauses struct {
	// ID is the framework id.
	ID string `json:"id"`
	// Clauses are the clause identifiers, sorted by NewFinding.
	Clauses []string `json:"clauses"`
	// SupportingClauses are the Clauses a schema 3.4 manifest marked as
	// supporting evidence only, never full enforcement, sorted by NewFinding.
	// Nil (omitted) means unknown: the source does not classify. An empty
	// non-nil list means it classified and hedged nothing. Every entry must
	// be non-empty and listed in Clauses; the SARIF renderer refuses a
	// finding that breaks either rule.
	SupportingClauses []string `json:"supportingClauses,omitzero"`
}

// Remediation is the ctf.remediation object: the compliance.tf module that
// would have prevented the finding.
type Remediation struct {
	// ModuleSource is the module source with the host label already
	// substituted. It is the only sales touchpoint in the output: inform,
	// never sell.
	ModuleSource string `json:"moduleSource"`
	// Version is the version constraint to write alongside the source.
	Version string `json:"version,omitempty"`
}

// ExceptionProperty is the ctf.exception object. It is advisory at this level;
// the suppression a reader acts on is the SARIF suppressions entry the runner
// writes beside it.
type ExceptionProperty struct {
	// Allowed is true when a valid exception covered the finding. False with
	// the rest of the fields set is the expired waiver: somebody allowed this
	// and let the review lapse, which reads differently from nobody having
	// looked at it.
	Allowed bool `json:"allowed"`
	// EntryID names the registry entry the verdict came from, so a reader can
	// find it without guessing which entry matched.
	EntryID string `json:"entryId,omitempty"`
	// Justification is the reason recorded on that entry. It is metadata, not
	// an authenticated approval.
	Justification string `json:"justification,omitempty"`
	// TTLSeconds is how long the waiver still has to run, zero once its review
	// date has passed.
	TTLSeconds int64 `json:"ttlSeconds,omitempty"`
	// RequiresJustification records that the entry carries no reason and the
	// registry wants one.
	RequiresJustification bool `json:"requiresJustification,omitempty"`
}

// MarshalJSON writes the ctf.* property bag. The required keys are always
// present and empty lists marshal as [] rather than null, so a reader never
// has to tell an absent key from a null one.
func (p Properties) MarshalJSON() ([]byte, error) {
	bag := make(map[string]any, 8)

	controls := p.ControlIDs
	if controls == nil {
		controls = []ControlID{}
	}
	frameworks := p.Frameworks
	if frameworks == nil {
		frameworks = []FrameworkClauses{}
	}

	bag[PropertySchema] = p.Schema
	bag[PropertyStage] = string(p.Stage)
	bag[PropertyControlIDs] = controls
	bag[PropertyFrameworks] = frameworks
	bag[PropertyPreventive] = p.Preventive
	if len(p.Attributes) > 0 {
		bag[PropertyAttributes] = p.Attributes
	}
	if p.Remediation != nil {
		bag[PropertyRemediation] = p.Remediation
	}
	if p.Exception != nil {
		bag[PropertyException] = p.Exception
	}
	return json.Marshal(bag)
}

// findingJSON is the SARIF result object a Finding marshals to.
type findingJSON struct {
	RuleID     string     `json:"ruleId"`
	Level      string     `json:"level"`
	Kind       string     `json:"kind"`
	Message    Message    `json:"message"`
	Locations  []Location `json:"locations,omitempty"`
	Properties Properties `json:"properties"`
}

// MarshalJSON writes the SARIF result object, property bag included.
func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(findingJSON{
		RuleID:     f.RuleID,
		Level:      f.Level,
		Kind:       f.Kind,
		Message:    f.Message,
		Locations:  f.Locations,
		Properties: f.Props,
	})
}

// Validate reports whether the finding can be emitted as conformant output:
// the rule id matches the frozen format, the level and kind are inside their
// frozen sets, the schema version is set, and the stage is one of the five. It
// is the shape check a renderer makes at the emit boundary, and NewFinding
// makes it for every finding it builds. ValidateFor is the stricter check the
// runner makes when it takes a finding from an analyzer.
func (f Finding) Validate() error {
	if !RuleIDPattern.MatchString(f.RuleID) {
		return fmt.Errorf("ctfkit: rule id %q does not match %s", f.RuleID, RuleIDPattern)
	}
	switch f.Level {
	case LevelNote, LevelWarning, LevelError:
	default:
		return fmt.Errorf("ctfkit: finding %s has level %q, want one of %s, %s, %s",
			f.RuleID, f.Level, LevelNote, LevelWarning, LevelError)
	}
	switch f.Kind {
	case KindPass, KindFail, KindOpen, KindReview:
	default:
		return fmt.Errorf("ctfkit: finding %s has kind %q, want one of %s, %s, %s, %s",
			f.RuleID, f.Kind, KindPass, KindFail, KindOpen, KindReview)
	}
	if f.Props.Schema == "" {
		return fmt.Errorf("ctfkit: finding %s has no %s", f.RuleID, PropertySchema)
	}
	if f.Props.Stage.Rank() < 0 {
		return fmt.Errorf("ctfkit: finding %s has %s %q, which is not a known stage",
			f.RuleID, PropertyStage, f.Props.Stage)
	}
	return nil
}

// ValidateFor is the check the runner makes before it accepts a finding from
// an analyzer, and it returns the finding the runner should keep.
//
// It checks everything Validate checks, plus the four things only the runner
// can see. The rule id must be the id of the analyzer that produced it, so one
// analyzer cannot emit findings under another's id and escape its exceptions
// and its taxonomy entry. The stage property must be the stage the invocation
// ran at, so a finding cannot claim to come from a stage that did not run. The
// exception property must be unset, because an analyzer does not decide that a
// waiver applies; Decide and WithException do. And every control id must exist
// in the catalog, so a typo cannot reach a report as a control nobody can look
// up.
//
// The returned copy is sanitized: the userinfo strip runs again over every
// string the finding holds. NewFinding already strips, so this only changes a
// Finding assembled by struct literal, which is the path that bypasses every
// other guarantee here. The runner keeps the returned value and discards the
// one it was given.
func (f Finding) ValidateFor(analyzerID string, stage Stage, cat ControlCatalog) (Finding, error) {
	if err := f.Validate(); err != nil {
		return Finding{}, err
	}
	if f.RuleID != analyzerID {
		return Finding{}, fmt.Errorf("ctfkit: analyzer %s emitted a finding with rule id %s",
			analyzerID, f.RuleID)
	}
	if f.Props.Stage != stage {
		return Finding{}, fmt.Errorf("ctfkit: analyzer %s ran at stage %s but its finding says %s",
			analyzerID, stage, f.Props.Stage)
	}
	if f.Props.Exception != nil {
		return Finding{}, fmt.Errorf(
			"ctfkit: analyzer %s set %s; only the runner does that, through WithException",
			analyzerID, PropertyException)
	}
	if cat == nil {
		return Finding{}, fmt.Errorf("ctfkit: finding %s cannot be checked without a catalog", f.RuleID)
	}
	for _, id := range f.Props.ControlIDs {
		if _, ok := cat.Control(id); !ok {
			return Finding{}, fmt.Errorf("ctfkit: finding %s names control %s, which the catalog %s does not hold",
				f.RuleID, id, cat.Version().Version)
		}
	}

	out := f
	out.Message = Message{Text: StripUserinfo(f.Message.Text)}
	// An analyzer sets the discriminator after NewFinding, so this is the one
	// strip it gets: a module source with a token then neither carries the
	// token into the fingerprint nor changes it when the token rotates.
	out.Discriminator = StripUserinfo(f.Discriminator)
	out.Props = cloneProperties(f.Props)
	if len(f.Locations) > 0 {
		out.Locations = make([]Location, 0, len(f.Locations))
		for _, l := range f.Locations {
			out.Locations = append(out.Locations, cloneLocation(l))
		}
	}
	return out, nil
}

// Subject returns what the finding is about: the fully qualified name of its
// first logical location of kind "resource"; failing that, of kind "module";
// failing that, of kind "provider"; failing that, of the first logical location
// of any kind. It is empty only for a finding with no logical location at all,
// one about a file or about the run as a whole. It is what an exception lookup
// is keyed on and what the stable finding order falls back to.
//
// Each fallback exists because some finding names nothing more specific, and
// without it every such finding in a configuration would share the empty
// subject and be indistinguishable to an exception. A coverage finding names a
// module call and no resource. An origin.provider finding at post_plan names
// only a provider instance. The last fallback keeps a kind the SDK has no
// constant for from being unreachable the same way.
func (f Finding) Subject() string {
	var module, provider, other string
	for _, l := range f.Locations {
		for _, ll := range l.LogicalLocations {
			switch ll.Kind {
			case LogicalLocationResource:
				return ll.FullyQualifiedName
			case LogicalLocationModule:
				if module == "" {
					module = ll.FullyQualifiedName
				}
			case LogicalLocationProvider:
				if provider == "" {
					provider = ll.FullyQualifiedName
				}
			default:
				if other == "" {
					other = ll.FullyQualifiedName
				}
			}
		}
	}
	switch {
	case module != "":
		return module
	case provider != "":
		return provider
	default:
		return other
	}
}

// Suppressed reports whether an allowed exception waives f. It is the one
// definition of a waived finding: the verdict of every projection, the exit
// code and each renderer's waiver handling all ask it rather than reading the
// exception property themselves.
//
// An exception found but out of its review window is recorded with Allowed
// false. It stays on the finding so a reader sees the lapse, and it waives
// nothing, so Suppressed is false for it. The level plays no part.
//
// A suppressed finding is still reported; what a waiver buys is that it stops
// driving the verdict and the exit code.
func (f Finding) Suppressed() bool {
	return f.Props.Exception != nil && f.Props.Exception.Allowed
}

// WithException returns a copy of f carrying what the exception registry said
// about it. It is the runner's move and the only way the property is set: an
// analyzer reports what it found and never decides that a waiver applies.
func WithException(f Finding, e ExceptionProperty) Finding {
	out := f
	out.Props = cloneProperties(f.Props)
	out.Props.Exception = &e
	out.Locations = make([]Location, 0, len(f.Locations))
	for _, l := range f.Locations {
		out.Locations = append(out.Locations, cloneLocation(l))
	}
	if len(out.Locations) == 0 {
		out.Locations = nil
	}
	return out
}

// NewFinding builds a Finding and is the only supported way to make one.
//
// It accepts locations (uri, line), resource addresses and attribute names,
// and rejects attribute values. The message text a caller passes is an
// analyzer constant, optionally formatted with those same names, never with a
// value read from a plan or a configuration. That rule is what the
// secret-canary conformance fixture proves; this constructor cannot inspect
// the provenance of the text it is handed, so it enforces the parts that are
// structural: it calls Validate, it strips URL userinfo from every string it
// stores, and it sorts the parts whose order would otherwise vary between runs
// over the same input.
//
// Everything passed in is copied, so a later change to the caller's slices or
// maps does not reach the returned Finding.
func NewFinding(ruleID, level, kind string, msg Message, locs []Location, p Properties) (Finding, error) {
	f := Finding{
		RuleID:  ruleID,
		Level:   level,
		Kind:    kind,
		Message: Message{Text: StripUserinfo(msg.Text)},
		Props:   cloneProperties(p),
	}
	if p.Exception != nil {
		return Finding{}, fmt.Errorf(
			"ctfkit: analyzer %s set %s; only the runner does that, through WithException",
			ruleID, PropertyException)
	}
	if err := f.Validate(); err != nil {
		return Finding{}, err
	}

	if len(locs) > 0 {
		f.Locations = make([]Location, 0, len(locs))
		for _, l := range locs {
			f.Locations = append(f.Locations, cloneLocation(l))
		}
		sortLocations(f.Locations)
	}
	return f, nil
}

// cloneProperties copies a Properties value, sorts every list whose order is
// not meaningful, and strips userinfo from the strings it stores.
func cloneProperties(p Properties) Properties {
	out := Properties{
		Schema:     p.Schema,
		Stage:      p.Stage,
		Preventive: p.Preventive,
	}

	if p.ControlIDs != nil {
		out.ControlIDs = make([]ControlID, len(p.ControlIDs))
		copy(out.ControlIDs, p.ControlIDs)
		sort.Slice(out.ControlIDs, func(i, j int) bool { return out.ControlIDs[i] < out.ControlIDs[j] })
	}
	if p.Frameworks != nil {
		out.Frameworks = make([]FrameworkClauses, 0, len(p.Frameworks))
		for _, fw := range p.Frameworks {
			clauses := make([]string, len(fw.Clauses))
			copy(clauses, fw.Clauses)
			sort.Strings(clauses)
			var supporting []string
			if fw.SupportingClauses != nil {
				supporting = make([]string, len(fw.SupportingClauses))
				copy(supporting, fw.SupportingClauses)
				sort.Strings(supporting)
			}
			out.Frameworks = append(out.Frameworks, FrameworkClauses{ID: fw.ID, Clauses: clauses, SupportingClauses: supporting})
		}
		sort.Slice(out.Frameworks, func(i, j int) bool { return out.Frameworks[i].ID < out.Frameworks[j].ID })
	}
	if p.Attributes != nil {
		out.Attributes = make([]string, len(p.Attributes))
		copy(out.Attributes, p.Attributes)
		sort.Strings(out.Attributes)
	}
	if p.Remediation != nil {
		r := *p.Remediation
		r.ModuleSource = StripUserinfo(r.ModuleSource)
		out.Remediation = &r
	}
	if p.Exception != nil {
		e := *p.Exception
		out.Exception = &e
	}
	return out
}

// cloneLocation copies a Location down to its pointers, so two findings never
// share a location and a caller cannot reach into one it already handed over.
// It strips userinfo from every logical name, and passes the uri through
// RedactPath: a file in a module directory is named after the source that
// called it, so its path can carry the same userinfo and query a source can.
// Every finding of every analyzer reaches output through here.
func cloneLocation(l Location) Location {
	out := Location{}
	if l.PhysicalLocation != nil {
		pl := *l.PhysicalLocation
		pl.ArtifactLocation.URI = RedactPath(pl.ArtifactLocation.URI)
		if l.PhysicalLocation.Region != nil {
			region := *l.PhysicalLocation.Region
			pl.Region = &region
		}
		out.PhysicalLocation = &pl
	}
	if len(l.LogicalLocations) > 0 {
		out.LogicalLocations = make([]LogicalLocation, 0, len(l.LogicalLocations))
		for _, ll := range l.LogicalLocations {
			ll.FullyQualifiedName = StripUserinfo(ll.FullyQualifiedName)
			out.LogicalLocations = append(out.LogicalLocations, ll)
		}
	}
	return out
}

// sortLocations orders locations by uri, then start line, then the first
// logical name, so two runs over the same input emit them in the same order.
func sortLocations(locs []Location) {
	sort.SliceStable(locs, func(i, j int) bool {
		ui, uj := locationURI(locs[i]), locationURI(locs[j])
		if ui != uj {
			return ui < uj
		}
		li, lj := locationLine(locs[i]), locationLine(locs[j])
		if li != lj {
			return li < lj
		}
		return locationName(locs[i]) < locationName(locs[j])
	})
}

func locationURI(l Location) string {
	if l.PhysicalLocation == nil {
		return ""
	}
	return l.PhysicalLocation.ArtifactLocation.URI
}

func locationLine(l Location) int {
	if l.PhysicalLocation == nil || l.PhysicalLocation.Region == nil {
		return 0
	}
	return l.PhysicalLocation.Region.StartLine
}

func locationName(l Location) string {
	if len(l.LogicalLocations) == 0 {
		return ""
	}
	return l.LogicalLocations[0].FullyQualifiedName
}

// userinfoPattern matches the userinfo of a URL: whatever sits between a
// scheme's "://" and the "@" that ends the credentials. It cannot cross a
// slash, so an "@" inside a path is left alone.
var userinfoPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@`)

// StripUserinfo removes the credentials from every URL in s, wherever the URL
// sits: a bare "https://user:token@host/path", a Terraform module source with
// a forced getter such as "git::https://user:token@host/repo.git",
// "hg::https://..." or "s3::https://...", and a URL embedded in a sentence.
// Everything else is returned unchanged.
//
// A module source is repository text, and repository text reaches a finding
// through a location uri and a message. It is the one place a credential can
// arrive without anyone having read a plan value, which is why the constructor
// runs this over every string it stores rather than trusting the caller.
//
// The scp-style Git form "git@host:org/repo.git" carries a user name, not a
// credential, and has no "://", so it is left as it stands.
func StripUserinfo(s string) string {
	if s == "" {
		return s
	}
	return userinfoPattern.ReplaceAllString(s, "$1")
}

// sourceUserinfoAfter matches userinfo after a scheme's "://" or a forced
// getter's "::"; sourceUserinfoLeading matches it at the start of a source
// with neither, as "user@host" or "user:token@host". Neither crosses a slash,
// and the leading form takes at most one colon so it never swallows a "::"
// getter prefix.
var (
	sourceUserinfoAfter   = regexp.MustCompile(`(://|::)[^/@\s]*@`)
	sourceUserinfoLeading = regexp.MustCompile(`^[^/@\s:]*(:[^/@\s:]*)?@`)
)

// RedactSource returns a module source as a finding may quote it: with its
// query removed, since a getter argument such as sshkey= can carry a private
// key, and with any userinfo removed, since it can carry a token. What is left
// says where the module comes from and nothing it was fetched with. Unlike
// StripUserinfo it also drops the user of a scheme-less "user@host" form,
// because a source is the subject here and its user adds nothing to it.
//
// It is the one helper every analyzer, loader diagnostic and projection calls
// for a module source it quotes, so output can name a module's origin without
// repeating anything that was used to fetch it.
//
// A source it cannot read as a module address returns UnparsedSource instead
// of any of its text: one where an "@" survives the redaction (userinfo in a
// place no form above has), or that holds whitespace, a control character or
// invalid UTF-8, read as written or fully percent-decoded (so "%40" and
// "%2540" are an "@" and "%3F" a "?"), and one with a malformed escape.
//
// Additive function, v0.x.
func RedactSource(source string) string {
	return redact(source, false)
}

// RedactPath applies the redaction of RedactSource to each "/"-separated
// component of p, so a path or source whose components carry credentials
// keeps the rest: the directory "../user:token@shared?sshkey=k/main.tf"
// becomes "../shared/main.tf" and "git::https://user:token@host/repo?ref=v1"
// becomes "git::https://host/repo". It is the redaction for a module
// directory or file path, which a module source names.
//
// A component becomes UnparsedSource, and nothing of it survives, when it
// still holds an "@" or a "?", a control character or invalid UTF-8, or a
// "/" or a backslash, in its text or once fully percent-decoded (so "%40",
// "%2540" and "%2F" count), or when an escape is malformed. Whitespace alone
// does not: a directory named "my module" keeps its name.
//
// Additive function, v0.x.
func RedactPath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = redact(part, true)
	}
	return strings.Join(parts, "/")
}

// redact is RedactSource, or with component set, the redaction of one
// RedactPath component.
func redact(s string, component bool) string {
	s, _, _ = strings.Cut(s, "?")
	s = sourceUserinfoAfter.ReplaceAllString(s, "$1")
	s = sourceUserinfoLeading.ReplaceAllString(s, "")
	// Checked again fully decoded, so an encoded "@" or "?" cannot carry
	// userinfo or a query past the cuts above.
	decoded, ok := decodeAll(s)
	if !ok || !readable(s, component) || !readable(decoded, component) ||
		component && strings.ContainsAny(decoded, `/\`) {
		return UnparsedSource
	}
	return s
}

// maxDecodes bounds decodeAll; a string still changing after that many
// rounds is refused.
const maxDecodes = 8

// decodeAll percent-decodes s until it stops changing, so a double-encoded
// "%2540" is read as "@". It reports false for a malformed escape.
func decodeAll(s string) (string, bool) {
	for range maxDecodes {
		d, err := url.PathUnescape(s)
		if err != nil {
			return "", false
		}
		if d == s {
			return s, true
		}
		s = d
	}
	return "", false
}

// readable reports whether s, after redaction, holds nothing redact refuses:
// invalid UTF-8, an "@", a "?" or a control character, and for a source,
// whitespace.
func readable(s string, component bool) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return r == '@' || r == '?' || unicode.IsControl(r) || !component && unicode.IsSpace(r)
	})
}

// UnparsedSource is what RedactSource returns for a source it cannot read as
// a module address.
//
// Additive constant, v0.x.
const UnparsedSource = "<unparsed module source>"

// Message is the SARIF message object.
type Message struct {
	// Text is the message, one sentence, no trailing newline.
	Text string `json:"text"`
}

// Location is the SARIF location object, reduced to the members ctfkit emits.
type Location struct {
	// PhysicalLocation is the file and line the finding points at.
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	// LogicalLocations name the addresses in the configuration, for example a
	// resource address.
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation is a file and a region within it.
type PhysicalLocation struct {
	// ArtifactLocation is the file.
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	// Region is the position within the file, omitted when unknown.
	Region *Region `json:"region,omitempty"`
}

// ArtifactLocation names a file.
type ArtifactLocation struct {
	// URI is the path relative to the analysis root, POSIX separated.
	URI string `json:"uri"`
}

// Region is a position within a file. SARIF counts from 1.
type Region struct {
	// StartLine is the first line of the region.
	StartLine int `json:"startLine,omitempty"`
	// StartColumn is the first column of the region.
	StartColumn int `json:"startColumn,omitempty"`
	// EndLine is the last line of the region.
	EndLine int `json:"endLine,omitempty"`
	// EndColumn is the last column of the region.
	EndColumn int `json:"endColumn,omitempty"`
}

// Kinds used by LogicalLocation.Kind.
const (
	// LogicalLocationResource names a resource address, which is what
	// Finding.Subject looks for.
	LogicalLocationResource = "resource"
	// LogicalLocationModule names a module call address.
	LogicalLocationModule = "module"
	// LogicalLocationProvider names a provider address.
	LogicalLocationProvider = "provider"
)

// LogicalLocation names an address in the configuration rather than a file.
type LogicalLocation struct {
	// FullyQualifiedName is the address, for example "aws_s3_bucket.logs".
	FullyQualifiedName string `json:"fullyQualifiedName"`
	// Kind is what the address names, for example "resource" or "module".
	Kind string `json:"kind,omitempty"`
}
