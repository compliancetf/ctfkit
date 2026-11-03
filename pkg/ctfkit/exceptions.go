package ctfkit

import (
	"strings"
	"time"
)

// Exception is an approved, time-bounded waiver, either of one control on one
// resource or of one rule id on one resource. It is advisory: the registry
// says which entry covers a finding and whether that entry is valid, and the
// runner records both. Approval workflow and enforcement live above the SDK,
// and approval strings are recorded metadata, never authenticated here.
type Exception struct {
	// ID identifies the exception in the registry it came from.
	ID string
	// ControlID is the control being waived. It is set on a control-level
	// entry and empty on a rule-level one; exactly one of ControlID and RuleID
	// is set.
	ControlID ControlID
	// RuleID is the rule id being waived. It is how a finding that carries no
	// control id, such as a module coverage or floating reference finding, is
	// waived at all, because a control entry can never cover one. Rule ids are
	// stage independent, so one entry waives a rule at every stage it runs at.
	RuleID string
	// Resource is the resource address the waiver covers, for example
	// "aws_s3_bucket.logs". An empty value means the waiver is not scoped to a
	// single resource.
	Resource string
	// Justification is why the waiver was granted. It is copied into the
	// suppression the runner writes.
	Justification string
	// Approvers are the identities that approved it.
	Approvers []string
	// ExpiresAt is the review date the entry carries, as a UTC date. The
	// waiver is in force through 23:59:59Z of that day, so a review date of
	// today is still valid today. A zero time means the registry stated no
	// review date, which IsValid treats as invalid: an open ended waiver is
	// not evidence.
	ExpiresAt time.Time
}

// ExceptionRegistry answers which approved waiver covers a finding.
//
// It is not part of AnalyzerInput and an analyzer never sees it. An analyzer
// reports what it found; the runner asks Decide afterwards, marks the finding
// with WithException and writes the SARIF suppressions entry. Keeping the two
// apart is what lets a suppressed finding stay in every projection instead of
// vanishing from the record, and it keeps the decision to suppress in one
// place rather than in every analyzer.
//
// An implementation is a preloaded, immutable snapshot: read-only, safe for
// concurrent use, and fetching nothing. It reads the system clock nowhere; the
// run clock is an argument, so pass RunMetadata.Now.
//
// A lookup prefers a valid entry but never hides an invalid one. Where a scope
// has entries, the first valid at now is returned; where none is valid, the
// first entry is returned anyway, so the runner can report an expired waiver
// as an expired waiver rather than as no waiver at all.
//
// What a file-backed implementation owes its loader, stated here because the
// behavior is part of the contract rather than of the file format: a duplicate
// (control or rule, resource) pair is rejected, since two entries for one
// scope make "the first" a property of file order rather than of intent; a
// missing file is an empty registry, not an error, because having no
// exceptions is the normal case; and a malformed file is an error the command
// reports as an environment failure, never an empty registry, so a typo can
// never silently widen what is allowed.
//
// The interface is sealed until 1.0: an implementation embeds
// ExceptionRegistrySeal to declare that it accepts a contract which may still
// gain methods.
type ExceptionRegistry interface {
	// Match returns the control-level entry covering control on resource: the
	// first valid at now, or the first entry of that scope when none is valid.
	// The second result is false when no entry covers the scope at all.
	Match(control ControlID, resource string, now time.Time) (Exception, bool)

	// MatchRule returns the rule-level entry covering ruleID on resource, by
	// the same rule as Match. It is the only way to waive a finding that
	// carries no control id; a control entry never covers one. Rule ids are
	// stage independent, so no stage is passed.
	MatchRule(ruleID, resource string, now time.Time) (Exception, bool)

	// IsValid reports whether e is in force at now: it has the approvals this
	// registry requires, and its review date has not passed. The review date
	// is a UTC date and the entry is in force through 23:59:59Z of that day,
	// so an entry reviewed today is valid for the whole of today.
	IsValid(e Exception, now time.Time) bool

	sealedExceptions()
}

// UnresolvedModule is the address segment an analyzer puts where it could
// not follow a local module call to the directory it reads, as in
// "module.app.<unresolved>.terraform_data.x".
//
// Additive constant, v0.x.
const UnresolvedModule = "<unresolved>"

// Decide is the exception decision, in one place so that every adapter reaches
// the same verdict from the same registry. The runner calls it after an
// analyzer returns and passes the result to WithException.
//
// A finding is suppressed only when every control id it carries is covered by
// a valid entry. A finding that carries no control id is looked up by its rule
// id instead, which is the only waiver that can reach it.
//
// The three outcomes:
//
//	no entry covers some id     (nil, false)   no waiver, nothing to record
//	every id covered, one stale (&{...}, false) the waiver is recorded and the
//	                                            finding still counts
//	every id covered and valid  (&{...}, true)  the runner suppresses it
//
// The middle case is the one worth keeping: an expired waiver is evidence that
// somebody meant to allow this and let the review lapse, which reads
// differently from nobody having looked at it.
//
// A finding whose subject holds UnresolvedModule is never waived.
func Decide(f Finding, reg ExceptionRegistry, now time.Time) (*ExceptionProperty, bool) {
	// An address with UnresolvedModule in it says where a block runs only up
	// to a module call that could not be followed, so no waiver covers it.
	if reg == nil || strings.Contains(f.Subject(), UnresolvedModule) {
		return nil, false
	}

	matched := make([]Exception, 0, len(f.Props.ControlIDs)+1)
	if len(f.Props.ControlIDs) == 0 {
		e, ok := reg.MatchRule(f.RuleID, f.Subject(), now)
		if !ok {
			return nil, false
		}
		matched = append(matched, e)
	}
	for _, id := range f.Props.ControlIDs {
		e, ok := reg.Match(id, f.Subject(), now)
		if !ok {
			return nil, false
		}
		matched = append(matched, e)
	}

	for _, e := range matched {
		if !reg.IsValid(e, now) {
			p := exceptionProperty(e, now)
			p.Allowed = false
			return &p, false
		}
	}

	p := exceptionProperty(matched[0], now)
	p.Allowed = true
	return &p, true
}

// exceptionProperty renders an entry as the property a finding carries.
func exceptionProperty(e Exception, now time.Time) ExceptionProperty {
	return ExceptionProperty{
		EntryID:               e.ID,
		Justification:         e.Justification,
		TTLSeconds:            ttlSeconds(e, now),
		RequiresJustification: e.Justification == "",
	}
}

// ttlSeconds is how long the waiver still has to run: the seconds from now to
// the end of its review date, and zero once that has passed or when the entry
// carries no review date at all.
func ttlSeconds(e Exception, now time.Time) int64 {
	if e.ExpiresAt.IsZero() {
		return 0
	}
	d := e.ExpiresAt.UTC()
	endOfDay := time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 0, time.UTC)
	remaining := endOfDay.Sub(now.UTC())
	if remaining < 0 {
		return 0
	}
	return int64(remaining.Seconds())
}

// ExceptionRegistrySeal is embedded by an ExceptionRegistry implementation to
// satisfy the seal. Embedding it is the implementer's acknowledgment that the
// interface may gain methods before 1.0.
type ExceptionRegistrySeal struct{}

// sealedExceptions is the seal itself. Implementations outside this package
// embed ExceptionRegistrySeal to satisfy ExceptionRegistry, which no analysis
// of this package alone can observe, so it reads as unused here. See doc.go,
// "Sealed interfaces".
//
//nolint:unused // seal marker, see doc.go
func (ExceptionRegistrySeal) sealedExceptions() {}
