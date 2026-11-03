package ctfkit_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

var runClock = time.Date(2026, time.September, 20, 12, 0, 0, 0, time.UTC)

// A lookup prefers a valid entry but never hides an invalid one, which is what
// lets the runner report an expired waiver as expired.
func TestMatchPrefersAValidEntryAndStillReturnsAStaleOne(t *testing.T) {
	registry := fakeExceptions{entries: []ctfkit.Exception{
		{
			ID: "exc-stale", ControlID: "s3_bucket_versioning_enabled",
			Resource: "aws_s3_bucket.logs", ExpiresAt: runClock.AddDate(0, 0, -1),
		},
		{
			ID: "exc-live", RuleID: "ctf.coverage.module_source",
			Resource: "aws_s3_bucket.logs", ExpiresAt: runClock.AddDate(0, 0, 30),
		},
	}}

	stale, ok := registry.Match("s3_bucket_versioning_enabled", "aws_s3_bucket.logs", runClock)
	if !ok {
		t.Fatal("Match did not return the expired entry; an expired waiver must still be reportable")
	}
	if registry.IsValid(stale, runClock) {
		t.Error("IsValid accepted an entry whose review date was yesterday")
	}

	live, ok := registry.MatchRule("ctf.coverage.module_source", "aws_s3_bucket.logs", runClock)
	if !ok {
		t.Fatal("MatchRule did not return the rule-level entry")
	}
	if !registry.IsValid(live, runClock) {
		t.Error("IsValid rejected an entry reviewed 30 days from now")
	}

	if _, ok := registry.Match("s3_bucket_logging_enabled", "aws_s3_bucket.logs", runClock); ok {
		t.Error("Match returned an entry for a control nothing covers")
	}
	if _, ok := registry.Match("", "aws_s3_bucket.logs", runClock); ok {
		t.Error("Match covered a finding with no control id")
	}
}

// The review date is a date, so an entry reviewed today is valid for the whole
// of today and stops at midnight UTC.
func TestIsValidRunsToTheEndOfTheReviewDay(t *testing.T) {
	registry := fakeExceptions{}
	reviewDate := time.Date(2026, time.September, 20, 0, 0, 0, 0, time.UTC)
	e := ctfkit.Exception{ID: "exc-today", ExpiresAt: reviewDate}

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"start of the review day", reviewDate, true},
		{"one second before midnight", reviewDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second), true},
		{"midnight of the next day", reviewDate.AddDate(0, 0, 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := registry.IsValid(e, tt.now); got != tt.want {
				t.Errorf("IsValid at %s = %v, want %v", tt.now, got, tt.want)
			}
		})
	}

	if registry.IsValid(ctfkit.Exception{ID: "exc-open"}, runClock) {
		t.Error("IsValid accepted an entry with no review date; an open ended waiver is not evidence")
	}
}

func TestDecideNoEntry(t *testing.T) {
	f := findingWithControls(t, "s3_bucket_versioning_enabled")

	p, suppress := ctfkit.Decide(f, fakeExceptions{}, runClock)
	if p != nil || suppress {
		t.Errorf("Decide returned (%v, %v) with nothing in the registry, want (nil, false)", p, suppress)
	}
}

func TestDecideEveryControlCoveredAndValid(t *testing.T) {
	f := findingWithControls(t, "s3_bucket_encryption_enabled", "s3_bucket_versioning_enabled")
	registry := fakeExceptions{entries: []ctfkit.Exception{
		{
			ID: "exc-1", ControlID: "s3_bucket_encryption_enabled", Resource: "aws_s3_bucket.logs",
			Justification: "encrypted by the bucket policy", ExpiresAt: runClock.AddDate(0, 0, 1),
		},
		{
			ID: "exc-2", ControlID: "s3_bucket_versioning_enabled", Resource: "aws_s3_bucket.logs",
			Justification: "log bucket, rotation handles it", ExpiresAt: runClock.AddDate(0, 0, 10),
		},
	}}

	p, suppress := ctfkit.Decide(f, registry, runClock)
	if !suppress {
		t.Fatal("Decide did not suppress a finding whose every control is covered by a valid entry")
	}
	if !p.Allowed {
		t.Error("the recorded property says the waiver was not allowed")
	}
	if p.EntryID == "" || p.Justification == "" {
		t.Errorf("the property does not name the entry it came from: %+v", p)
	}
	if p.TTLSeconds <= 0 {
		t.Errorf("TTLSeconds = %d, want the time left on the entry", p.TTLSeconds)
	}
}

// One control covered by a lapsed entry is enough to keep the finding
// counting, and the lapsed entry is still recorded on it. This is the shape of
// conformance fixture 07.
func TestDecideOneEntryExpired(t *testing.T) {
	f := findingWithControls(t, "s3_bucket_encryption_enabled", "s3_bucket_versioning_enabled")
	registry := fakeExceptions{entries: []ctfkit.Exception{
		{
			ID: "exc-1", ControlID: "s3_bucket_encryption_enabled", Resource: "aws_s3_bucket.logs",
			Justification: "encrypted by the bucket policy", ExpiresAt: runClock.AddDate(0, 0, 10),
		},
		{
			ID: "exc-lapsed", ControlID: "s3_bucket_versioning_enabled", Resource: "aws_s3_bucket.logs",
			Justification: "waiting on the migration", ExpiresAt: runClock.AddDate(0, 0, -2),
		},
	}}

	p, suppress := ctfkit.Decide(f, registry, runClock)
	if suppress {
		t.Fatal("Decide suppressed a finding whose waiver has lapsed")
	}
	if p == nil {
		t.Fatal("Decide discarded the lapsed waiver; it is evidence that somebody meant to allow this")
	}
	if p.Allowed {
		t.Error("the recorded property says a lapsed waiver was allowed")
	}
	if p.EntryID != "exc-lapsed" {
		t.Errorf("EntryID = %q, want the lapsed entry", p.EntryID)
	}
	if p.TTLSeconds != 0 {
		t.Errorf("TTLSeconds = %d on a lapsed entry, want 0", p.TTLSeconds)
	}

	// Fixture 07: the finding surfaces with the exception metadata, its level
	// and kind unchanged.
	marked := ctfkit.WithException(f, *p)
	if marked.Level != ctfkit.LevelError || marked.Kind != ctfkit.KindFail {
		t.Error("recording a lapsed waiver changed the level or the kind")
	}
	raw, err := json.Marshal(marked)
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	if !contains(string(raw), `"ctf.exception":{"allowed":false,"entryId":"exc-lapsed"`) {
		t.Errorf("the marked finding does not carry the lapsed waiver: %s", raw)
	}
}

// A finding with no control id is reachable only through its rule id.
func TestDecideFallsBackToTheRuleID(t *testing.T) {
	f, err := ctfkit.NewFinding("ctf.coverage.module_source", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Raw aws_s3_bucket"},
		[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
			FullyQualifiedName: "aws_s3_bucket.logs", Kind: ctfkit.LogicalLocationResource,
		}}}},
		ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostPlan})
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}

	controlEntry := fakeExceptions{entries: []ctfkit.Exception{{
		ID: "exc-control", ControlID: "s3_bucket_versioning_enabled",
		Resource: "aws_s3_bucket.logs", ExpiresAt: runClock.AddDate(0, 0, 10),
	}}}
	if _, suppress := ctfkit.Decide(f, controlEntry, runClock); suppress {
		t.Error("a control entry suppressed a finding that carries no control id")
	}

	ruleEntry := fakeExceptions{entries: []ctfkit.Exception{{
		ID: "exc-rule", RuleID: "ctf.coverage.module_source",
		Resource: "aws_s3_bucket.logs", Justification: "migrating next quarter",
		ExpiresAt: runClock.AddDate(0, 0, 10),
	}}}
	p, suppress := ctfkit.Decide(f, ruleEntry, runClock)
	if !suppress || p == nil || p.EntryID != "exc-rule" {
		t.Errorf("Decide returned (%+v, %v), want the rule-level waiver to suppress", p, suppress)
	}
}

func findingWithControls(t *testing.T, ids ...ctfkit.ControlID) ctfkit.Finding {
	t.Helper()
	f, err := ctfkit.NewFinding("ctf.control.framework_findings", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Bucket does not satisfy its controls"},
		[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
			FullyQualifiedName: "aws_s3_bucket.logs", Kind: ctfkit.LogicalLocationResource,
		}}}},
		ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostPlan, ControlIDs: ids})
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}
	return f
}
