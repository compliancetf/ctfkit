package exceptions_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/exceptions"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// fixtureNow is the frozen run clock of the fixture pack, the timestamp
// testdata/fixtures/README.md "Run context" names. Fixture 06 is valid at it
// and fixture 07 is not, which is the whole difference between the two cases.
var fixtureNow = time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

const (
	versioning = ctfkit.ControlID("s3_bucket_versioning_enabled")
	bucket     = "aws_s3_bucket.logs"
	// waivedRule is the rule fixtures 06 and 07 waive on the bucket: the raw
	// aws_s3_bucket module_source finding, which under the embedded CIS
	// catalog carries no control id.
	waivedRule = "ctf.coverage.module_source"
)

func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "fixtures", "plan", name, "input")
}

// Fixture 06 is the sentinel: an entry that covers the finding and is still
// inside its review window.
func TestTheSentinelFixtureMatchesAndIsValid(t *testing.T) {
	reg, err := exceptions.Discover(fixtureDir(t, "06-sentinel-exception"))
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	e, ok := reg.MatchRule(waivedRule, bucket, fixtureNow)
	if !ok {
		t.Fatalf("MatchRule(%s, %s) not found", waivedRule, bucket)
	}
	if e.ID != "SEC-4711" {
		t.Errorf("ID = %q, want SEC-4711", e.ID)
	}
	if e.RuleID != waivedRule {
		t.Errorf("RuleID = %q, want %q", e.RuleID, waivedRule)
	}
	if e.ControlID != "" {
		t.Errorf("ControlID = %q, want empty on a rule entry", e.ControlID)
	}
	if e.Justification == "" {
		t.Error("Justification is empty, want the reason the file records")
	}
	if want := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC); !e.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", e.ExpiresAt, want)
	}
	if !reg.IsValid(e, fixtureNow) {
		t.Error("IsValid() = false, want true at the fixture run clock")
	}
}

// Fixture 07 is the same entry past its review date: it still matches, so the
// runner can report an expired waiver as an expired waiver rather than as no
// waiver at all.
func TestTheExpiredFixtureMatchesAndIsNotValid(t *testing.T) {
	reg, err := exceptions.Discover(fixtureDir(t, "07-expired-exception"))
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	e, ok := reg.MatchRule(waivedRule, bucket, fixtureNow)
	if !ok {
		t.Fatalf("MatchRule(%s, %s) not found", waivedRule, bucket)
	}
	if e.ID != "SEC-4108" {
		t.Errorf("ID = %q, want SEC-4108", e.ID)
	}
	if reg.IsValid(e, fixtureNow) {
		t.Error("IsValid() = true, want false past the review date")
	}
}

func TestDiscoverWithoutAFileIsAnEmptyRegistry(t *testing.T) {
	reg, err := exceptions.Discover(t.TempDir())
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil for a directory with no file", err)
	}
	if _, ok := reg.Match(versioning, bucket, fixtureNow); ok {
		t.Error("Match() found an entry in an empty registry")
	}
	if _, ok := reg.MatchRule("ctf.coverage.module_source", bucket, fixtureNow); ok {
		t.Error("MatchRule() found an entry in an empty registry")
	}
}

// A typo can never quietly widen what is allowed: a malformed file is an
// environment error, never an empty snapshot.
func TestLoadRejectsAMalformedFile(t *testing.T) {
	path := write(t, "exceptions: [{control: a, resource:\n\tnot yaml")

	if _, err := exceptions.Load(path); !errors.Is(err, exceptions.ErrExceptions) {
		t.Errorf("Load() error = %v, want it to wrap ErrExceptions", err)
	}
}

func TestLoadRejectsAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.yaml")

	if _, err := exceptions.Load(path); !errors.Is(err, exceptions.ErrExceptions) {
		t.Errorf("Load() error = %v, want it to wrap ErrExceptions", err)
	}
}

func TestLoadRejectsABadEntry(t *testing.T) {
	cases := map[string]string{
		"both control and rule": `exceptions:
  - control: s3_bucket_versioning_enabled
    rule: ctf.coverage.module_source
    resource: aws_s3_bucket.logs
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]`,
		"neither control nor rule": `exceptions:
  - resource: aws_s3_bucket.logs
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]`,
		"no resource": `exceptions:
  - control: s3_bucket_versioning_enabled
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]`,
		"duplicate control and resource pair": `exceptions:
  - control: s3_bucket_versioning_enabled
    resource: aws_s3_bucket.logs
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]
  - control: s3_bucket_versioning_enabled
    resource: aws_s3_bucket.logs
    review_date: "2028-06-01"
    approvals: [b@bobthecorp.example]`,
		"duplicate rule and resource pair": `exceptions:
  - rule: ctf.coverage.module_source
    resource: aws_s3_bucket.logs
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]
  - rule: ctf.coverage.module_source
    resource: aws_s3_bucket.logs
    review_date: "2028-06-01"
    approvals: [b@bobthecorp.example]`,
		"unparseable review date": `exceptions:
  - control: s3_bucket_versioning_enabled
    resource: aws_s3_bucket.logs
    review_date: "the first of June"
    approvals: [a@bobthecorp.example]`,
		"unsupported schema major": `schema_version: "2.0"
exceptions:
  - control: s3_bucket_versioning_enabled
    resource: aws_s3_bucket.logs
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := exceptions.Load(write(t, body)); !errors.Is(err, exceptions.ErrExceptions) {
				t.Errorf("Load() error = %v, want it to wrap ErrExceptions", err)
			}
		})
	}
}

// The loader rejects a duplicate (control or rule, resource) pair, so a scope
// holds exactly one entry and "the first valid at now, else the first entry of
// that scope" is that entry either way. Both branches are asserted here: the
// valid entry and the expired one both come back with ok true.
func TestMatchReturnsTheEntryWhetherValidOrNot(t *testing.T) {
	path := write(t, `exceptions:
  - control: s3_bucket_versioning_enabled
    resource: aws_s3_bucket.logs
    id: VALID-1
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]
  - control: s3_bucket_logging_enabled
    resource: aws_s3_bucket.logs
    id: STALE-1
    review_date: "2026-03-01"
    approvals: [a@bobthecorp.example]`)

	reg, err := exceptions.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	valid, ok := reg.Match(versioning, bucket, fixtureNow)
	if !ok || valid.ID != "VALID-1" || !reg.IsValid(valid, fixtureNow) {
		t.Errorf("Match(versioning) = %+v, %v; want VALID-1 and valid", valid, ok)
	}

	stale, ok := reg.Match("s3_bucket_logging_enabled", bucket, fixtureNow)
	if !ok || stale.ID != "STALE-1" {
		t.Fatalf("Match(logging) = %+v, %v; want STALE-1 found", stale, ok)
	}
	if reg.IsValid(stale, fixtureNow) {
		t.Error("IsValid(STALE-1) = true, want false")
	}
}

// A control entry never covers a zero-control finding and a rule entry never
// covers a control id; the two lookups are separate scopes.
func TestMatchRuleIsASeparateScope(t *testing.T) {
	path := write(t, `exceptions:
  - rule: ctf.coverage.module_source
    resource: aws_s3_bucket.logs
    id: RULE-1
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]`)

	reg, err := exceptions.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	e, ok := reg.MatchRule("ctf.coverage.module_source", bucket, fixtureNow)
	if !ok {
		t.Fatal("MatchRule() not found")
	}
	if e.RuleID != "ctf.coverage.module_source" || e.ControlID != "" {
		t.Errorf("entry = %+v, want RuleID set and ControlID empty", e)
	}
	if !reg.IsValid(e, fixtureNow) {
		t.Error("IsValid() = false, want true")
	}

	if _, ok := reg.Match("ctf.coverage.module_source", bucket, fixtureNow); ok {
		t.Error("Match() answered a rule entry, want the scopes kept apart")
	}
	if _, ok := reg.MatchRule(string(versioning), bucket, fixtureNow); ok {
		t.Error("MatchRule() answered a control entry, want the scopes kept apart")
	}
	if _, ok := reg.MatchRule("ctf.coverage.module_source", "aws_s3_bucket.other", fixtureNow); ok {
		t.Error("MatchRule() matched another resource, want an exact string match")
	}
}

func TestIsValidWantsApprovalsAndAReviewDateNotYetPast(t *testing.T) {
	reviewDay := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	approved := ctfkit.Exception{ExpiresAt: reviewDay, Approvers: []string{"a@bobthecorp.example"}}

	reg, err := exceptions.Load(write(t, "exceptions: []"))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	cases := []struct {
		name string
		e    ctfkit.Exception
		now  time.Time
		want bool
	}{
		{"inside the window", approved, fixtureNow, true},
		{"the review day itself", approved, reviewDay, true},
		{"the last second of the review day", approved, reviewDay.Add(24*time.Hour - time.Second), true},
		{"the last nanosecond of the review day", approved, reviewDay.Add(24*time.Hour - time.Nanosecond), true},
		{"the first instant of the day after", approved, reviewDay.Add(24 * time.Hour), false},
		{"the day after the review day", approved, reviewDay.Add(25 * time.Hour), false},
		{"no approvals", ctfkit.Exception{ExpiresAt: reviewDay}, fixtureNow, false},
		{"no review date", ctfkit.Exception{Approvers: []string{"a@bobthecorp.example"}}, fixtureNow, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reg.IsValid(c.e, c.now); got != c.want {
				t.Errorf("IsValid() = %v, want %v", got, c.want)
			}
		})
	}
}

// An entry with no review date loads, because an open ended waiver is a
// governance failure to report rather than a malformed file, and IsValid says
// it is not in force.
func TestAnEntryWithoutAReviewDateLoadsAndIsNotValid(t *testing.T) {
	reg, err := exceptions.Load(write(t, `exceptions:
  - control: s3_bucket_versioning_enabled
    resource: aws_s3_bucket.logs
    id: OPEN-1
    approvals: [a@bobthecorp.example]`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	e, ok := reg.Match(versioning, bucket, fixtureNow)
	if !ok {
		t.Fatal("Match() not found")
	}
	if !e.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want the zero time", e.ExpiresAt)
	}
	if reg.IsValid(e, fixtureNow) {
		t.Error("IsValid() = true, want false for an open ended waiver")
	}
}

// approved_by is the field the exceptions file schema and both recorded
// fixtures carry; approvals is the list the SDK spec names. Either fills
// Approvers.
func TestBothApprovalSpellingsFillApprovers(t *testing.T) {
	reg, err := exceptions.Load(write(t, `exceptions:
  - control: s3_bucket_versioning_enabled
    resource: aws_s3_bucket.logs
    review_date: "2027-06-01"
    approved_by: single@bobthecorp.example
  - control: s3_bucket_logging_enabled
    resource: aws_s3_bucket.logs
    review_date: "2027-06-01"
    approvals: [first@bobthecorp.example, second@bobthecorp.example]`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	one, _ := reg.Match(versioning, bucket, fixtureNow)
	if len(one.Approvers) != 1 || one.Approvers[0] != "single@bobthecorp.example" {
		t.Errorf("Approvers = %v, want the approved_by value", one.Approvers)
	}
	two, _ := reg.Match("s3_bucket_logging_enabled", bucket, fixtureNow)
	if len(two.Approvers) != 2 {
		t.Errorf("Approvers = %v, want both list entries", two.Approvers)
	}
}

// The registry is an immutable snapshot: a caller cannot reach back into it
// through a slice it was handed.
func TestReturnedValuesAreCopies(t *testing.T) {
	reg, err := exceptions.Discover(fixtureDir(t, "06-sentinel-exception"))
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	first, _ := reg.MatchRule(waivedRule, bucket, fixtureNow)
	if len(first.Approvers) == 0 {
		t.Fatal("the fixture entry records no approver")
	}
	want := first.Approvers[0]
	first.Approvers[0] = "attacker@example.invalid"

	second, _ := reg.MatchRule(waivedRule, bucket, fixtureNow)
	if second.Approvers[0] != want {
		t.Errorf("Approvers[0] = %q after a caller wrote to its copy, want %q", second.Approvers[0], want)
	}
}

// FileExceptions is an ExceptionRegistry, which is what lets the runner's
// Decide helper reach it.
func TestFileExceptionsSatisfiesTheInterface(t *testing.T) {
	reg, err := exceptions.Discover(fixtureDir(t, "06-sentinel-exception"))
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	var _ ctfkit.ExceptionRegistry = reg

	p, allowed := ctfkit.Decide(finding(t), reg, fixtureNow)
	if !allowed || p == nil || p.EntryID != "SEC-4711" {
		t.Errorf("Decide() = %+v, %v; want the fixture entry allowed", p, allowed)
	}
}

// finding is the raw-bucket module_source finding both fixture files waive by
// rule. Under the embedded CIS catalog it carries no control id.
func finding(t *testing.T) ctfkit.Finding {
	t.Helper()
	f, err := ctfkit.NewFinding("ctf.coverage.module_source", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Raw aws_s3_bucket"},
		[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
			FullyQualifiedName: bucket, Kind: ctfkit.LogicalLocationResource,
		}}}},
		ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostPlan})
	if err != nil {
		t.Fatalf("NewFinding() error = %v", err)
	}
	return f
}

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".ctf-exceptions.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the test file: %v", err)
	}
	return path
}

// A whitespace-only rule value is absent, and it has to be absent to every
// part of the loader at once. Reading it as present anywhere would file the
// entry under a lookup nothing ever performs, which loses an approved waiver
// with no diagnostic at all.
func TestAWhitespaceRuleValueIsAbsentToTheWholeLoader(t *testing.T) {
	reg, err := exceptions.Load(write(t, `exceptions:
  - control: s3_bucket_versioning_enabled
    rule: " "
    resource: aws_s3_bucket.logs
    id: SPACE-1
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	e, ok := reg.Match(versioning, bucket, fixtureNow)
	if !ok {
		t.Fatal("Match() not found: the entry is filed where no lookup reaches it")
	}
	if e.ID != "SPACE-1" || e.RuleID != "" {
		t.Errorf("entry = %+v, want SPACE-1 with no rule id", e)
	}
	if _, ok := reg.MatchRule(string(versioning), bucket, fixtureNow); ok {
		t.Error("MatchRule() answered a control entry")
	}
}

// A resource padded with spaces is the same resource. The alternative is an
// entry that loads, passes the duplicate check, and then never equals any
// resource address.
func TestAPaddedResourceIsTheSameScope(t *testing.T) {
	reg, err := exceptions.Load(write(t, `exceptions:
  - control: s3_bucket_versioning_enabled
    resource: "  aws_s3_bucket.logs  "
    id: PADDED-1
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	e, ok := reg.Match(versioning, bucket, fixtureNow)
	if !ok {
		t.Fatal("Match() not found for the unpadded address")
	}
	if e.Resource != bucket {
		t.Errorf("Resource = %q, want %q", e.Resource, bucket)
	}

	_, err = exceptions.Load(write(t, `exceptions:
  - control: s3_bucket_versioning_enabled
    resource: aws_s3_bucket.logs
    review_date: "2027-06-01"
    approvals: [a@bobthecorp.example]
  - control: s3_bucket_versioning_enabled
    resource: " aws_s3_bucket.logs"
    review_date: "2028-06-01"
    approvals: [b@bobthecorp.example]`))
	if !errors.Is(err, exceptions.ErrExceptions) {
		t.Errorf("Load() error = %v, want a padded copy of a scope rejected as a duplicate", err)
	}
}

// The middle outcome of Decide is the one worth keeping: an expired waiver is
// evidence that somebody meant to allow this and let the review lapse, which
// reads differently from nobody having looked at it.
func TestDecideRecordsTheExpiredWaiverWithoutSuppressing(t *testing.T) {
	reg, err := exceptions.Discover(fixtureDir(t, "07-expired-exception"))
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	p, suppress := ctfkit.Decide(finding(t), reg, fixtureNow)
	if suppress {
		t.Error("Decide() suppressed a finding whose waiver has lapsed")
	}
	if p == nil {
		t.Fatal("Decide() recorded no waiver, want the lapsed entry reported")
	}
	if p.Allowed {
		t.Error("Allowed = true, want false past the review date")
	}
	if p.EntryID != "SEC-4108" {
		t.Errorf("EntryID = %q, want SEC-4108", p.EntryID)
	}
	if p.TTLSeconds != 0 {
		t.Errorf("TTLSeconds = %d, want 0 once the review date has passed", p.TTLSeconds)
	}
}
