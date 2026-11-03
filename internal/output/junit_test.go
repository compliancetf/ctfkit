package output

import (
	"encoding/xml"
	"testing"

	"github.com/compliancetf/ctfkit/internal/validator"
)

// These mirror the emitted XML rather than reusing the production structs, so
// the assertions describe what a CI consumer actually parses.
type parsedSuites struct {
	XMLName  xml.Name      `xml:"testsuites"`
	Tests    int           `xml:"tests,attr"`
	Failures int           `xml:"failures,attr"`
	Errors   int           `xml:"errors,attr"`
	Skipped  int           `xml:"skipped,attr"`
	Suites   []parsedSuite `xml:"testsuite"`
}

type parsedSuite struct {
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Cases    []parsedCase `xml:"testcase"`
}

type parsedCase struct {
	Name    string      `xml:"name,attr"`
	Failure *parsedNote `xml:"failure"`
	Error   *parsedNote `xml:"error"`
	Skipped *parsedNote `xml:"skipped"`
}

type parsedNote struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func parseJUnit(t *testing.T, violations []validator.Violation) parsedSuites {
	t.Helper()
	raw, err := NewJUnitFormatter().Format(violations)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	var got parsedSuites
	if err := xml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("emitted XML does not parse: %v\n%s", err, raw)
	}
	return got
}

// An info-severity violation is a real finding. Emitting it as a testcase with
// no child element makes CI render it as a passing test, which is
// indistinguishable from no finding at all.
func TestJUnitInfoViolationIsNotAPassingTest(t *testing.T) {
	got := parseJUnit(t, []validator.Violation{{
		Rule:     "ctf-004",
		Severity: validator.SeverityInfo,
		Message:  "Resource type is outside the configured allowlist",
		File:     "network/vpc.tf",
		Line:     7,
		Module:   "vpc",
	}})

	if len(got.Suites) != 1 || len(got.Suites[0].Cases) != 1 {
		t.Fatalf("want one suite with one case, got %+v", got)
	}
	tc := got.Suites[0].Cases[0]
	if tc.Skipped == nil {
		t.Fatalf("info violation rendered as a bare (passing) testcase: %+v", tc)
	}
	if tc.Skipped.Message == "" {
		t.Error("skipped element carries no message, so the finding is invisible in CI")
	}
	if tc.Failure != nil || tc.Error != nil {
		t.Error("info violation must not be reported as a failure or an error")
	}
}

// tests must equal failures + errors + skipped whenever there are violations.
// Before this change a mixed run rendered as tests=3 failures=1 errors=1, so
// the info finding vanished from the totals: the sum did not reach tests.
//
// The no-violations case is the exception and is asserted separately: it emits
// one synthetic testcase that really is a pass.
func TestJUnitCountsAreConsistent(t *testing.T) {
	cases := map[string][]validator.Violation{
		"mixed severities": sampleViolations(),
		"info only": {{
			Rule:     "ctf-004",
			Severity: validator.SeverityInfo,
			Message:  "informational",
			File:     "main.tf",
			Line:     1,
		}},
	}

	for name, violations := range cases {
		t.Run(name, func(t *testing.T) {
			got := parseJUnit(t, violations)

			if got.Tests != len(violations) {
				t.Errorf("testsuites tests = %d, want %d (one per violation)", got.Tests, len(violations))
			}
			if sum := got.Failures + got.Errors + got.Skipped; sum != got.Tests {
				t.Errorf("testsuites: failures+errors+skipped = %d, want tests = %d", sum, got.Tests)
			}

			var tests, failures, errs, skipped int
			for _, s := range got.Suites {
				if sum := s.Failures + s.Errors + s.Skipped; sum != s.Tests {
					t.Errorf("testsuite %q: failures+errors+skipped = %d, want tests = %d", s.Name, sum, s.Tests)
				}
				if s.Tests != len(s.Cases) {
					t.Errorf("testsuite %q: tests = %d but has %d testcase elements", s.Name, s.Tests, len(s.Cases))
				}
				tests += s.Tests
				failures += s.Failures
				errs += s.Errors
				skipped += s.Skipped
			}

			if tests != got.Tests {
				t.Errorf("testsuites tests = %d, suites sum to %d", got.Tests, tests)
			}
			if failures != got.Failures {
				t.Errorf("testsuites failures = %d, suites sum to %d", got.Failures, failures)
			}
			if errs != got.Errors {
				t.Errorf("testsuites errors = %d, suites sum to %d", got.Errors, errs)
			}
			if skipped != got.Skipped {
				t.Errorf("testsuites skipped = %d, suites sum to %d", got.Skipped, skipped)
			}
		})
	}
}

// The no-violations run is the one case where a passing testcase is correct.
func TestJUnitNoViolationsIsASinglePass(t *testing.T) {
	got := parseJUnit(t, []validator.Violation{})

	if got.Tests != 1 || got.Failures != 0 || got.Errors != 0 || got.Skipped != 0 {
		t.Errorf("want tests=1 failures=0 errors=0 skipped=0, got %+v", got)
	}
	if len(got.Suites) != 1 || len(got.Suites[0].Cases) != 1 {
		t.Fatalf("want one suite with one case, got %+v", got)
	}
	if tc := got.Suites[0].Cases[0]; tc.Failure != nil || tc.Error != nil || tc.Skipped != nil {
		t.Errorf("the all-passed testcase must have no child element, got %+v", tc)
	}
}

// Every violation must reach CI as exactly one categorized testcase.
func TestJUnitEveryViolationIsCategorized(t *testing.T) {
	violations := sampleViolations()
	got := parseJUnit(t, violations)

	categorized := 0
	for _, s := range got.Suites {
		for _, tc := range s.Cases {
			if tc.Failure == nil && tc.Error == nil && tc.Skipped == nil {
				t.Errorf("testcase %q has no failure, error or skipped child, so CI reads it as passing", tc.Name)
				continue
			}
			categorized++
		}
	}
	if categorized != len(violations) {
		t.Errorf("categorized %d testcases, want %d (one per violation)", categorized, len(violations))
	}
}
