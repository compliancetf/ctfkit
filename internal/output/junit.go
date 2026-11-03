package output

import (
	"encoding/xml"
	"fmt"
	"sort"
	"time"

	"github.com/compliancetf/ctfkit/internal/validator"
)

// JUnitFormatter outputs results in JUnit XML format
type JUnitFormatter struct{}

// NewJUnitFormatter creates a new JUnit formatter
func NewJUnitFormatter() *JUnitFormatter {
	return &JUnitFormatter{}
}

// JUnit XML structures
// JUnitTestSuites represents JUnit XML test suites
type JUnitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Errors     int              `xml:"errors,attr"`
	Skipped    int              `xml:"skipped,attr"`
	Time       float64          `xml:"time,attr"`
	TestSuites []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite represents a JUnit test suite
type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      float64         `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a JUnit test case
type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Error     *JUnitError   `xml:"error,omitempty"`
	Skipped   *JUnitSkipped `xml:"skipped,omitempty"`
}

// JUnitSkipped represents a JUnit test case that did not fail but is not a
// plain pass either.
type JUnitSkipped struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// JUnitFailure represents a JUnit test failure
type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// JUnitError represents a JUnit test error
type JUnitError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// Format formats results as JUnit XML
func (f *JUnitFormatter) Format(violations []validator.Violation) ([]byte, error) {
	// Default duration to 0 since we don't track execution time yet
	duration := time.Duration(0)
	// Group violations by file
	violationsByFile := make(map[string][]validator.Violation)
	for _, v := range violations {
		violationsByFile[v.File] = append(violationsByFile[v.File], v)
	}

	// The totals are summed from the suites below rather than counted here.
	// A second classification pass is how the counts drifted from the emitted
	// elements in the first place: it silently disagreed with the switch that
	// builds the test cases.
	testSuites := JUnitTestSuites{
		Name:  "ctfkit validation",
		Tests: len(violations),
		Time:  duration.Seconds(),
	}

	// Create a test suite for each file, in a stable order: Go randomizes map
	// iteration, so ranging over violationsByFile directly reorders the suites
	// on every run and makes the XML churn between otherwise identical runs.
	files := make([]string, 0, len(violationsByFile))
	for file := range violationsByFile {
		files = append(files, file)
	}
	sort.Strings(files)

	for _, file := range files {
		fileViolations := violationsByFile[file]
		suite := JUnitTestSuite{
			Name:      file,
			Tests:     len(fileViolations),
			Timestamp: time.Now().Format(time.RFC3339),
			Time:      0.001, // Nominal time
		}

		for _, v := range fileViolations {
			testName := fmt.Sprintf("%s - %s", v.Rule, v.Module)
			if v.Module == "" {
				testName = fmt.Sprintf("%s - line %d", v.Rule, v.Line)
			}

			testCase := JUnitTestCase{
				Name:      testName,
				ClassName: file,
				Time:      0.001,
			}

			details := fmt.Sprintf("Location: %s:%d\n%s", v.File, v.Line, v.Message)
			if v.Remediation != "" {
				details += fmt.Sprintf("\nRemediation: %s", v.Remediation)
			}

			// Every violation must carry a child element. A testcase with none
			// is rendered by CI as a plain pass, which makes a real finding
			// indistinguishable from no finding at all, so anything that is
			// not an error or a warning - info today, any severity added
			// later - falls through to skipped rather than out of the switch.
			switch v.Severity {
			case validator.SeverityError:
				suite.Errors++
				testCase.Error = &JUnitError{
					Message: v.Message,
					Type:    v.Rule,
					Text:    details,
				}
			case validator.SeverityWarning:
				suite.Failures++
				testCase.Failure = &JUnitFailure{
					Message: v.Message,
					Type:    v.Rule,
					Text:    details,
				}
			default:
				suite.Skipped++
				testCase.Skipped = &JUnitSkipped{
					Message: v.Message,
					Text:    details,
				}
			}

			suite.TestCases = append(suite.TestCases, testCase)
		}

		testSuites.Failures += suite.Failures
		testSuites.Errors += suite.Errors
		testSuites.Skipped += suite.Skipped
		testSuites.TestSuites = append(testSuites.TestSuites, suite)
	}

	// If no violations, create a success test case
	if len(violations) == 0 {
		suite := JUnitTestSuite{
			Name:      "compliance-validation",
			Tests:     1,
			Timestamp: time.Now().Format(time.RFC3339),
			Time:      duration.Seconds(),
		}
		suite.TestCases = append(suite.TestCases, JUnitTestCase{
			Name:      "all-compliance-checks-passed",
			ClassName: "ctfkit",
			Time:      duration.Seconds(),
		})
		testSuites.TestSuites = append(testSuites.TestSuites, suite)
		testSuites.Tests = 1
	}

	// Prepend XML header
	xmlData, err := xml.MarshalIndent(testSuites, "", "  ")
	if err != nil {
		return nil, err
	}

	result := append([]byte(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"), xmlData...)
	return result, nil
}
