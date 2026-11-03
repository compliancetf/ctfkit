package output

import "github.com/compliancetf/ctfkit/internal/validator"

// sampleViolations is the single fixture every formatter golden is rendered
// from, so a change in one formatter shows up as a diff against the same input
// the others saw. It deliberately covers each branch the formatters switch on:
//
//   - all three severities, including info, which neither the text nor the
//     JUnit formatter has a dedicated case for;
//   - a violation with a Module set and one without, which is the branch JUnit
//     uses to choose between a "<rule> - <module>" and a "<rule> - line N" test
//     name;
//   - a violation with a Remediation and one without;
//   - a Column set and one left at zero, which SARIF emits as omitempty;
//   - two distinct files, so the JUnit per-file grouping has more than one
//     suite to order.
//
// The info-severity violation records three gaps that the golden files pin as
// they are today rather than silently bless; each has a follow-up issue:
//
//   - JUnit emits it as a testcase with neither <failure> nor <error>, so CI
//     reads a real finding as a passing test and the testsuites counts do not
//     add up (tests="3" against failures="1" errors="1");
//   - the text formatter labels it [WARNING], because the severity string is
//     chosen by a single != SeverityError check;
//   - the pretty formatter gives it the warning icon for the same reason.
//
// A golden file is a record of current behavior, not a judgment that the
// behavior is right. Changing any of the three should change these files.
func sampleViolations() []validator.Violation {
	return []validator.Violation{
		{
			Rule:        "ctf-001",
			Severity:    validator.SeverityError,
			Message:     "Module source is not an approved compliance.tf endpoint",
			File:        "main.tf",
			Line:        12,
			Column:      3,
			Module:      "bucket",
			Remediation: "Use soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws",
		},
		{
			Rule:     "ctf-003",
			Severity: validator.SeverityWarning,
			Message:  "Variable name suggests a control bypass",
			File:     "main.tf",
			Line:     41,
		},
		{
			Rule:     "ctf-004",
			Severity: validator.SeverityInfo,
			Message:  "Resource type is outside the configured allowlist",
			File:     "network/vpc.tf",
			Line:     7,
			Resource: "aws_flow_log",
			Module:   "vpc",
		},
	}
}
