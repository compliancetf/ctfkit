package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// digestFinding is one finding at uri:line on a bobthecorp resource.
func digestFinding(rule, level, uri string, line int, address, message string) ctfkit.Finding {
	return ctfkit.Finding{
		RuleID: rule, Level: level, Kind: ctfkit.KindFail,
		Message: ctfkit.Message{Text: message},
		Locations: []ctfkit.Location{{
			PhysicalLocation: &ctfkit.PhysicalLocation{
				ArtifactLocation: ctfkit.ArtifactLocation{URI: uri},
				Region:           &ctfkit.Region{StartLine: line},
			},
			LogicalLocations: []ctfkit.LogicalLocation{{FullyQualifiedName: address, Kind: ctfkit.LogicalLocationResource}},
		}},
		Props: ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostPlan},
	}
}

func digestFindings() ctfkit.Findings {
	return ctfkit.Findings{
		digestFinding("ctf.coverage.module_source", ctfkit.LevelError, "modules/s3/main.tf", 12,
			"module.s3.aws_s3_bucket.bobthecorp_logs", "aws_s3_bucket is not declared through a compliance.tf module."),
		digestFinding("ctf.coverage.module_source", ctfkit.LevelError, "main.tf", 3,
			"aws_s3_bucket.bobthecorp_data", "aws_s3_bucket is not declared through a compliance.tf module."),
		digestFinding("ctf.sensitive.public_exposure", ctfkit.LevelWarning, "main.tf", 40,
			"aws_security_group.bobthecorp_web", "Ingress opens port 22 to 0.0.0.0/0."),
		{
			RuleID: "ctf.origin.provider_unpinned", Level: ctfkit.LevelNote, Kind: ctfkit.KindReview,
			Message: ctfkit.Message{Text: "The run has no location."},
			Props:   ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostPlan},
		},
	}
}

func mustDigest(t *testing.T, fs ctfkit.Findings) string {
	t.Helper()
	d, err := findingsDigest(fs)
	if err != nil {
		t.Fatalf("findingsDigest: %v", err)
	}
	return d
}

// TestFindingsDigestGolden pins the value, so a change to the entry fields,
// their normalization or their order fails here and has to come with a new
// findingsDigestAlgorithm version rather than a silently different digest.
func TestFindingsDigestGolden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		findings ctfkit.Findings
		want     string
	}{
		// sha256 of "[]": an empty run still has a digest a re-scan can match.
		{"no findings", nil, "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"},
		{"four findings", digestFindings(), "sha256:d3aeaa0da640e573ab8f156e1ffc0abac230580a7d1ec368dc72ca8cb8b39b41"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := mustDigest(t, tt.findings); got != tt.want {
				t.Errorf("findingsDigest = %s, want %s", got, tt.want)
			}
		})
	}
	if findingsDigestAlgorithm != "jcs-sha256/v1" {
		t.Errorf("findingsDigestAlgorithm = %q; a new algorithm needs a new golden", findingsDigestAlgorithm)
	}
}

// TestFindingsDigestIgnoresOrderSeparatorsAndRunData: every permutation of the
// findings, Windows separators in the URIs, and data that belongs to the run
// rather than to what it found give the same digest.
func TestFindingsDigestIgnoresOrderSeparatorsAndRunData(t *testing.T) {
	t.Parallel()
	want := mustDigest(t, digestFindings())

	tests := []struct {
		name   string
		mutate func(ctfkit.Findings) ctfkit.Findings
	}{
		{"reversed", func(fs ctfkit.Findings) ctfkit.Findings {
			return ctfkit.Findings{fs[3], fs[2], fs[1], fs[0]}
		}},
		{"shuffled", func(fs ctfkit.Findings) ctfkit.Findings {
			return ctfkit.Findings{fs[2], fs[0], fs[3], fs[1]}
		}},
		{"windows separators", func(fs ctfkit.Findings) ctfkit.Findings {
			fs[0].Locations[0].PhysicalLocation.ArtifactLocation.URI = `modules\s3\main.tf`
			return fs
		}},
		{"discriminator and catalog data", func(fs ctfkit.Findings) ctfkit.Findings {
			fs[1].Discriminator = "registry.compliance.tf/bobthecorp/s3/aws"
			fs[1].Props.ControlIDs = []ctfkit.ControlID{"s3.1"}
			fs[1].Props.Remediation = &ctfkit.Remediation{ModuleSource: "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws"}
			return fs
		}},
		{"waiver metadata of an unsuppressed finding", func(fs ctfkit.Findings) ctfkit.Findings {
			fs[2] = ctfkit.WithException(fs[2], ctfkit.ExceptionProperty{Allowed: false, EntryID: "bobthecorp-1", TTLSeconds: 0})
			return fs
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := mustDigest(t, tt.mutate(digestFindings())); got != want {
				t.Errorf("findingsDigest = %s, want %s", got, want)
			}
		})
	}
}

// TestFindingsDigestTracksWhatWasFound: changing one finding's rule, level,
// kind, message, location or suppression changes the digest.
func TestFindingsDigestTracksWhatWasFound(t *testing.T) {
	t.Parallel()
	base := mustDigest(t, digestFindings())

	loc := func(f *ctfkit.Finding) *ctfkit.PhysicalLocation { return f.Locations[0].PhysicalLocation }
	tests := []struct {
		name   string
		mutate func(fs ctfkit.Findings)
	}{
		{"message", func(fs ctfkit.Findings) { fs[0].Message.Text += " Use the module." }},
		{"uri", func(fs ctfkit.Findings) { loc(&fs[0]).ArtifactLocation.URI = "modules/s3/bucket.tf" }},
		{"line", func(fs ctfkit.Findings) { loc(&fs[0]).Region.StartLine = 13 }},
		{"column", func(fs ctfkit.Findings) { loc(&fs[0]).Region.StartColumn = 2 }},
		{"resource address", func(fs ctfkit.Findings) {
			fs[1].Locations[0].LogicalLocations[0].FullyQualifiedName = "aws_s3_bucket.bobthecorp_other"
		}},
		{"rule", func(fs ctfkit.Findings) { fs[2].RuleID = "ctf.sensitive.wildcard_iam" }},
		{"level", func(fs ctfkit.Findings) { fs[2].Level = ctfkit.LevelError }},
		{"kind", func(fs ctfkit.Findings) { fs[3].Kind = ctfkit.KindPass }},
		{"suppressed", func(fs ctfkit.Findings) {
			fs[2] = ctfkit.WithException(fs[2], ctfkit.ExceptionProperty{Allowed: true, EntryID: "bobthecorp-1"})
		}},
		{"a finding replaced by a duplicate", func(fs ctfkit.Findings) { fs[3] = fs[0] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fs := digestFindings()
			tt.mutate(fs)
			if got := mustDigest(t, fs); got == base {
				t.Errorf("findingsDigest unchanged at %s", got)
			}
		})
	}
}

// TestFindingsDigestLeavesTheFindingsAlone: normalizing a Windows URI for the
// digest does not rewrite the finding every other projection renders.
func TestFindingsDigestLeavesTheFindingsAlone(t *testing.T) {
	t.Parallel()
	fs := digestFindings()
	fs[0].Locations[0].PhysicalLocation.ArtifactLocation.URI = `modules\s3\main.tf`
	mustDigest(t, fs)
	if got := fs[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != `modules\s3\main.tf` {
		t.Errorf("uri = %q after findingsDigest", got)
	}
}

// TestScanJSONFindingsDigest runs the same plan twice under two run contexts
// and a banner: the digest is the same, while a plan with other findings gets
// another one.
func TestScanJSONFindingsDigest(t *testing.T) {
	// Resolved before the first run, which changes the working directory.
	inputs := map[string]string{}
	for _, name := range []string{"01-raw-s3-no-ctf", "11-sensitive-public-exposure"} {
		inputs[name] = fixtureInput(t, name)
	}
	digestOf := func(t *testing.T, fixture string, args ...string) findingsDigestJSON {
		t.Helper()
		res := runScanIn(t, inputs[fixture], append([]string{"scan", "plan.json", "--format", "json"}, args...)...)
		if res.code == ExitEnvironment {
			t.Fatalf("exit 2: %v\n%s", res.err, res.stderr)
		}
		var doc struct {
			FindingsDigest findingsDigestJSON `json:"findingsDigest"`
			Findings       []json.RawMessage  `json:"findings"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
			t.Fatalf("parse json projection: %v\n%s", err, res.stdout)
		}
		if len(doc.Findings) == 0 {
			t.Fatalf("%s produced no findings; the comparison would prove nothing", fixture)
		}
		return doc.FindingsDigest
	}

	first := digestOf(t, "01-raw-s3-no-ctf", scanRunContext...)
	second := digestOf(t, "01-raw-s3-no-ctf", "--run-id", "bobthecorp-run-2", "--commit", strings.Repeat("b", 40),
		"--platform", "local", "--watermark", "bobthecorp re-scan")
	if first.Algorithm != findingsDigestAlgorithm || !strings.HasPrefix(first.Digest, "sha256:") {
		t.Errorf("findingsDigest = %+v, want algorithm %s and a sha256: value", first, findingsDigestAlgorithm)
	}
	if first != second {
		t.Errorf("two scans of one plan: %+v and %+v", first, second)
	}
	if other := digestOf(t, "11-sensitive-public-exposure", scanRunContext...); other == first {
		t.Errorf("two plans with different findings share the digest %+v", other)
	}
}
