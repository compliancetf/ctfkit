package sarif_test

import (
	"encoding/json"
	"testing"

	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// located is a finding on a resource block at the given lines of main.tf.
func located(address string, start, end int) ctfkit.Finding {
	f := finding("ctf.coverage.manifest_missing", ctfkit.LevelError)
	f.Locations = []ctfkit.Location{{
		PhysicalLocation: &ctfkit.PhysicalLocation{
			ArtifactLocation: ctfkit.ArtifactLocation{URI: "main.tf"},
			Region:           &ctfkit.Region{StartLine: start, EndLine: end},
		},
		LogicalLocations: []ctfkit.LogicalLocation{{FullyQualifiedName: address, Kind: ctfkit.LogicalLocationResource}},
	}}
	return f
}

// fingerprints renders the findings and returns each result's
// ctfkitFindingHash/v1, in result order.
func fingerprints(t *testing.T, fs ...ctfkit.Finding) []string {
	t.Helper()
	raw, err := sarif.Render(sarif.Input{
		Tool:     sarif.Tool{Name: toolName, Version: toolVersion},
		Rules:    reportRules,
		Findings: fs,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var out []string
	for _, r := range doc.Runs[0].Results {
		v := r.PartialFingerprints[sarif.FingerprintKey]
		if len(v) != 64 {
			t.Fatalf("%s = %q, want 64 hex characters", sarif.FingerprintKey, v)
		}
		out = append(out, v)
	}
	return out
}

// The fingerprint is what GitHub code scanning keys an alert on, so it must
// survive the block moving and must tell two blocks apart.
func TestFingerprintIgnoresLinesAndFollowsTheAddress(t *testing.T) {
	before := fingerprints(t, located("aws_s3_bucket.raw", 1, 8))[0]
	moved := fingerprints(t, located("aws_s3_bucket.raw", 40, 47))[0]
	other := fingerprints(t, located("aws_s3_bucket.logs", 1, 8))[0]

	if moved != before {
		t.Errorf("moving the block changed the fingerprint: %s -> %s", before, moved)
	}
	if other == before {
		t.Errorf("a different address kept the fingerprint %s", before)
	}
}

// The message carries counts and served versions that change on routine
// runs; none of it may move the alert. The discriminator (a module source
// without its version, an obligation token) is what tells two such findings
// apart (review of #101).
func TestFingerprintIgnoresTheMessageAndFollowsTheDiscriminator(t *testing.T) {
	base := finding("ctf.coverage.delegation_unresolved", ctfkit.LevelWarning)
	base.Props.ControlIDs = []ctfkit.ControlID{"s3_bucket_event_notifications_enabled"}
	base.Discriminator = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
	base.Message.Text = "delegated in s3-bucket/aws 5.16.1"

	bumped := base
	bumped.Message.Text = "delegated in s3-bucket/aws 5.17.0"
	otherBuild := base
	otherBuild.Discriminator = "bobthecorp.compliance.tf/terraform-aws-modules/vpc/aws"

	tests := finding("ctf.coverage.tests_failed", ctfkit.LevelError)
	tests.Message.Text = "Imported test results report 1 failed and 0 errored run(s) of 3"
	moreTests := tests
	moreTests.Message.Text = "Imported test results report 2 failed and 0 errored run(s) of 5"

	want := fingerprints(t, base)[0]
	if got := fingerprints(t, bumped)[0]; got != want {
		t.Errorf("a version bump in the message changed the fingerprint: %s -> %s", want, got)
	}
	if got := fingerprints(t, otherBuild)[0]; got == want {
		t.Errorf("a different module source kept the fingerprint %s", want)
	}
	if a, b := fingerprints(t, tests)[0], fingerprints(t, moreTests)[0]; a != b {
		t.Errorf("a count change in the message changed the fingerprint: %s -> %s", a, b)
	}
}

// Two findings that share every input still get distinct fingerprints, so a
// consumer that deduplicates on them keeps both.
func TestFingerprintsAreUniqueWithinARun(t *testing.T) {
	a := finding("ctf.coverage.delegation_unresolved", ctfkit.LevelWarning)
	b := finding("ctf.coverage.delegation_unresolved", ctfkit.LevelWarning)
	b.Message.Text = "another control"

	got := fingerprints(t, located("aws_s3_bucket.raw", 1, 8), located("aws_s3_bucket.raw", 20, 27), a, b)
	seen := map[string]bool{}
	for _, v := range got {
		if seen[v] {
			t.Errorf("duplicate fingerprint %s in %v", v, got)
		}
		seen[v] = true
	}
}
