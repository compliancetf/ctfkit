package sensitivechange_test

import (
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A finding anchors to the .tofu twin OpenTofu reads, not the .tf copy it
// shadows, and never to an override file.
func TestFindingsAnchorPastOverridesAndShadowedTwins(t *testing.T) {
	for syntax, want := range map[string]map[string]string{
		"native": {"aws_s3_bucket.logs": "main.tf", "aws_s3_bucket.archive": "storage.tofu"},
		"json":   {"aws_s3_bucket.logs": "main.tf.json", "aws_s3_bucket.archive": "storage.tofu.json"},
	} {
		t.Run(syntax, func(t *testing.T) {
			config, err := loader.LoadConfig(filepath.Join("..", "..", "..", "testdata", "override_twins", syntax))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			findings := run(t, ctfkit.AnalyzerInput{
				Stage:   ctfkit.PostPlan,
				Config:  config,
				Catalog: fixtureCatalog(t),
				PlanJSON: plan(t,
					rc{"aws_s3_bucket.logs", `["delete"]`, `{"bucket": "bobthecorp-logs"}`, `null`, ``, ``},
					rc{"aws_s3_bucket.archive", `["delete"]`, `{"bucket": "bobthecorp-archive"}`, `null`, ``, ``}),
			})
			got := map[string]string{}
			for _, f := range findings {
				if p := f.Locations[0].PhysicalLocation; p != nil {
					got[f.Subject()] = p.ArtifactLocation.URI
				}
			}
			for address, file := range want {
				if got[address] != file {
					t.Errorf("%s anchored to %q, want %q (all: %v)", address, got[address], file, got)
				}
			}
		})
	}
}
