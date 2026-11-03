package sensitivechange_test

import (
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A root resource declared in any of the four configuration suffixes anchors
// its post_plan finding to the file and the whole block that declare it.
func TestFindingsAnchorToEverySuffix(t *testing.T) {
	for dir, file := range map[string]string{
		"tf": "main.tf", "tofu": "main.tofu", "tf-json": "main.tf.json", "tofu-json": "main.tofu.json",
	} {
		t.Run(dir, func(t *testing.T) {
			config, err := loader.LoadConfig(filepath.Join("..", "..", "..", "testdata", "postplan_json", dir))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			in := ctfkit.AnalyzerInput{
				Stage:    ctfkit.PostPlan,
				Config:   config,
				Catalog:  fixtureCatalog(t),
				PlanJSON: plan(t, rc{"aws_s3_bucket.logs", `["delete"]`, `{"bucket": "bobthecorp-logs"}`, `null`, ``, ``}),
			}
			findings := run(t, in)
			if len(findings) == 0 {
				t.Fatal("got no finding for the deleted bucket")
			}
			for _, f := range findings {
				p := f.Locations[0].PhysicalLocation
				if p == nil || p.ArtifactLocation.URI != file || p.Region == nil || p.Region.StartLine < 1 || p.Region.EndLine <= p.Region.StartLine {
					t.Errorf("%s is not anchored to the whole block in %s: %+v", f.RuleID, file, p)
				}
			}
		})
	}
}
