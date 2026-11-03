package modulesource_test

import (
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A planned raw resource anchors to the file OpenTofu declares it in: never an
// override file that restates it (bucket_override sorts before main), and the
// .tofu twin rather than the .tf copy it shadows.
func TestPostPlanAnchorsPastOverridesAndShadowedTwins(t *testing.T) {
	for syntax, want := range map[string]map[string]string{
		"native": {"aws_s3_bucket.logs": "main.tf", "aws_s3_bucket.archive": "storage.tofu"},
		"json":   {"aws_s3_bucket.logs": "main.tf.json", "aws_s3_bucket.archive": "storage.tofu.json"},
	} {
		t.Run(syntax, func(t *testing.T) {
			config, err := loader.LoadConfig(filepath.Join("..", "..", "..", "testdata", "override_twins", syntax))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			for address, file := range want {
				findings := analyzeTyped(t, ctfkit.AnalyzerInput{
					Stage:    ctfkit.PostPlan,
					Config:   config,
					PlanJSON: planWithResources(address, "aws_s3_bucket"),
					Catalog:  fixtureCatalog(t),
				})
				if len(findings) != 1 {
					t.Fatalf("%s: got %d findings, want 1", address, len(findings))
				}
				if p := findings[0].Locations[0].PhysicalLocation; p == nil || p.ArtifactLocation.URI != file {
					t.Errorf("%s anchored to %+v, want %s", address, p, file)
				}
			}
		})
	}
}
