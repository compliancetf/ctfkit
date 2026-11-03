package tagging_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/tagging"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A finding anchors to the file OpenTofu declares the resource in: never an
// override file that restates it (bucket_override sorts before main), and the
// .tofu twin rather than the .tf copy it shadows.
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
			in := input(buildPlan(t, `{}`,
				change("aws_s3_bucket.logs", "aws_s3_bucket", "create", `{"tags": {}}`, `{}`),
				change("aws_s3_bucket.archive", "aws_s3_bucket", "create", `{"tags": {}}`, `{}`)),
				[]ctfkit.TagRule{{Key: "Owner", Required: true}})
			in.Config = config

			r := ctfkit.NewRegistry()
			tagging.Register(r)
			got := map[string]string{}
			for _, a := range r.ByStage(ctfkit.PostPlan) {
				produced, err := a.Analyze(context.Background(), in)
				if err != nil {
					t.Fatalf("%s: %v", a.ID(), err)
				}
				for _, f := range produced {
					if p := f.Locations[0].PhysicalLocation; p != nil {
						got[f.Locations[0].LogicalLocations[0].FullyQualifiedName] = p.ArtifactLocation.URI
					}
				}
			}
			for address, file := range want {
				if got[address] != file {
					t.Errorf("%s anchored to %q, want %q", address, got[address], file)
				}
			}
		})
	}
}
