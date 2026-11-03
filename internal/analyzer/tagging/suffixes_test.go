package tagging_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/tagging"
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
			in := input(buildPlan(t, `{}`,
				change("aws_s3_bucket.logs", "aws_s3_bucket", "create", `{"tags": {}}`, `{}`)),
				[]ctfkit.TagRule{{Key: "Owner", Required: true}})
			in.Config = config

			r := ctfkit.NewRegistry()
			tagging.Register(r)
			var findings ctfkit.Findings
			for _, a := range r.ByStage(ctfkit.PostPlan) {
				produced, err := a.Analyze(context.Background(), in)
				if err != nil {
					t.Fatalf("%s: %v", a.ID(), err)
				}
				findings = append(findings, produced...)
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want the missing Owner tag: %+v", len(findings), findings)
			}
			p := findings[0].Locations[0].PhysicalLocation
			if p == nil || p.ArtifactLocation.URI != file || p.Region == nil || p.Region.StartLine < 1 || p.Region.EndLine <= p.Region.StartLine {
				t.Errorf("finding is not anchored to the whole block in %s: %+v", file, p)
			}
		})
	}
}
