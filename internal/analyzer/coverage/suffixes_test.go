package coverage_test

import (
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/coverage"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A manifest-less local module declared in any of the four configuration
// suffixes is read for its resource types, so it is told its served
// equivalent whatever syntax it is written in.
func TestManifestMissingReadsEverySuffix(t *testing.T) {
	for _, dir := range []string{"tf", "tofu", "tf-json", "tofu-json"} {
		t.Run(dir, func(t *testing.T) {
			config, err := loader.LoadConfig(filepath.Join("..", "..", "..", "testdata", "postplan_json", dir))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			in := ctfkit.AnalyzerInput{
				Stage:   ctfkit.PostInit,
				Catalog: fixtureCatalog(t),
				Config:  config,
				Modules: &ctfkit.ModuleInventory{Root: ".", Instances: []ctfkit.ModuleInstance{{
					Key: "store", Source: "./modules/store", Dir: "modules/store",
				}}},
			}
			findings := analyzeOne(t, coverage.ManifestMissing{}, in)
			if len(findings) != 1 {
				t.Fatalf("got %d finding(s), want 1", len(findings))
			}
			r := findings[0].Props.Remediation
			if r == nil || r.ModuleSource != "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws" {
				t.Errorf("remediation = %+v, want the served s3-bucket module", r)
			}
		})
	}
}
