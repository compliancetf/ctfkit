package coverage_test

import (
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/coverage"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// modules/store declares an aws_s3_bucket and an aws_iam_role in main.tf, only
// the role in its main.tofu twin, and role_override restates the role. OpenTofu
// reads main.tofu instead of main.tf and an override declares nothing, so the
// module holds only the role, which the catalog does not cover: no served
// equivalent is named. (Terraform, which never reads main.tofu, would see the
// bucket too; ctfkit takes OpenTofu's reading of twins.) Both readings load
// cleanly: testdata/override_twins/check.sh.
func TestManifestMissingSkipsOverridesAndShadowedTwins(t *testing.T) {
	for _, syntax := range []string{"native", "json"} {
		t.Run(syntax, func(t *testing.T) {
			config, err := loader.LoadConfig(filepath.Join("..", "..", "..", "testdata", "override_twins", syntax))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			findings := analyzeOne(t, coverage.ManifestMissing{}, ctfkit.AnalyzerInput{
				Stage:   ctfkit.PostInit,
				Catalog: fixtureCatalog(t),
				Config:  config,
				Modules: &ctfkit.ModuleInventory{Root: ".", Instances: []ctfkit.ModuleInstance{{
					Key: "store", Source: "./modules/store", Dir: "modules/store",
				}}},
			})
			if len(findings) != 1 {
				t.Fatalf("got %d finding(s), want 1", len(findings))
			}
			if r := findings[0].Props.Remediation; r != nil {
				t.Errorf("remediation = %+v, want none: the module declares only an aws_iam_role", *r)
			}
		})
	}
}
