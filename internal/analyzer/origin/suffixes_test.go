package origin_test

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Every origin rule reads all four configuration suffixes the loader loads.
// The four fixtures state one configuration each, in native
// syntax (.tf, .tofu) and in JSON (.tf.json, .tofu.json; the latter in array
// form, with "//" comment properties and configuration_aliases), and every
// pre_plan origin rule reports the same subjects in each, anchored to that
// file with a line range.
func TestOriginRulesReadEverySuffix(t *testing.T) {
	want := []string{
		`ctf.origin.provider_resource_type|aws_instance`,
		`ctf.origin.provider_unpinned|provider["registry.terraform.io/hashicorp/aws"]`,
		`ctf.origin.provider_unverified|provider["registry.terraform.io/hashicorp/aws"]`,
		`ctf.origin.provider|provider["registry.terraform.io/hashicorp/aws"]`,
		`ctf.policy.floating_ref_unbounded|module.open`,
		`ctf.policy.floating_ref|module.branch`,
	}
	sort.Strings(want)

	for dir, file := range map[string]string{
		"tf": "main.tf", "tofu": "main.tofu", "tf-json": "main.tf.json", "tofu-json": "main.tofu.json",
	} {
		t.Run(dir, func(t *testing.T) {
			archive, err := loader.LoadConfig(filepath.Join("..", "..", "..", "testdata", "origin", "suffixes", dir))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			archive.ClassifyModules = true // a directory scan: the fixture is its own root
			findings := analyze(t, ctfkit.AnalyzerInput{
				Stage: ctfkit.PrePlan, Config: archive, Catalog: catalog.Embedded(),
				Settings: ctfkit.Settings{
					AllowedProviders: []string{"registry.terraform.io/hashicorp/random"},
					AllowedResources: []string{"aws_s3_bucket"},
				},
			})
			if got := ruleSubjects(findings); !reflect.DeepEqual(got, want) {
				t.Errorf("got  %q\nwant %q", got, want)
			}
			for _, f := range findings {
				p := f.Locations[0].PhysicalLocation
				if p == nil || p.ArtifactLocation.URI != file || p.Region == nil ||
					p.Region.StartLine < 1 || p.Region.EndLine < p.Region.StartLine {
					t.Errorf("%s|%s is not anchored to a line range of %s: %+v", f.RuleID, subject(f), file, p)
				}
			}
		})
	}
}
