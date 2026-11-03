package modulesource_test

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// suffixCases are one configuration in each suffix the loader loads: an
// upstream module, a compliance.tf-served module, a third-party module and a
// raw bucket. The .tofu.json case uses the array forms and "//" comment
// properties.
var suffixCases = map[string]string{
	"tf": "main.tf", "tofu": "main.tofu", "tf-json": "main.tf.json", "tofu-json": "main.tofu.json",
}

func loadSuffixCase(t *testing.T, dir string) *ctfkit.ConfigArchive {
	t.Helper()
	archive, err := loader.LoadConfig(filepath.Join("..", "..", "..", "testdata", "module_source", "suffixes", dir))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return archive
}

// At pre_plan the module blocks of every suffix are read: the upstream module
// is a migration candidate and the third-party one is listed, each anchored to
// a line range of its own file; the served module says nothing.
func TestPrePlanReadsEverySuffix(t *testing.T) {
	want := []string{
		"error|module.vpc",
		"note|module.other",
	}
	for dir, file := range suffixCases {
		t.Run(dir, func(t *testing.T) {
			findings := analyzeTyped(t, ctfkit.AnalyzerInput{
				Stage: ctfkit.PrePlan, Config: loadSuffixCase(t, dir), Catalog: fixtureCatalog(t),
			})
			got := []string{}
			for _, f := range findings {
				got = append(got, f.Level+"|"+f.Subject())
				assertAnchored(t, f, file)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got  %q\nwant %q", got, want)
			}
		})
	}
}

// At post_plan the configuration anchors a planned raw resource to the file
// that declares it, whichever suffix that file has.
func TestPostPlanAnchorsToEverySuffix(t *testing.T) {
	for dir, file := range suffixCases {
		t.Run(dir, func(t *testing.T) {
			findings := analyzeTyped(t, ctfkit.AnalyzerInput{
				Stage:    ctfkit.PostPlan,
				Config:   loadSuffixCase(t, dir),
				PlanJSON: planWithResources("aws_s3_bucket.logs", "aws_s3_bucket"),
				Catalog:  fixtureCatalog(t),
			})
			if len(findings) != 1 || findings[0].Subject() != "aws_s3_bucket.logs" {
				t.Fatalf("got %+v, want one finding on aws_s3_bucket.logs", findings)
			}
			assertAnchored(t, findings[0], file)
		})
	}
}

// A templated module source is not a literal in JSON either, so it is not
// classified, exactly as in native syntax.
func TestPrePlanSkipsTemplatedJSONSources(t *testing.T) {
	for name, body := range map[string]string{
		"templated registry path": `{"module": {"m": {"source": "terraform-aws-modules/${var.name}/aws", "version": "~> 6.0"}}}`,
		"templated whole source":  `{"module": {"m": {"source": "${var.source}"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			archive := &ctfkit.ConfigArchive{Root: ".", Files: []ctfkit.ConfigFile{{Path: "main.tf.json", Bytes: []byte(body)}}}
			if findings := analyzeTyped(t, ctfkit.AnalyzerInput{
				Stage: ctfkit.PrePlan, Config: archive, Catalog: fixtureCatalog(t),
			}); len(findings) != 0 {
				t.Errorf("got %+v, want no finding for a templated source", findings)
			}
		})
	}
}

func assertAnchored(t *testing.T, f ctfkit.Finding, file string) {
	t.Helper()
	p := f.Locations[0].PhysicalLocation
	if p == nil || p.ArtifactLocation.URI != file || p.Region == nil ||
		p.Region.StartLine < 1 || p.Region.EndLine <= p.Region.StartLine {
		t.Errorf("%s is not anchored to the whole multi-line block in %s: %+v", f.Subject(), file, p)
	}
}
