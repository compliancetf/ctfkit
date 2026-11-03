package origin_test

import (
	"context"
	"encoding/json"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/origin"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const unpinnedRoot = "../../../testdata/origin/provider_unpinned"

// unpinnedCases are the provider_unpinned fixture trees. Every directory in them
// declares one aws requirement with no upper bound in versions.tf, so an
// unclassified scan reports every versions.tf, and want lists the ones a
// classified directory scan still reports.
var unpinnedCases = []struct {
	name string
	want []string
}{
	// A backend or cloud block makes a directory a root.
	{"01-backend-root", []string{"stacks/cloud/versions.tf", "stacks/prod/versions.tf", "versions.tf"}},
	// The scan root with no signal of its own is a root.
	{"02-bare-root", []string{"versions.tf"}},
	// A module repository: the example that configures a provider and calls
	// ../../ is the only root; the scan root, modules/ and wrappers/ are not.
	{"03-module-repo", []string{"examples/complete/versions.tf"}},
	// A provider block keeps an uncalled subdirectory a root; a call from a
	// root demotes the called one.
	{"04-subdir-provider", []string{"uncalled/versions.tf", "versions.tf"}},
	// configuration_aliases is not a provider block, so aliased/ is a module
	// and neither its versions.tf nor its aliases.tf entry is reported.
	{"05-configuration-aliases", []string{"versions.tf"}},
	// An escaping path, an absolute path and a remote //subdir name no
	// directory of the archive, so modules/sub keeps its provider-block root.
	{"06-escaping-and-registry", []string{"modules/sub/versions.tf", "versions.tf"}},
	// A .tf.json caller with an array-form provider demotes the scan root, a
	// .tofu caller demotes modules/a, a .tf.json backend in array form keeps
	// stacks/prod a root and its call demotes modules/b.
	{"07-json-and-tofu", []string{"examples/json/versions.tf", "examples/tofu/versions.tf", "stacks/prod/versions.tf"}},
	// Known false negative (i): live/app deploys, but nothing says so.
	{"09-fn-uncalled-deployable", []string{"versions.tf"}},
	// .\ and ..\ are local sources.
	{"10-backslash-source", []string{"examples/x/versions.tf", "versions.tf"}},
	// A backend outranks a call; a provider block does not.
	{"11-called-backend", []string{"stacks/a/versions.tf", "versions.tf"}},
	// A directory calling itself is not demoted.
	{"12-self-edge", []string{"a/versions.tf", "versions.tf"}},
	// Known false negative (ii): the scan root and app deploy, but a root in
	// the same scan calls each of them.
	{"13-fn-called-deployable", []string{"examples/complete/versions.tf"}},
	// A caller with no root signal does not demote the scan root.
	{"14-wrappers-no-evidence", []string{"versions.tf"}},
}

// TestProviderUnpinnedClassifiedDirectory is the directory scan: a
// requirement in a reusable module directory is not reported.
func TestProviderUnpinnedClassifiedDirectory(t *testing.T) {
	for _, tc := range unpinnedCases {
		t.Run(tc.name, func(t *testing.T) {
			archive := loadUnpinned(t, tc.name)
			archive.ClassifyModules = true
			if got := unpinnedURIs(t, archive); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("reported %q\n     want %q", got, tc.want)
			}
		})
	}
}

// TestProviderUnpinnedZeroValueIsUnchanged: an archive that does not ask for
// classification, which is every archive built before the field existed and
// every explicit file list, reports every unbounded requirement in every
// directory, and classification only ever drops findings, never alters one.
func TestProviderUnpinnedZeroValueIsUnchanged(t *testing.T) {
	for _, tc := range unpinnedCases {
		t.Run(tc.name, func(t *testing.T) {
			archive := loadUnpinned(t, tc.name)
			var all []string
			for _, f := range archive.Files {
				// 05's aliases.tf holds the one requirement outside a
				// versions.tf, an entry with configuration_aliases.
				if base := path.Base(f.Path); base == "versions.tf" || base == "aliases.tf" {
					all = append(all, f.Path)
				}
			}
			sort.Strings(all)
			if got := unpinnedURIs(t, archive); !reflect.DeepEqual(got, all) {
				t.Errorf("zero value reported %q\n                want %q", got, all)
			}

			unclassified := marshalEach(t, unpinned(t, archive))
			classified := *archive
			classified.ClassifyModules = true
			for _, raw := range marshalEach(t, unpinned(t, &classified)) {
				if !slices.Contains(unclassified, raw) {
					t.Errorf("classified finding is not one the zero value reports: %s", raw)
				}
			}
		})
	}
}

// TestClassificationLeavesOtherOriginRulesAlone: every origin rule but
// provider_unpinned reports the same findings whether or not the archive asks
// for classification, including in the directories it classifies as modules.
func TestClassificationLeavesOtherOriginRulesAlone(t *testing.T) {
	for _, tc := range unpinnedCases {
		t.Run(tc.name, func(t *testing.T) {
			archive := loadUnpinned(t, tc.name)
			settings := ctfkit.Settings{
				AllowedProviders: []string{"registry.terraform.io/hashicorp/random"},
				AllowedResources: []string{"aws_instance"},
			}
			others := func(a *ctfkit.ConfigArchive) []string {
				var out []string
				for _, f := range analyze(t, ctfkit.AnalyzerInput{
					Stage: ctfkit.PrePlan, Config: a, Catalog: catalog.Embedded(), Settings: settings,
				}) {
					if f.RuleID == "ctf.origin.provider_unpinned" {
						continue
					}
					raw, err := json.Marshal(f)
					if err != nil {
						t.Fatal(err)
					}
					out = append(out, string(raw))
				}
				return out
			}
			before := others(archive)
			classified := *archive
			classified.ClassifyModules = true
			if after := others(&classified); !reflect.DeepEqual(after, before) {
				t.Errorf("other origin rules changed under classification\n got %q\nwant %q", after, before)
			}
		})
	}

	// The module repository carries a lock file, a floating ref and resource
	// types outside the allowlist, so the comparison above is not vacuous.
	archive := loadUnpinned(t, "03-module-repo")
	archive.ClassifyModules = true
	seen := map[string]bool{}
	for _, f := range analyze(t, ctfkit.AnalyzerInput{
		Stage: ctfkit.PrePlan, Config: archive, Catalog: catalog.Embedded(),
		Settings: ctfkit.Settings{
			AllowedProviders: []string{"registry.terraform.io/hashicorp/random"},
			AllowedResources: []string{"aws_instance"},
		},
	}) {
		seen[f.RuleID+"|"+uri(f)] = true
	}
	for _, want := range []string{
		"ctf.origin.provider_unverified|modules/sub/versions.tf",
		"ctf.origin.provider_unverified|wrappers/versions.tf",
		"ctf.policy.floating_ref|modules/sub/main.tf",
		"ctf.origin.provider|versions.tf",
		"ctf.origin.provider_resource_type|main.tf",
	} {
		if !seen[want] {
			t.Errorf("missing %s; got %v", want, seen)
		}
	}
}

func loadUnpinned(t *testing.T, name string) *ctfkit.ConfigArchive {
	t.Helper()
	archive, err := loader.LoadConfig(filepath.Join(unpinnedRoot, name))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return archive
}

func unpinned(t *testing.T, archive *ctfkit.ConfigArchive) ctfkit.Findings {
	t.Helper()
	findings, err := origin.ProviderUnpinned{}.Analyze(context.Background(), ctfkit.AnalyzerInput{
		Stage: ctfkit.PrePlan, Config: archive, Catalog: catalog.Embedded(),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}

// unpinnedURIs is the sorted file of every provider_unpinned finding on the
// aws requirement.
func unpinnedURIs(t *testing.T, archive *ctfkit.ConfigArchive) []string {
	t.Helper()
	var out []string
	for _, f := range unpinned(t, archive) {
		out = append(out, uri(f))
	}
	sort.Strings(out)
	return nonNil(out)
}

func uri(f ctfkit.Finding) string {
	if len(f.Locations) == 0 || f.Locations[0].PhysicalLocation == nil {
		return ""
	}
	return f.Locations[0].PhysicalLocation.ArtifactLocation.URI
}

func marshalEach(t *testing.T, findings ctfkit.Findings) []string {
	t.Helper()
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(raw))
	}
	return out
}
