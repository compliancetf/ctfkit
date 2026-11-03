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

// A required_providers entry that lists configuration_aliases is read like
// any other: its provider references do not hide the literal source and
// version beside them.
func TestConfigurationAliasesEntriesAreRead(t *testing.T) {
	archive, err := loader.LoadConfig(filepath.Join("..", "..", "..", "testdata", "origin", "configuration_aliases"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	got := ruleSubjects(analyze(t, ctfkit.AnalyzerInput{
		Stage: ctfkit.PrePlan, Config: archive, Catalog: catalog.Embedded(),
		Settings: ctfkit.Settings{AllowedProviders: []string{"registry.terraform.io/hashicorp/random"}},
	}))
	want := []string{
		`ctf.origin.provider_unpinned|provider["registry.terraform.io/hashicorp/aws"]`,
		`ctf.origin.provider_unverified|provider["registry.terraform.io/hashicorp/aws"]`,
		`ctf.origin.provider|provider["registry.terraform.io/hashicorp/aws"]`,
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// The item-by-item reading takes source and version only when they are
// literal strings, and never guesses one it cannot read.
func TestConfigurationAliasesItems(t *testing.T) {
	cases := []struct {
		name, entry string
		want        []string
	}{
		{"quoted keys", `"source" = "hashicorp/aws"
      "version" = ">= 6.0"
      configuration_aliases = [aws.peer]`, []string{`ctf.origin.provider_unpinned|provider["registry.terraform.io/hashicorp/aws"]`}},
		{"no version", `source = "hashicorp/aws"
      configuration_aliases = [aws.peer]`, []string{`ctf.origin.provider_unpinned|provider["registry.terraform.io/hashicorp/aws"]`}},
		{"bounded version", `source = "hashicorp/aws"
      version = "~> 6.0"
      configuration_aliases = [aws.peer]`, []string{}},
		{"no source is the implied hashicorp one", `version = ">= 6.0"
      configuration_aliases = [aws.peer]`, []string{`ctf.origin.provider_unpinned|provider["registry.terraform.io/hashicorp/aws"]`}},
		{"a version that is not a literal is not read", `source = "hashicorp/aws"
      version = var.aws_version
      configuration_aliases = [aws.peer]`, []string{}},
		{"a key that is not a literal refuses the entry", `source = "hashicorp/aws"
      (local.version_key) = ">= 6.0"
      configuration_aliases = [aws.peer]`, []string{}},
		{"a number version beside aliases is not read", `source = "hashicorp/aws"
      version = 6
      configuration_aliases = [aws.peer]`, []string{}},
		{"a number version is not read as no version", `source = "hashicorp/aws"
      version = 6`, []string{}},
		{"a number source is not read as the implied one", `source = 6
      version = ">= 6.0"`, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := "terraform {\n  required_providers {\n    aws = {\n      " + tc.entry + "\n    }\n  }\n}\n"
			archive := &ctfkit.ConfigArchive{Root: ".", Files: []ctfkit.ConfigFile{{Path: "versions.tf", Bytes: []byte(body)}}}
			got := ruleSubjects(analyze(t, ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan, Config: archive, Catalog: catalog.Embedded()}))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// An aliased entry with a source outside the default namespace is now read,
// so a resource of that provider resolves to the declared source instead of
// the implied hashicorp/<name>, and ctf.origin.provider names the declared
// source at the required_providers entry, which comes first.
func TestConfigurationAliasesDeclaredSourceWins(t *testing.T) {
	body := `terraform {
  required_providers {
    acme = {
      source                = "bobthecorp/acme"
      version               = "~> 6.0"
      configuration_aliases = [acme.org]
    }
  }
}

resource "acme_widget" "r" {
  provider = acme.org
}
`
	archive := &ctfkit.ConfigArchive{Root: ".", Files: []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(body)}}}
	got := ruleSubjects(analyze(t, ctfkit.AnalyzerInput{
		Stage: ctfkit.PrePlan, Config: archive, Catalog: catalog.Embedded(),
		Settings: ctfkit.Settings{AllowedProviders: []string{"registry.terraform.io/hashicorp/random"}},
	}))
	want := []string{`ctf.origin.provider|provider["registry.terraform.io/bobthecorp/acme"]`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func ruleSubjects(findings ctfkit.Findings) []string {
	out := []string{}
	for _, f := range findings {
		out = append(out, f.RuleID+"|"+subject(f))
	}
	sort.Strings(out)
	return out
}
