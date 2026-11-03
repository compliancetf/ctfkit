package origin_test

import (
	"reflect"
	"testing"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A templated value is not a literal in either syntax. JSON reads a string as
// a template only when it is evaluated in a context, so without one
// "${var.ref}" would come through as text where native syntax skips it; the
// two syntaxes must report the same.
func TestTemplatedValuesAreNotLiteralsInEitherSyntax(t *testing.T) {
	cases := []struct {
		name, native, json string
		want               []string
	}{
		{
			"a templated git ref is not read",
			`module "tpl" {
  source = "git::https://github.com/bobthecorp/x.git?ref=${var.ref}"
}`,
			`{"module": {"tpl": {"source": "git::https://github.com/bobthecorp/x.git?ref=${var.ref}"}}}`,
			[]string{},
		},
		{
			"a templated registry source is not read",
			`module "reg" {
  source = "terraform-aws-modules/${var.name}/aws"
}`,
			`{"module": {"reg": {"source": "terraform-aws-modules/${var.name}/aws"}}}`,
			[]string{},
		},
		{
			"a templated module version is no version",
			`module "v" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "${var.v}"
}`,
			`{"module": {"v": {"source": "terraform-aws-modules/vpc/aws", "version": "${var.v}"}}}`,
			[]string{"ctf.policy.floating_ref_unbounded|module.v"},
		},
		{
			"a templated provider alias is no alias",
			`provider "aws" {
  alias = "${var.alias}"
}`,
			`{"provider": {"aws": {"alias": "${var.alias}"}}}`,
			[]string{`ctf.origin.provider|provider["registry.terraform.io/hashicorp/aws"]`},
		},
		{
			"a templated required_providers version refuses the entry",
			`terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "${var.v}"
    }
  }
}`,
			`{"terraform": {"required_providers": {"aws": {"source": "hashicorp/aws", "version": "${var.v}"}}}}`,
			[]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for file, body := range map[string]string{"main.tf": tc.native, "main.tf.json": tc.json} {
				archive := &ctfkit.ConfigArchive{Root: ".", Files: []ctfkit.ConfigFile{{Path: file, Bytes: []byte(body)}}}
				got := ruleSubjects(analyze(t, ctfkit.AnalyzerInput{
					Stage: ctfkit.PrePlan, Config: archive, Catalog: catalog.Embedded(),
					Settings: ctfkit.Settings{AllowedProviders: []string{"registry.terraform.io/hashicorp/random"}},
				}))
				if !reflect.DeepEqual(got, tc.want) {
					t.Errorf("%s: got %q, want %q", file, got, tc.want)
				}
			}
		})
	}
}
