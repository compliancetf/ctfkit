package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	hcljson "github.com/hashicorp/hcl/v2/json"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A block's location spans the whole block, header to closing brace, and
// Region hands that span to a finding.
func TestBlockLocationSpansTheWholeBlock(t *testing.T) {
	content := "\nmodule \"s3\" {\n  source = \"x\"\n\n  bucket = \"b\"\n}\n\nresource \"aws_s3_bucket\" \"r\" {}\n"
	result, err := New().ParseContent([]byte(content), "main.tf")
	if err != nil {
		t.Fatalf("ParseContent() error = %v", err)
	}
	if got, want := result.Modules[0].Location.Region(), (&ctfkit.Region{StartLine: 2, EndLine: 6}); *got != *want {
		t.Errorf("module Region() = %+v, want %+v", *got, *want)
	}
	if got, want := result.Resources[0].Location.Region(), (&ctfkit.Region{StartLine: 8, EndLine: 8}); *got != *want {
		t.Errorf("resource Region() = %+v, want %+v", *got, *want)
	}
	if (Location{File: "main.tf"}).Region() != nil {
		t.Error("Region() of a location with no line is not nil")
	}
}

// A JSON body has no source range of its own, but it reports the closing brace
// of its object as the place a missing item would go, so a .tf.json block
// spans its key to that brace, as a native block spans its header to its own.
func TestBlockRegionOfAJSONBlockSpansItsObject(t *testing.T) {
	content := "{\n  \"module\": {\n    \"s3\": {\n      \"source\": \"x\",\n      \"bucket\": \"b\"\n    }\n  }\n}\n"
	file, diags := hcljson.Parse([]byte(content), "main.tf.json")
	if diags.HasErrors() {
		t.Fatalf("hcljson.Parse() = %v", diags)
	}
	schema := &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "module", LabelNames: []string{"name"}}}}
	moduleBlocks, _, _ := file.Body.PartialContent(schema)
	if len(moduleBlocks.Blocks) != 1 {
		t.Fatalf("got %d module blocks, want 1", len(moduleBlocks.Blocks))
	}
	got := BlockRegion(moduleBlocks.Blocks[0])
	if want := (ctfkit.Region{StartLine: 3, EndLine: 6}); got == nil || *got != want {
		t.Errorf("BlockRegion() = %+v, want %+v: the \"s3\" key to the closing brace of its object", got, want)
	}
}

func TestParseFile(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.tf")

	content := `
module "s3_bucket" {
  source  = "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket = "my-bucket"
  acl    = "private"
}

resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
}

variable "region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}
`

	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Parse the file
	parser := New()
	result, err := parser.ParseFile(testFile)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Verify results
	if len(result.Modules) != 1 {
		t.Errorf("Expected 1 module, got %d", len(result.Modules))
	} else {
		module := result.Modules[0]
		if module.Name != "s3_bucket" {
			t.Errorf("Expected module name 's3_bucket', got '%s'", module.Name)
		}
		if module.Source != "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws" {
			t.Errorf("Unexpected module source: %s", module.Source)
		}
		if module.Version != "~> 3.0" {
			t.Errorf("Expected version '~> 3.0', got '%s'", module.Version)
		}
	}

	if len(result.Resources) != 1 {
		t.Errorf("Expected 1 resource, got %d", len(result.Resources))
	} else {
		resource := result.Resources[0]
		if resource.Type != "aws_s3_bucket" {
			t.Errorf("Expected resource type 'aws_s3_bucket', got '%s'", resource.Type)
		}
		if resource.Name != "example" {
			t.Errorf("Expected resource name 'example', got '%s'", resource.Name)
		}
	}

	if len(result.Variables) != 1 {
		t.Errorf("Expected 1 variable, got %d", len(result.Variables))
	} else {
		variable := result.Variables[0]
		if variable.Name != "region" {
			t.Errorf("Expected variable name 'region', got '%s'", variable.Name)
		}
	}
}

func TestParseDirectory(t *testing.T) {
	// Create test directory structure
	tmpDir := t.TempDir()

	// Create main.tf
	mainTf := filepath.Join(tmpDir, "main.tf")
	mainContent := `
module "vpc" {
  source = "pcidss.compliance.tf/terraform-aws-modules/vpc/aws"
}
`
	if err := os.WriteFile(mainTf, []byte(mainContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Create variables.tf
	varsTf := filepath.Join(tmpDir, "variables.tf")
	varsContent := `
variable "environment" {
  type = string
}
`
	if err := os.WriteFile(varsTf, []byte(varsContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Create .terraform directory (should be skipped)
	terraformDir := filepath.Join(tmpDir, ".terraform")
	//nolint:gosec // Test directory
	if err := os.Mkdir(terraformDir, 0750); err != nil {
		t.Fatal(err)
	}
	ignoredFile := filepath.Join(terraformDir, "ignored.tf")
	if err := os.WriteFile(ignoredFile, []byte("# Should be ignored"), 0600); err != nil {
		t.Fatal(err)
	}

	// Parse directory
	parser := New()
	result, err := parser.ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}

	// Verify results
	if len(result.Files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(result.Files))
	}
	if len(result.Modules) != 1 {
		t.Errorf("Expected 1 module, got %d", len(result.Modules))
	}
	if len(result.Variables) != 1 {
		t.Errorf("Expected 1 variable, got %d", len(result.Variables))
	}
}

func TestParseModulesJSON(t *testing.T) {
	content := `{
  "version": "1",
  "Modules": [
    {
      "Key": "s3_bucket",
      "Source": "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws",
      "Version": "3.0.1",
      "Dir": ".terraform/modules/s3_bucket"
    },
    {
      "Key": "vpc",
      "Source": "git::https://github.com/example/vpc.git",
      "Dir": ".terraform/modules/vpc",
      "Git": {
        "url": "https://github.com/example/vpc.git",
        "ref": "main"
      }
    }
  ]
}`

	parser := NewModulesJSONParser(true)
	modules, err := parser.ParseContent([]byte(content))
	if err != nil {
		t.Fatalf("ParseContent failed: %v", err)
	}

	if len(modules.Modules) != 2 {
		t.Errorf("Expected 2 modules, got %d", len(modules.Modules))
	}

	// Check first module
	if modules.Modules[0].Source != "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws" {
		t.Errorf("Unexpected source for first module: %s", modules.Modules[0].Source)
	}

	// Check second module has Git info
	if modules.Modules[1].Git == nil {
		t.Error("Expected Git info for second module")
	}
}

func TestParseInvalidHCL(t *testing.T) {
	// Test with invalid HCL
	parser := New()
	result, err := parser.ParseContent([]byte("invalid { hcl content"), "test.tf")

	// Should not return error but should have parse errors
	if err != nil {
		t.Fatalf("ParseContent should not fail on invalid HCL: %v", err)
	}

	if len(result.Errors) == 0 {
		t.Error("Expected parse errors for invalid HCL")
	}
}

// Provisioners are read from resource and removed blocks, and data blocks are
// listed, in native syntax and in JSON (object and array forms), each anchored
// to its own block.
func TestParseConfigContentProvisionersAndDataSources(t *testing.T) {
	native := `resource "terraform_data" "run" {
  provisioner "local-exec" {
    command = "true"
  }
  provisioner "file" {
    source = "a"
  }
}

removed {
  from = terraform_data.old
  provisioner "local-exec" {
    when    = destroy
    command = "true"
  }
}

data "external" "probe" {
  program = ["true"]
}
`
	jsonDoc := `{
  "resource": {"terraform_data": {"run": {"provisioner": [
    {"local-exec": {"command": "true"}},
    {"file": {"source": "a"}}
  ]}}},
  "removed": [{"from": "terraform_data.old", "provisioner": {"local-exec": {"command": "true"}}}],
  "data": {"external": {"probe": {"program": ["true"]}}}
}
`
	wantProvisioners := []string{"terraform_data.run|local-exec", "terraform_data.run|file", "terraform_data.old|local-exec"}

	for _, tc := range []struct {
		name, file, content string
	}{
		{"native", "main.tf", native},
		{"json", "main.tf.json", jsonDoc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseConfigContent([]byte(tc.content), tc.file)
			if len(result.Errors) > 0 {
				t.Fatalf("parse errors: %+v", result.Errors)
			}
			var got []string
			for _, p := range result.Provisioners {
				got = append(got, p.Owner+"|"+p.Type)
				if p.Location.File != tc.file || p.Location.Region() == nil {
					t.Errorf("provisioner %s|%s has no location in %s: %+v", p.Owner, p.Type, tc.file, p.Location)
				}
			}
			if strings.Join(got, ",") != strings.Join(wantProvisioners, ",") {
				t.Errorf("provisioners = %q, want %q", got, wantProvisioners)
			}
			if len(result.DataSources) != 1 || result.DataSources[0].Type != "external" ||
				result.DataSources[0].Name != "probe" || result.DataSources[0].Location.Region() == nil {
				t.Errorf("data sources = %+v, want one external.probe with a region", result.DataSources)
			}
		})
	}
}

// A data block nested in a check block is listed with its check scope, in
// native syntax and in JSON; a top-level one has none (the
// scoped external data source runs at plan like any other).
func TestParseConfigContentCheckScopedDataSources(t *testing.T) {
	native := "data \"external\" \"top\" {}\n\ncheck \"health\" {\n  data \"external\" \"probe\" {\n    program = [\"true\"]\n  }\n\n  assert {\n    condition     = true\n    error_message = \"x\"\n  }\n}\n"
	jsonDoc := `{"data": {"external": {"top": {}}}, "check": {"health": {"data": {"external": {"probe": {"program": ["true"]}}}, "assert": [{"condition": true, "error_message": "x"}]}}}`
	for _, tc := range []struct{ name, file, content string }{
		{"native", "main.tf", native},
		{"json", "main.tf.json", jsonDoc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseConfigContent([]byte(tc.content), tc.file)
			if len(result.Errors) > 0 {
				t.Fatalf("parse errors: %+v", result.Errors)
			}
			var got []string
			for _, d := range result.DataSources {
				got = append(got, d.Scope+"|"+d.Type+"."+d.Name)
				if d.Location.Region() == nil {
					t.Errorf("%s.%s has no region", d.Type, d.Name)
				}
			}
			if want := "|external.top,check.health|external.probe"; strings.Join(got, ",") != want {
				t.Errorf("data sources = %q, want %q", got, want)
			}
		})
	}
}

// A removed block whose from is not a plain reference still has its
// provisioners listed, under the owner "removed".
func TestRemovedFromFallback(t *testing.T) {
	result := ParseConfigContent([]byte("removed {\n  provisioner \"local-exec\" {}\n}\n"), "main.tf")
	if len(result.Provisioners) != 1 || result.Provisioners[0].Owner != "removed" {
		t.Errorf("provisioners = %+v, want one owned by removed", result.Provisioners)
	}
}
