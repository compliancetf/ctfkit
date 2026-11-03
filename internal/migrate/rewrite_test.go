package migrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// rewriteFixtures are the PM-T04 oracle cases, and the PM-T05 blocked cases: expected/migrate-plan.json
// edits[] and expected/files/ per fixture.
var rewriteFixtures = []string{
	"01-single-root-local",
	"02-aliases-and-configuration-aliases",
	"03-local-modules",
	"04-remote-module-blocked",
	"05-implied-provider",
	"09-opentofu-host",
	"14-tf-json-blocked",
	"18-hard-fail-violations",
}

type fixturePlan struct {
	Providers []Provider `json:"providers"`
	Units     []Unit     `json:"units"`
	Edits     []Edit     `json:"edits"`
}

func readFixturePlan(t *testing.T, dir string) fixturePlan {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "expected", "migrate-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p fixturePlan
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRewriteFixtures: Rewrite on input/ yields the expected edits[] and,
// byte for byte, the files under expected/files/, and nothing else.
func TestRewriteFixtures(t *testing.T) {
	for _, name := range rewriteFixtures {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("..", "..", "testdata", "fixtures", "migrate", name)
			want := readFixturePlan(t, dir)
			got, err := Rewrite(filepath.Join(dir, "input"), want.Units, want.Providers)
			if err != nil {
				t.Fatal(err)
			}
			meta := make([]Edit, len(got))
			for i, e := range got {
				meta[i] = e
				meta[i].Content = nil
			}
			if !reflect.DeepEqual(meta, want.Edits) {
				g, _ := json.MarshalIndent(meta, "", "  ")
				w, _ := json.MarshalIndent(want.Edits, "", "  ")
				t.Errorf("edits:\n%s\nwant:\n%s", g, w)
			}

			files := filepath.Join(dir, "expected", "files")
			wantFiles := map[string][]byte{}
			err = filepath.WalkDir(files, func(p string, d fs.DirEntry, err error) error {
				if p == files && errors.Is(err, fs.ErrNotExist) {
					return nil // a case with no edits has no expected/files
				}
				if err != nil || d.IsDir() {
					return err
				}
				b, err := os.ReadFile(p)
				rel, _ := filepath.Rel(files, p)
				wantFiles[filepath.ToSlash(rel)] = b
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range got {
				w, ok := wantFiles[e.File]
				if !ok {
					t.Errorf("%s: edited, but not under expected/files", e.File)
					continue
				}
				if !bytes.Equal(e.Content, w) {
					t.Errorf("%s:\n%s\nwant:\n%s", e.File, e.Content, w)
				}
				if e.SHA256After != hashHex(w) {
					t.Errorf("%s: sha256_after %s does not hash the expected file", e.File, e.SHA256After)
				}
				delete(wantFiles, e.File)
			}
			for f := range wantFiles {
				t.Errorf("%s: under expected/files, but not edited", f)
			}
		})
	}
}

// TestRewriteIdempotent: the rewritten tree of every fixture needs no edit.
func TestRewriteIdempotent(t *testing.T) {
	for _, name := range rewriteFixtures {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("..", "..", "testdata", "fixtures", "migrate", name)
			want := readFixturePlan(t, dir)
			tmp := t.TempDir()
			if err := os.CopyFS(tmp, os.DirFS(filepath.Join(dir, "input"))); err != nil {
				t.Fatal(err)
			}
			for _, e := range want.Edits {
				b, err := os.ReadFile(filepath.Join(dir, "expected", "files", filepath.FromSlash(e.File)))
				if err == nil {
					err = os.WriteFile(filepath.Join(tmp, filepath.FromSlash(e.File)), b, 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := Rewrite(tmp, want.Units, want.Providers)
			if err != nil || len(got) != 0 {
				t.Fatalf("edits = %+v, err = %v; want none", got, err)
			}
		})
	}
}

var awsProvider = []Provider{{Type: "aws", To: "registry.compliance.tf/compliancetf/aws", RootConstraint: "~> 6.67", ModuleConstraint: ">= 6.0.0"}}

// rewriteOne runs Rewrite on a single-root tree and returns the content of
// each edited file.
func rewriteOne(t *testing.T, files map[string]string) (map[string]string, error) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	edits, err := Rewrite(dir, []Unit{{Dir: "."}}, awsProvider)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range edits {
		out[e.File] = string(e.Content)
	}
	return out, nil
}

func TestRewriteCases(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		want    map[string]string
		wantErr string
	}{
		{
			name: "object without source keeps comments and other keys",
			files: map[string]string{"main.tf": `terraform {
  required_providers {
    aws = {
      # pinned by bobthecorp platform
      version = "~> 6.0" # upstream
      configuration_aliases = [aws.west]
    }
  }
}
`},
			want: map[string]string{"main.tf": `terraform {
  required_providers {
    aws = {
      source = "registry.compliance.tf/compliancetf/aws"
      # pinned by bobthecorp platform
      version               = "~> 6.0" # upstream
      configuration_aliases = [aws.west]
    }
  }
}
`},
		},
		{
			name: "upper-case address on the Terraform host",
			files: map[string]string{"main.tf": `terraform {
  required_providers {
    aws = { source = "Registry.Terraform.io/HashiCorp/AWS", version = "~> 6.0" }
  }
}
`},
			want: map[string]string{"main.tf": `terraform {
  required_providers {
    aws = { source = "registry.compliance.tf/compliancetf/aws", version = "~> 6.0" }
  }
}
`},
		},
		{
			name: "implied provider added to an existing required_providers in versions.tf",
			files: map[string]string{
				"versions.tf": "terraform {\n  required_providers {\n    random = {\n      source = \"hashicorp/random\"\n    }\n  }\n}\n",
				"main.tf":     "data \"aws_caller_identity\" \"current\" {}\n",
			},
			want: map[string]string{"versions.tf": `terraform {
  required_providers {
    random = {
      source = "hashicorp/random"
    }
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = "~> 6.67"
    }
  }
}
`},
		},
		{
			name: "implied provider appended to a versions.tf without a terraform block",
			files: map[string]string{
				"versions.tf": "# bobthecorp versions",
				"main.tf":     "resource \"aws_s3_bucket\" \"b\" {}\n",
			},
			want: map[string]string{"versions.tf": `# bobthecorp versions

terraform {
  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = "~> 6.67"
    }
  }
}
`},
		},
		{
			name: "other sources, other types and migrated entries stay",
			files: map[string]string{"main.tf": `terraform {
  required_providers {
    aws    = { source = "registry.compliance.tf/compliancetf/aws", version = "~> 2.0" }
    awsfork = { source = "bobthecorp/aws" }
    awsmirror = { source = "mirror.bobthecorp.example/hashicorp/aws" }
    random = "~> 3.0"
  }
}

resource "random_id" "x" {
  byte_length = 4
}
`},
			want: map[string]string{},
		},
		{
			name:    "local module outside the scan root",
			files:   map[string]string{"main.tf": "module \"m\" {\n  source = \"../elsewhere\"\n}\n"},
			wantErr: "outside the scan root",
		},
		{
			name:    "missing local module",
			files:   map[string]string{"main.tf": "module \"m\" {\n  source = \"./modules/none\"\n}\n"},
			wantErr: "not a directory",
		},
		{
			name:  "quoted keys are replaced, not duplicated",
			files: map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = {\n      \"source\"  = \"hashicorp/aws\"\n      \"version\" = \"~> 6.0\"\n    }\n  }\n}\n"},
			want:  map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = {\n      \"source\"  = \"registry.compliance.tf/compliancetf/aws\"\n      \"version\" = \"~> 6.0\"\n    }\n  }\n}\n"},
		},
		{
			name:  "inline comment before a value stays",
			files: map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = {\n      source = /* up */ \"hashicorp/aws\"\n    }\n  }\n}\n"},
			want:  map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = {\n      source  = /* up */ \"registry.compliance.tf/compliancetf/aws\"\n      version = \"~> 6.67\"\n    }\n  }\n}\n"},
		},
		{
			name: "implied into a single-line terraform block",
			files: map[string]string{
				"main.tf":     "resource \"aws_s3_bucket\" \"b\" {}\n",
				"versions.tf": "terraform {}\n",
			},
			want: map[string]string{"versions.tf": "terraform {\n  required_providers {\n    aws = {\n      source  = \"registry.compliance.tf/compliancetf/aws\"\n      version = \"~> 6.67\"\n    }\n  }\n}\n"},
		},
		{
			name: "implied into a single-line terraform block with an argument",
			files: map[string]string{
				"main.tf":     "resource \"aws_s3_bucket\" \"b\" {}\n",
				"versions.tf": "terraform { required_version = \">= 1.5\" }\n",
			},
			want: map[string]string{"versions.tf": "terraform {\n  required_version = \">= 1.5\"\n  required_providers {\n    aws = {\n      source  = \"registry.compliance.tf/compliancetf/aws\"\n      version = \"~> 6.67\"\n    }\n  }\n}\n"},
		},
		{
			name:    "escaped source key is refused, not duplicated",
			files:   map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = {\n      \"sour\\u0063e\" = \"hashicorp/aws\"\n    }\n  }\n}\n"},
			wantErr: "unsupported source key form",
		},
		{
			name:    "comment between key and = is refused, not duplicated",
			files:   map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = {\n      source /* up */ = \"hashicorp/aws\"\n    }\n  }\n}\n"},
			wantErr: "unsupported source key form",
		},
		{
			name:  "implied joins the required_providers block of another file",
			files: map[string]string{"main.tf": "terraform {\n  required_providers {\n    random = { source = \"hashicorp/random\" }\n  }\n}\n\nresource \"aws_s3_bucket\" \"b\" {}\n"},
			want:  map[string]string{"main.tf": "terraform {\n  required_providers {\n    random = { source = \"hashicorp/random\" }\n    aws = {\n      source  = \"registry.compliance.tf/compliancetf/aws\"\n      version = \"~> 6.67\"\n    }\n  }\n}\n\nresource \"aws_s3_bucket\" \"b\" {}\n"},
		},
		{
			name: "hidden files are ignored like Terraform does",
			files: map[string]string{
				"main.tf":      "resource \"null_resource\" \"n\" {}\n",
				".disabled.tf": "module \"m\" {\n  source = \"../elsewhere\"\n}\nresource \"aws_s3_bucket\" \"b\" {}\n",
			},
			want: map[string]string{},
		},
		{
			name:    "unlabeled module block is an error, not a panic",
			files:   map[string]string{"main.tf": "module {\n  source = \"./none\"\n}\n"},
			wantErr: "not a directory",
		},
		{
			name:  "legacy string entry keeps its constraint",
			files: map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = \"~> 6.0\"\n  }\n}\n"},
			want:  map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = {\n      source  = \"registry.compliance.tf/compliancetf/aws\"\n      version = \"~> 6.0\"\n    }\n  }\n}\n"},
		},
		{
			name: "local module entry without version gets the module constraint",
			files: map[string]string{
				"main.tf":       "module \"m\" {\n  source = \"./m\"\n}\n",
				"m/versions.tf": "terraform {\n  required_providers {\n    aws = { source = \"hashicorp/aws\" }\n  }\n}\n",
			},
			want: map[string]string{"m/versions.tf": "terraform {\n  required_providers {\n    aws = { source = \"registry.compliance.tf/compliancetf/aws\", version = \">= 6.0.0\" }\n  }\n}\n"},
		},
		{
			name:    "escaped version key is refused, not duplicated",
			files:   map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = {\n      source = \"hashicorp/aws\"\n      \"versio\\u006e\" = \"~> 6.0\"\n    }\n  }\n}\n"},
			wantErr: "unsupported version key form",
		},
		{
			name:    "non-literal legacy entry is refused",
			files:   map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = local.v\n  }\n}\n"},
			wantErr: "not a literal version constraint",
		},
		{
			name: "remote modules are not followed",
			files: map[string]string{"main.tf": `module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
}
`},
			want: map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rewriteOne(t, tc.files)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v; want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got:\n%v\nwant:\n%v", got, tc.want)
			}
		})
	}
}

// TestRewriteTwoImplied: two implied providers share one required_providers
// block in versions.tf.
func TestRewriteTwoImplied(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource \"aws_s3_bucket\" \"b\" {}\nresource \"google_x\" \"g\" {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	providers := append(slices.Clone(awsProvider), Provider{Type: "google", To: "registry.compliance.tf/compliancetf/google", RootConstraint: "~> 1.0", ModuleConstraint: ">= 1.0.0"})
	edits, err := Rewrite(dir, []Unit{{Dir: "."}}, providers)
	if err != nil {
		t.Fatal(err)
	}
	want := "terraform {\n  required_providers {\n    aws = {\n      source  = \"registry.compliance.tf/compliancetf/aws\"\n      version = \"~> 6.67\"\n    }\n    google = {\n      source  = \"registry.compliance.tf/compliancetf/google\"\n      version = \"~> 1.0\"\n    }\n  }\n}\n"
	if len(edits) != 1 || edits[0].File != "versions.tf" || string(edits[0].Content) != want {
		t.Fatalf("edits = %+v; want one versions.tf:\n%s", edits, want)
	}
}

// TestRewriteRefusesSymlinksOutOfRoot: a local module dir or a .tf file that
// is a symlink would make apply write outside the scan root, or edit one file
// under two names.
func TestRewriteRefusesSymlinksOutOfRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "main.tf"), []byte("resource \"aws_s3_bucket\" \"b\" {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(dir string) error{
		"module dir": func(dir string) error {
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("module \"m\" {\n  source = \"./mods\"\n}\n"), 0o600); err != nil {
				return err
			}
			return os.Symlink(outside, filepath.Join(dir, "mods"))
		},
		"tf file": func(dir string) error {
			return os.Symlink(filepath.Join(outside, "main.tf"), filepath.Join(dir, "main.tf"))
		},
		"in-root alias of a unit dir": func(dir string) error {
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("module \"m\" {\n  source = \"./alias\"\n}\n"), 0o600); err != nil {
				return err
			}
			if err := os.Mkdir(filepath.Join(dir, "shared"), 0o700); err != nil {
				return err
			}
			return os.Symlink("shared", filepath.Join(dir, "alias"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := setup(dir); err != nil {
				t.Fatal(err)
			}
			edits, err := Rewrite(dir, []Unit{{Dir: "."}}, awsProvider)
			if err == nil {
				t.Fatalf("edits = %+v; want a refusal", edits)
			}
		})
	}
}

func TestIsUpstream(t *testing.T) {
	cases := map[string]bool{
		"hashicorp/aws":                         true,
		"registry.terraform.io/hashicorp/aws":   true,
		"registry.opentofu.org/hashicorp/aws":   true,
		"HashiCorp/AWS":                         true,
		"hashicorp/awscc":                       false,
		"example.com/hashicorp/aws":             false,
		"bobthecorp/aws":                        false,
		"aws":                                   false,
		"registry.terraform.io/x/hashicorp/aws": false,
	}
	for src, want := range cases {
		if got := isUpstream(src, "aws"); got != want {
			t.Errorf("isUpstream(%q) = %v; want %v", src, got, want)
		}
	}
}

func TestVersionReason(t *testing.T) {
	cases := []struct {
		version string
		added   bool
		want    string
	}{
		{"~> 6.67", true, "version ~> 6.67 added"},
		{">= 5.0, < 7.0", false, "version >= 5.0, < 7.0 kept"},
		{"~> 6.0 # https://user:pass@example.com", false, "version kept"},
	}
	for _, tc := range cases {
		if got := versionReason(tc.version, tc.added); got != tc.want {
			t.Errorf("versionReason(%q, %v) = %q; want %q", tc.version, tc.added, got, tc.want)
		}
	}
}
