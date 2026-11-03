package tfroots

import (
	"reflect"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// TestLocalTarget resolves a module source against the directory of the file
// that calls it. Only ./ and ../ paths are local, as in Terraform and OpenTofu,
// and a path that leaves the scan root names nothing.
func TestLocalTarget(t *testing.T) {
	cases := []struct {
		dir, source string
		want        string
		ok          bool
	}{
		{".", "./modules/sub", "modules/sub", true},
		{".", "./modules/sub/", "modules/sub", true},
		{".", "./modules//sub", "modules/sub", true},
		{"examples/complete", "../../", ".", true},
		{"examples/complete", "../..", ".", true},
		{"wrappers", "../", ".", true},
		{"wrappers/sub", "../../modules/a", "modules/a", true},
		{"a", "./", "a", true},
		{"a", "../a", "a", true},
		{".", `.\modules\sub`, "modules/sub", true},
		{"examples/x", `..\..\modules\peer`, "modules/peer", true},
		{".", "../outside", "", false},
		{"a/b", "../../..", "", false},
		{"a", "../../a", "", false},
		{".", "..", "", false},
		{".", ".", "", false},
		{".", "", "", false},
		{".", "/modules/sub", "", false},
		{".", "modules/sub", "", false},
		{".", "terraform-aws-modules/vpc/aws//modules/sub", "", false},
		{".", "git::https://github.com/bobthecorp/x.git//modules/sub", "", false},
		{".", "github.com/bobthecorp/x//modules/sub", "", false},
	}
	for _, tc := range cases {
		got, ok := localTarget(tc.dir, tc.source)
		if got != tc.want || ok != tc.ok {
			t.Errorf("localTarget(%q, %q) = %q, %v; want %q, %v", tc.dir, tc.source, got, ok, tc.want, tc.ok)
		}
	}
}

// TestUnparseableDirectoryIsRoot: a file the classifier cannot read keeps its
// directory a root, whatever calls it.
func TestUnparseableDirectoryIsRoot(t *testing.T) {
	archive := archiveOf(map[string]string{
		"providers.tf":      `provider "aws" {}`,
		"main.tf":           "module \"sub\" { source = \"./sub\" }\nmodule \"json\" { source = \"./json\" }",
		"sub/versions.tf":   `terraform {`,
		"json/main.tf.json": `{ "provider": `,
		"other/main.tf":     `module "sub" { source = "../sub" }`,
		"plain/versions.tf": `terraform {}`,
	})
	children := ModuleDirs(archive)
	if children["sub"] || children["json"] || children["."] {
		t.Errorf("children = %v; sub and json are unparseable and . is the scan root", children)
	}
	// Both parse and have no root signal, so each is a module: only a parse
	// failure keeps a directory without one a root.
	if !children["other"] || !children["plain"] {
		t.Errorf("children = %v; other and plain parse and have no root signal", children)
	}
}

func archiveOf(files map[string]string) *ctfkit.ConfigArchive {
	archive := &ctfkit.ConfigArchive{Root: ".", ClassifyModules: true}
	for name, body := range files {
		archive.Files = append(archive.Files, ctfkit.ConfigFile{Path: name, Bytes: []byte(body)})
	}
	return archive
}

// TestRoots lists the roots in Dir order with their backend and its literal
// arguments as strings; modules are left out.
func TestRoots(t *testing.T) {
	archive := archiveOf(map[string]string{
		"main.tf":              "terraform {\n  backend \"local\" {\n    path = \"state/a.tfstate\"\n  }\n}\nmodule \"m\" { source = \"./modules/m\" }",
		"modules/m/main.tf":    "terraform {\n  required_providers {\n    aws = { source = \"hashicorp/aws\" }\n  }\n}\n",
		"live/prod/backend.tf": "terraform {\n  backend \"s3\" {\n    bucket  = \"bobthecorp-state\"\n    encrypt = true\n  }\n}\n",
		"broken/main.tf":       `terraform {`,
		"live/hcp/main.tf":     "terraform {\n  cloud {\n    organization = \"bobthecorp\"\n  }\n}\n",
		"examples/x/main.tf":   `provider "aws" {}`,
	})
	got, err := Roots(archive)
	if err != nil {
		t.Fatal(err)
	}
	want := []Root{
		{Dir: ".", Backend: "local", BackendArgs: map[string]string{"path": "state/a.tfstate"}},
		{Dir: "broken", Unparseable: true},
		{Dir: "examples/x"},
		{Dir: "live/hcp", Backend: "cloud", BackendArgs: map[string]string{"organization": "bobthecorp"}},
		{Dir: "live/prod", Backend: "s3", BackendArgs: map[string]string{"bucket": "bobthecorp-state", "encrypt": "true"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Roots = %+v\nwant %+v", got, want)
	}
}

// TestRootsMalformedBackend: a backend block Terraform would reject is an
// error, never a guessed path, and the error names the first bad root.
func TestRootsMalformedBackend(t *testing.T) {
	for name, src := range map[string]string{
		"non-literal": "terraform {\n  backend \"local\" {\n    path = var.p\n  }\n}\n",
		"no label":    "terraform {\n  backend {}\n}\n",
		"nested":      "terraform {\n  backend \"local\" {\n    path = \"x\"\n    extra {}\n  }\n}\n",
		"list path":   "terraform {\n  backend \"local\" {\n    path = [\"x\"]\n  }\n}\n",
		"empty type":  "terraform {\n  backend \"\" {}\n}\n",
		"two":         "terraform {\n  backend \"local\" {}\n  backend \"s3\" {}\n}\n",
	} {
		if _, err := Roots(archiveOf(map[string]string{"main.tf": src})); err == nil {
			t.Errorf("%s: Roots accepted a malformed backend block", name)
		}
	}
	if _, err := Roots(archiveOf(map[string]string{"live/prod/main.tf": "terraform {\n  backend {}\n}\n"})); err == nil {
		t.Error("Roots skipped a malformed backend in a directory classified as a module")
	}
	bad := "terraform {\n  backend \"local\" {\n    path = var.p\n  }\n}\n"
	archive := archiveOf(map[string]string{"b/main.tf": bad, "a/main.tf": bad})
	for range 20 {
		if _, err := Roots(archive); err == nil || !strings.HasPrefix(err.Error(), "a: ") {
			t.Fatalf("err = %v; want the first root in Dir order", err)
		}
	}
}

// TestRootsNestedBlockOtherBackend: a nested block outside a local backend
// binds nothing, so it is not refused.
func TestRootsNestedBlockOtherBackend(t *testing.T) {
	got, err := Roots(archiveOf(map[string]string{"main.tf": "terraform {\n  backend \"remote\" {\n    workspaces {\n      name = \"bobthecorp\"\n    }\n  }\n}\n"}))
	if err != nil || len(got) != 1 || got[0].Backend != "remote" {
		t.Fatalf("Roots = %+v, %v", got, err)
	}
}

// TestRootsNumericBackendArg: a number converts to a string as Terraform
// converts it, so a numeric local path is bound, not replaced by the default.
func TestRootsNumericBackendArg(t *testing.T) {
	got, err := Roots(archiveOf(map[string]string{"main.tf": "terraform {\n  backend \"local\" {\n    path = 123\n  }\n}\n"}))
	if err != nil || len(got) != 1 || got[0].BackendArgs["path"] != "123" {
		t.Fatalf("Roots = %+v, %v", got, err)
	}
}
