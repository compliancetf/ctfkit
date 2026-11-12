package pack

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// testCatalog carries every optional coverage field: a not-applicable reason
// for one control, an enforcement record for another, and a not-applicable
// clause at the top level.
const testCatalog = `schema: ctf.catalog/1
version: "2026.9.0"
hosts: {soc_2: soc2, hipaa: hipaa}
defaultHost: soc_2
controls:
  - id: s3_bucket_versioning_enabled
    name: S3 bucket versioning enabled
    resourceTypes: [aws_s3_bucket]
    clausesByFramework: {soc_2: [CC6.1]}
  - id: s3_bucket_logging_enabled
    name: S3 bucket logging enabled
    resourceTypes: [aws_s3_bucket]
    clausesByFramework: {soc_2: [CC7.2]}
    notApplicable: {hipaa: No HIPAA clause asks for access logs.}
  - id: s3_bucket_mfa_delete_enabled
    name: S3 bucket MFA delete enabled
    resourceTypes: [aws_s3_bucket]
    clausesByFramework: {soc_2: [CC6.1]}
    enforcement: {layer: runtime, reason: Needs the root user's credentials.}
  - id: s3_bucket_default_encryption_enabled
    name: S3 bucket default encryption enabled
    resourceTypes: [aws_s3_bucket]
    clausesByFramework: {soc_2: [CC6.1]}
notApplicableClauses:
  soc_2: {CC1.1: An organizational criterion.}
modules:
  - resourceTypes: [aws_s3_bucket]
    source: "{host}.compliance.tf/terraform-aws-modules/s3-bucket/aws"
    version: "~> 5.0"
    controls: [s3_bucket_versioning_enabled]
`

const testManifest = `{"schema_version":"3.4"}`

// fixture builds an inventory with one served module whose manifest is on
// disk under a temporary root, and the catalog above.
func fixture(t *testing.T) (Input, *catalog.FileCatalog) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".terraform", "modules", "s3_bucket")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), []byte(testManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	catFile := filepath.Join(t.TempDir(), "catalog.yaml")
	if err := os.WriteFile(catFile, []byte(testCatalog), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(catFile)
	if err != nil {
		t.Fatal(err)
	}

	manifest := &ctfkit.Manifest{
		SchemaVersion: "3.4",
		Module: ctfkit.ManifestModule{
			RegistrySource: "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws",
			Version:        "5.16.1",
			Frameworks:     []string{"soc_2", "hipaa"},
			FrameworkNames: map[string]string{"soc_2": "SOC 2", "hipaa": "HIPAA"},
		},
		Controls: []ctfkit.ManifestControl{
			{
				ControlID: "s3_bucket_versioning_enabled", Name: "S3 bucket versioning enabled", Status: "enforced",
				ClausesByFramework: map[string][]string{
					"soc_2": {"CC6.1 The entity implements logical access security", "A1.2 The entity authorizes"},
					"hipaa": {"164.312(c)(1) Integrity"},
				},
				SupportingClausesByFramework: map[string][]string{"soc_2": {"A1.2 The entity authorizes"}},
			},
			{
				ControlID: "s3_bucket_logging_enabled", Name: "S3 bucket logging enabled", Status: "delegated",
				ClausesByFramework: map[string][]string{"soc_2": {"CC7.2: The entity monitors"}},
			},
		},
		Build: ctfkit.ManifestBuild{ControlsSuperseded: map[string]string{
			"s3_bucket_default_encryption_enabled": "s3_bucket_default_encryption_enabled_kms",
		}},
	}
	in := Input{
		Modules: &ctfkit.ModuleInventory{Instances: []ctfkit.ModuleInstance{
			{Key: "", Dir: "."},
			{
				Key: "s3_bucket", Source: manifest.Module.RegistrySource, Dir: ".terraform/modules/s3_bucket",
				Manifest: manifest, ManifestSHA256: digest([]byte(testManifest)),
			},
			{Key: "helper", Source: "./helper", Dir: "helper", DeclaresNoResources: true},
		}},
		Catalog:              cat,
		CatalogVersion:       cat.Version(),
		NotApplicableClauses: cat.NotApplicableClauses(),
		Metadata: ctfkit.RunMetadata{
			Commit: "0000000000000000000000000000000000000000", Platform: "local",
			Now: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
		},
		Root:      root,
		Generator: Generator{Name: "ctfkit", Version: "1.0.0"},
		Receipt:   []byte("{}"),
		SARIF:     []byte("{}"),
	}
	return in, cat
}

func TestBuild(t *testing.T) {
	in, _ := fixture(t)
	p, attachments, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	mapped := p.Mapping[0].Controls[0]
	cases := []struct {
		name string
		got  any
		want any
	}{
		{"frameworks sorted by id", p.Frameworks, []Framework{{"hipaa", "HIPAA"}, {"soc_2", "SOC 2"}}},
		{"root entry left out of scope", len(p.Scope), 2},
		{"helper without manifest", p.Scope[1].ManifestFile, ""},
		{"release falls back to the root", p.Release.Name, in.Root},
		{"supporting clause marked", mapped.Clauses[0].Clauses, []ClauseRef{{"CC6.1", false}, {"A1.2", true}}},
		{"no-clause control with catalog reason", p.NoClause, []NoClauseControl{{
			ID: "s3_bucket_logging_enabled", Name: "S3 bucket logging enabled",
			Frameworks: []NoClauses{{Framework: "hipaa", Reason: "No HIPAA clause asks for access logs."}},
		}}},
		{"not enforced, with layer, reason and supersession", p.NotEnforced, []NotEnforced{
			{
				ID: "s3_bucket_default_encryption_enabled", Name: "S3 bucket default encryption enabled",
				ResourceTypes: []string{"aws_s3_bucket"}, SupersededBy: "s3_bucket_default_encryption_enabled_kms",
			},
			{
				ID: "s3_bucket_mfa_delete_enabled", Name: "S3 bucket MFA delete enabled", ResourceTypes: []string{"aws_s3_bucket"},
				Layer: ctfkit.LayerRuntime, Reason: "Needs the root user's credentials.",
			},
		}},
		{"register clauses in natural order, titles without the identifier", p.Register[1].Clauses, []RegisterClause{
			{ID: "A1.2", Title: "The entity authorizes", Controls: []string{"s3_bucket_versioning_enabled"}},
			{ID: "CC6.1", Title: "The entity implements logical access security", Controls: []string{"s3_bucket_versioning_enabled"}},
			{ID: "CC7.2", Title: "The entity monitors", Controls: []string{"s3_bucket_logging_enabled"}},
		}},
		{"register not-applicable clauses", p.Register[1].NotApplicable, []NotApplicableClause{{"CC1.1", "An organizational criterion."}}},
		{"summary", p.Summary, Summary{
			Modules: 2, ModulesWithManifest: 1, ControlsEnforced: 1, ControlsDelegated: 1,
			PerFramework: []FrameworkCount{{"hipaa", 1, 2}, {"soc_2", 2, 2}},
			NoClause:     1, NoClauseWithReason: 1, NotEnforced: 2,
		}},
		{"tests not supplied", p.Tests.Supplied, false},
		{"attachments sorted", names(attachments), []string{
			"findings.sarif", "manifests/s3_bucket/compliancetf-manifest.json", "pack-1.schema.json", "receipt.json",
		}},
		{"file digests listed", p.Files[1], FileRef{
			Path: "manifests/s3_bucket/compliancetf-manifest.json", SHA256: digest([]byte(testManifest)),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Errorf("got  %+v\nwant %+v", tc.got, tc.want)
			}
		})
	}
}

func TestBuildWithTests(t *testing.T) {
	in, _ := fixture(t)
	in.Tests = &ctfkit.TestRun{File: "tests.json", Runs: 1, Passed: 1, Cases: []ctfkit.TestCase{{Name: "versioning_off", Status: "pass"}}}
	p, _, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	md, err := RenderMarkdown(p)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Tests.Supplied || !strings.Contains(string(md.Body), "`versioning_off`") {
		t.Errorf("section 7 does not list the supplied test:\n%s", md.Body)
	}
}

func TestBuildRefusesAChangedManifest(t *testing.T) {
	in, _ := fixture(t)
	in.Modules.Instances[1].ManifestSHA256 = strings.Repeat("0", 64)
	if _, _, err := Build(in); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("Build = %v, want a changed-manifest error", err)
	}
}

func TestMarkdownStatesWhatIsMissing(t *testing.T) {
	in, _ := fixture(t)
	p, _, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	md, err := RenderMarkdown(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		Notice,
		"No tests supplied.",
		"| Commit | `0000000000000000000000000000000000000000` |",
		"the catalog file named with `--catalog`",
		"A1.2 (supporting)",
		"None (see 5)",
		"| Not set | Not set Replaced in this build by `s3_bucket_default_encryption_enabled_kms`. |",
		"| runtime | Needs the root user's credentials. |",
	} {
		if !strings.Contains(string(md.Body), want) {
			t.Errorf("pack.md does not contain %q", want)
		}
	}
	for _, banned := range []string{"policy engine", "signed by", "attested by"} {
		if strings.Contains(strings.ToLower(string(md.Body)), banned) {
			t.Errorf("pack.md contains %q", banned)
		}
	}
}

func TestWriteIsDeterministic(t *testing.T) {
	in, _ := fixture(t)
	p, attachments, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	if err = Write(&first, p, attachments); err != nil {
		t.Fatal(err)
	}
	if err = Write(&second, p, attachments); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("two writes of one pack differ")
	}

	zr, err := zip.NewReader(bytes.NewReader(first.Bytes()), int64(first.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range zr.File {
		got = append(got, f.Name)
		if !f.Modified.Equal(zipTime) {
			t.Errorf("%s modified %v, want %v", f.Name, f.Modified, zipTime)
		}
	}
	want := []string{
		"findings.sarif", "manifests/s3_bucket/compliancetf-manifest.json",
		"pack-1.schema.json", "pack.json", "pack.md", "receipt.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("entries = %v, want %v", got, want)
	}
}

func TestWriteRefusesADuplicateEntry(t *testing.T) {
	in, _ := fixture(t)
	p, attachments, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if err = Write(new(bytes.Buffer), p, append(attachments, File{Name: FileJSON})); err == nil {
		t.Fatal("Write accepted two pack.json entries")
	}
}

// The schema the zip ships is the one in schema/, and pack.json validates
// against it.
func TestSchema(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", FileSchema))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(published, schemaJSON) {
		t.Fatalf("internal/render/pack/%s differs from schema/%s; copy it", FileSchema, FileSchema)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err = c.AddResource(FileSchema, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(FileSchema)
	if err != nil {
		t.Fatal(err)
	}

	in, _ := fixture(t)
	in.Tests = &ctfkit.TestRun{File: "tests.json", Cases: []ctfkit.TestCase{{Name: "a", Status: "pass"}}}
	p, _, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	body, err := RenderJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body.Body))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Validate(inst); err != nil {
		t.Errorf("pack.json does not validate: %v", err)
	}
}

func TestNaturalLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"CC2.1", "CC10.1", true},
		{"CC10.1", "CC2.1", false},
		{"A1.2", "A1.10", true},
		{"A1.2", "CC1.1", true},
		{"3.4", "3.4.1", true},
		{"x", "x", false},
	}
	for _, tc := range cases {
		if got := naturalLess(tc.a, tc.b); got != tc.want {
			t.Errorf("naturalLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func names(files []File) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Name)
	}
	return out
}
