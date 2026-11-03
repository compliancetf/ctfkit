package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	schemas  = "../../schema"
	fixtures = "../../testdata/fixtures"
)

// TestFixturePackValidates is the check that matters: every expected output
// the fixture pack ships validates against the schema its file name selects.
func TestFixturePackValidates(t *testing.T) {
	if err := run(schemas, []string{fixtures}, io.Discard); err != nil {
		t.Fatalf("fixture pack does not validate:\n%v", err)
	}
}

// TestBrokenCopyFails is the positive control for the test above: a passing
// run proves nothing unless the same harness fails on a document that is out
// of contract. Each case mutates one file of a throwaway copy.
func TestBrokenCopyFails(t *testing.T) {
	cases := map[string]struct {
		file string
		// edit rewrites the file's bytes.
		edit func(string) string
		want string
	}{
		"receipt drops the scope statement": {
			file: "report/served-leaf/expected/receipt.json",
			edit: func(s string) string {
				return strings.Replace(s, `"scopeStatement":"This receipt records`, `"scopeStatement":"Certified compliant. This receipt records`, 1)
			},
			want: "receipt-1.schema.json",
		},
		"sarif run carries a two-line watermark": {
			file: "plan/02-ctf-module-intact/expected/findings.sarif",
			edit: func(s string) string {
				return strings.Replace(s, `"results": []`, `"properties": {"ctf.watermark": "one\ntwo"}, "results": []`, 1)
			},
			want: "cff-1.schema.json",
		},
		"sarif result drops ctf.preventive": {
			file: "plan/01-raw-s3-no-ctf/expected/findings.sarif",
			edit: func(s string) string {
				return strings.Replace(s, `"ctf.preventive"`, `"ctf.maybe"`, 1)
			},
			want: "cff-1.schema.json",
		},
		"exit code is not 0, 1 or 2": {
			file: "report/served-leaf/expected/exit-code",
			edit: func(string) string { return "7\n" },
			want: "is not 0, 1 or 2",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := copyFixtures(t)
			path := filepath.Join(dir, tc.file)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			edited := tc.edit(string(b))
			if edited == string(b) {
				t.Fatalf("%s: the edit changed nothing, so the case asserts nothing", tc.file)
			}
			if werr := os.WriteFile(path, []byte(edited), 0o644); werr != nil {
				t.Fatal(werr)
			}

			err = run(schemas, []string{dir}, io.Discard)
			var fail *failures
			if !errors.As(err, &fail) {
				t.Fatalf("want a validation failure, got %v", err)
			}
			if !strings.Contains(fail.Error(), tc.file) || !strings.Contains(fail.Error(), tc.want) {
				t.Fatalf("failure does not name %s and %s:\n%v", tc.file, tc.want, fail)
			}
		})
	}
}

// TestUnsupportedMajorIsRefused is the positive control for the inverted check
// on report/schema-4-stub. That case passes today because the manifest schema
// refuses a schema 4 document; loosening the major pin must turn it into a
// failure, or the inversion would be passing vacuously.
func TestUnsupportedMajorIsRefused(t *testing.T) {
	dir := t.TempDir()
	entries, err := filepath.Glob(filepath.Join(schemas, "*.schema.json"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no schemas found: %v", err)
	}
	for _, src := range entries {
		b, rerr := os.ReadFile(src)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if filepath.Base(src) == "manifest-3.schema.json" {
			b = []byte(strings.Replace(string(b), `"^3\\.[0-9]+$"`, `"^[0-9]+\\.[0-9]+$"`, 1))
		}
		if werr := os.WriteFile(filepath.Join(dir, filepath.Base(src)), b, 0o644); werr != nil {
			t.Fatal(werr)
		}
	}

	err = run(dir, []string{fixtures}, io.Discard)
	var fail *failures
	if !errors.As(err, &fail) {
		t.Fatalf("a loosened major pin must fail the schema-4 fixture, got %v", err)
	}
	if !strings.Contains(fail.Error(), "schema-4-stub") {
		t.Fatalf("failure does not name the schema-4 fixture:\n%v", fail)
	}
}

// TestArgs covers the two ways the command refuses to run at all.
func TestArgs(t *testing.T) {
	if err := run(schemas, nil, io.Discard); err == nil {
		t.Fatal("want an error without a fixtures directory")
	}
	if err := run(t.TempDir(), []string{fixtures}, io.Discard); err == nil {
		t.Fatal("want an error when the schema directory holds no schemas")
	}
	if err := run(schemas, []string{t.TempDir()}, io.Discard); err == nil {
		t.Fatal("want an error when the fixtures directory holds no fixtures")
	}
}

func copyFixtures(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fixtures")
	if err := os.CopyFS(dir, os.DirFS(fixtures)); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestCatalogRules covers catalog-1 and the one rule that lives in Go: a
// resource type may appear in at most one modules[] entry, which is what makes
// ModuleFor(resourceType) well defined.
func TestCatalogRules(t *testing.T) {
	good, err := os.ReadFile(filepath.Join(schemas, "testdata", "catalog-example.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		edit func(string) string
		want string
	}{
		"valid catalog": {
			edit: func(s string) string { return s },
			want: "",
		},
		"a control id defined twice": {
			edit: func(s string) string {
				return strings.Replace(s, "modules:", `  - id: s3_bucket_versioning_enabled
    name: S3 bucket versioning enabled, again
    resourceTypes: [aws_s3_bucket]
    clausesByFramework:
      soc_2: [CC6.1]
modules:`, 1)
			},
			want: "a control id may be defined only once: s3_bucket_versioning_enabled",
		},
		"a modules entry lists an undefined control": {
			edit: func(s string) string {
				return strings.Replace(s, "controls: [s3_bucket_versioning_enabled]", "controls: [s3_bucket_no_such_control]", 1)
			},
			want: "a modules[] control id must be defined in controls[]",
		},
		"defaultHost is not a key of hosts": {
			edit: func(s string) string {
				return strings.Replace(s, "defaultHost: soc_2", "defaultHost: iso27001", 1)
			},
			want: "defaultHost must be a key of hosts: iso27001 is not",
		},
		"a clause map names a framework hosts does not": {
			edit: func(s string) string {
				return strings.Replace(s, "      pci_dss_v40: [\"3.4\"]", "      iso27001: [\"A.8.1\"]", 1)
			},
			want: "every clausesByFramework key must be a key of hosts",
		},
		"a version with a leading zero in a numeric part": {
			edit: func(s string) string {
				return strings.Replace(s, `version: "2026.9.0"`, `version: "2026.09.0"`, 1)
			},
			want: "catalog-1.schema.json",
		},
		"a version that is not semver": {
			edit: func(s string) string {
				return strings.Replace(s, `version: "2026.9.0"`, `version: "latest"`, 1)
			},
			want: "catalog-1.schema.json",
		},
		"no version at all": {
			edit: func(s string) string {
				return strings.Replace(s, "version: \"2026.9.0\"\n", "", 1)
			},
			want: "catalog-1.schema.json",
		},
		"a version with a pre-release and build": {
			edit: func(s string) string {
				return strings.Replace(s, `version: "2026.9.0"`, `version: "2026.10.0-rc.1+g1e4b692"`, 1)
			},
		},
		"a source carries the placeholder twice": {
			edit: func(s string) string {
				return strings.Replace(s, "{host}.compliance.tf", "{host}.{host}.compliance.tf", 1)
			},
			want: "at most once",
		},
		"one resource type in two modules entries": {
			edit: func(s string) string {
				return s + `  - resourceTypes: [aws_s3_bucket]
    source: "{host}.compliance.tf/terraform-aws-modules/s3-other/aws"
    version: "~> 1.0"
    controls: [s3_bucket_versioning_enabled]
`
			},
			want: "at most one modules[] entry",
		},
		"unsupported catalog schema": {
			edit: func(s string) string {
				return strings.Replace(s, "ctf.catalog/1", "ctf.catalog/2", 1)
			},
			want: "catalog-1.schema.json",
		},
		"control id is not a catalog id": {
			edit: func(s string) string {
				return strings.Replace(s, "id: s3_bucket_versioning_enabled", "id: S3BucketVersioning", 1)
			},
			want: "catalog-1.schema.json",
		},
		"modules entry names no resource type": {
			edit: func(s string) string {
				return strings.Replace(s, "  - resourceTypes: [aws_s3_bucket]\n    source:", "  - resourceTypes: []\n    source:", 1)
			},
			want: "catalog-1.schema.json",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := copyFixtures(t)
			edited := tc.edit(string(good))
			if tc.want != "" && edited == string(good) {
				t.Fatal("the edit changed nothing, so the case asserts nothing")
			}
			path := filepath.Join(dir, "catalog.yaml")
			if werr := os.WriteFile(path, []byte(edited), 0o644); werr != nil {
				t.Fatal(werr)
			}

			err := run(schemas, []string{dir}, io.Discard)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("the catalog example must validate:\n%v", err)
				}
				return
			}
			var fail *failures
			if !errors.As(err, &fail) {
				t.Fatalf("want a validation failure, got %v", err)
			}
			if !strings.Contains(fail.Error(), "catalog.yaml") || !strings.Contains(fail.Error(), tc.want) {
				t.Fatalf("failure does not name catalog.yaml and %s:\n%v", tc.want, fail)
			}
		})
	}
}

// TestSettingsFileIsNotACatalog guards the content sniff: a fixture directory
// also holds settings and exception files, and neither is a catalog.
func TestSettingsFileIsNotACatalog(t *testing.T) {
	dir := copyFixtures(t)
	settings := "framework: soc_2\nfail_on: error\n"
	if err := os.WriteFile(filepath.Join(dir, ".ctfkit.yaml"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(schemas, []string{dir}, io.Discard); err != nil {
		t.Fatalf("a settings file must not be read as a catalog:\n%v", err)
	}
}

// TestRunPropertyBag covers the run-level properties cff-1 types. Every key is
// optional; the cases here are about what happens once one is present.
func TestRunPropertyBag(t *testing.T) {
	const sarif = "plan/02-ctf-module-intact/expected/findings.sarif"

	cases := map[string]struct {
		props string
		want  string
	}{
		"an empty bag": {
			props: ``,
		},
		"a banner line": {
			props: `"ctf.watermark": "internal use only"`,
		},
		"a typed catalog version and settings echo": {
			props: `"ctf.watermark": "internal use only",
        "ctf.catalogVersion": {"version": "2026.9.0", "origin": "embedded"},
        "ctf.settings": {"endpoints": ["soc2.compliance.tf"], "fail_on": "warning", "allowed_resources": ["aws_s3_bucket"]}`,
		},
		"an empty banner": {
			props: `"ctf.watermark": ""`,
			want:  "cff-1.schema.json",
		},
		"a two-line banner": {
			props: `"ctf.watermark": "note\ninternal use only"`,
			want:  "cff-1.schema.json",
		},
		"an unknown catalog origin": {
			props: `"ctf.catalogVersion": {"version": "2026.9.0", "origin": "network"}`,
			want:  "cff-1.schema.json",
		},
		"a catalog version that is not semver": {
			props: `"ctf.catalogVersion": {"version": "latest", "origin": "file"}`,
			want:  "cff-1.schema.json",
		},
		"a settings threshold outside the level set": {
			props: `"ctf.settings": {"fail_on": "whenever"}`,
			want:  "cff-1.schema.json",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := copyFixtures(t)
			path := filepath.Join(dir, sarif)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			const anchor = `"results": []`
			if !strings.Contains(string(b), anchor) {
				t.Fatalf("%s no longer carries %s, so this test cannot edit it", sarif, anchor)
			}
			edited := strings.Replace(string(b), anchor, `"properties": {`+tc.props+`}, `+anchor, 1)
			if werr := os.WriteFile(path, []byte(edited), 0o644); werr != nil {
				t.Fatal(werr)
			}

			err = run(schemas, []string{dir}, io.Discard)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("this run property bag must validate:\n%v", err)
				}
				return
			}
			var fail *failures
			if !errors.As(err, &fail) {
				t.Fatalf("want a validation failure, got %v", err)
			}
			if !strings.Contains(fail.Error(), sarif) || !strings.Contains(fail.Error(), tc.want) {
				t.Fatalf("failure does not name %s and %s:\n%v", sarif, tc.want, fail)
			}
		})
	}
}

// TestProjectionWatermark covers the optional watermark field of the receipt
// and the Spacelift file: absent by default, and when present one printable
// line of banner text.
func TestProjectionWatermark(t *testing.T) {
	type projection struct {
		schema string
		// insert adds a watermark field with the given JSON string value.
		insert func(body, value string) string
	}
	files := map[string]projection{
		"report/served-leaf/expected/receipt.json": {
			schema: "receipt-1.schema.json",
			insert: func(body, value string) string {
				// Canonical JSON: watermark sorts after statement, so it is the
				// last key of the envelope.
				return strings.TrimSuffix(body, "}") + `,"watermark":` + value + `}`
			},
		},
		"report/served-leaf/expected/ctfkit.custom.spacelift.json": {
			schema: "spacelift-1.schema.json",
			insert: func(body, value string) string {
				return strings.Replace(body, `"summary"`, `"watermark": `+value+`,
  "summary"`, 1)
			},
		},
	}

	edits := map[string]struct {
		value string
		want  bool
	}{
		"a banner line": {value: `"internal use only"`, want: true},
		"two lines":     {value: `"note\ninternal use only"`, want: false},
		"an empty line": {value: `""`, want: false},
	}

	for file, p := range files {
		for name, e := range edits {
			t.Run(filepath.Base(file)+" with "+name, func(t *testing.T) {
				dir := copyFixtures(t)
				path := filepath.Join(dir, file)
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(b), `"watermark"`) {
					t.Fatalf("%s already carries a watermark, so this test cannot add one", file)
				}
				if werr := os.WriteFile(path, []byte(p.insert(string(b), e.value)), 0o644); werr != nil {
					t.Fatal(werr)
				}

				err = run(schemas, []string{dir}, io.Discard)
				if e.want {
					if err != nil {
						t.Fatalf("a banner line must validate:\n%v", err)
					}
					return
				}
				var fail *failures
				if !errors.As(err, &fail) {
					t.Fatalf("want a validation failure, got %v", err)
				}
				if !strings.Contains(fail.Error(), file) || !strings.Contains(fail.Error(), p.schema) {
					t.Fatalf("failure does not name %s and %s:\n%v", file, p.schema, fail)
				}
			})
		}
	}
}

// TestResultAttributes covers ctf.attributes, the optional result property
// naming the attributes a finding concerns. It carries attribute names and
// never their values, which is why the items are plain strings and why an
// object or a number in the array is refused rather than coerced.
func TestResultAttributes(t *testing.T) {
	const sarif = "plan/08-missing-tags/expected/findings.sarif"
	const anchor = `"ctf.preventive"`

	cases := map[string]struct {
		attributes string
		want       string
	}{
		"attribute names": {
			attributes: `["tags", "tags_all"]`,
		},
		"a value smuggled in as an object": {
			attributes: `[{"tags": "owner=finance"}]`,
			want:       "cff-1.schema.json",
		},
		"a number where a name belongs": {
			attributes: `["tags", 42]`,
			want:       "cff-1.schema.json",
		},
		"an empty array rather than the property omitted": {
			attributes: `[]`,
			want:       "cff-1.schema.json",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := copyFixtures(t)
			path := filepath.Join(dir, sarif)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), anchor) {
				t.Fatalf("%s no longer carries %s, so this test cannot edit it", sarif, anchor)
			}
			edited := strings.Replace(string(b),
				anchor, `"ctf.attributes": `+tc.attributes+`,
            `+anchor, 1)
			if werr := os.WriteFile(path, []byte(edited), 0o644); werr != nil {
				t.Fatal(werr)
			}

			err = run(schemas, []string{dir}, io.Discard)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("attribute names must validate:\n%v", err)
				}
				return
			}
			var fail *failures
			if !errors.As(err, &fail) {
				t.Fatalf("want a validation failure, got %v", err)
			}
			if !strings.Contains(fail.Error(), sarif) || !strings.Contains(fail.Error(), tc.want) {
				t.Fatalf("failure does not name %s and %s:\n%v", sarif, tc.want, fail)
			}
		})
	}
}

// TestEvidenceChainLines is the positive control for the provider evidence
// goldens: every complete line of a *.jsonl chain is checked against
// evidence-record-1, so one record with a property the format does not allow
// fails and the failure names the file and the line.
func TestEvidenceChainLines(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "schema")
	if err := os.CopyFS(dir, os.DirFS(schemas)); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, []string{fixtures}, io.Discard); err != nil {
		t.Fatalf("the unedited copy must validate: %v", err)
	}

	path := filepath.Join(dir, "testdata", "provider-evidence", "chain-good.jsonl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A property the format does not allow, and a run id that misses the token
	// pattern: the failure names both places but never the value.
	edited := strings.Replace(string(b), `"stage":"plan"`, `"stage":"plan","value":"x"`, 1)
	edited = strings.Replace(edited, `"id":"bobthecorp-run-1"`, `"id":"SECRET VALUE"`, 1)
	if edited == string(b) {
		t.Fatal("the edit changed nothing, so the case asserts nothing")
	}
	if werr := os.WriteFile(path, []byte(edited), 0o644); werr != nil {
		t.Fatal(werr)
	}

	err = run(dir, []string{fixtures}, io.Discard)
	var fail *failures
	if !errors.As(err, &fail) {
		t.Fatalf("want a validation failure, got %v", err)
	}
	if !strings.Contains(fail.Error(), "chain-good.jsonl") || !strings.Contains(fail.Error(), "line 3:") {
		t.Fatalf("failure does not name chain-good.jsonl line 3:\n%v", fail)
	}
	if !strings.Contains(fail.Error(), "line 1: /run/id:") {
		t.Fatalf("failure does not name line 1 /run/id:\n%v", fail)
	}
	if strings.Contains(fail.Error(), "SECRET VALUE") {
		t.Fatalf("failure quotes a record value:\n%v", fail)
	}
}

// TestEvidenceReadDigest: the provider's plan record written with
// COMPLIANCETF_BASELINE_KEY_FILE set carries the optional results[].read_digest
// and validates; a read_digest that is not a sha256 digest fails.
func TestEvidenceReadDigest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "schema")
	if err := os.CopyFS(dir, os.DirFS(schemas)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "testdata", "provider-evidence", "plan-read-digest.jsonl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"read_digest":"sha256:`) {
		t.Fatal("the golden carries no read_digest, so the case asserts nothing")
	}
	if err = run(dir, []string{fixtures}, io.Discard); err != nil {
		t.Fatalf("the provider record must validate: %v", err)
	}
	if err = os.WriteFile(path, []byte(strings.ReplaceAll(string(b), `"read_digest":"sha256:`, `"read_digest":"md5:`)), 0o644); err != nil {
		t.Fatal(err)
	}
	err = run(dir, []string{fixtures}, io.Discard)
	var fail *failures
	if !errors.As(err, &fail) || !strings.Contains(fail.Error(), "plan-read-digest.jsonl") {
		t.Fatalf("want a failure naming plan-read-digest.jsonl, got %v", err)
	}
}

// TestVerdictSchemaRefuses is the positive control for verdict-1: the signed
// vector validates, and each edit that pkg/verdict.Parse or the provider
// refuses, or that is not a real time, fails the schema.
func TestVerdictSchemaRefuses(t *testing.T) {
	s, err := compileSchemas(schemas)
	if err != nil {
		t.Fatal(err)
	}
	src := "../../pkg/verdict/testdata/sig/valid/verdict.json"
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	try := func(name, doc string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return check(s, target{path: p, schema: "verdict-1.schema.json"})
	}
	if msg := try("valid.json", string(b)); msg != "" {
		t.Fatalf("valid vector refused: %s", msg)
	}
	edits := map[string][2]string{
		"impossible date":        {`"issued_at": "2026-10-19T10:00:00Z"`, `"issued_at": "2026-02-30T10:00:00Z"`},
		"offset time":            {`"issued_at": "2026-10-19T10:00:00Z"`, `"issued_at": "2026-10-19T10:00:00+01:00"`},
		"empty optional":         {`"deposed": "a1b2c3d4"`, `"deposed": ""`},
		"update with delete key": {`"action": "replace"`, `"action": "update"`},
		"create with prior":      {`"prior_identity_kind": "none"`, `"prior_identity_kind": "id"`},
		"number":                 {`"floor_epoch": "3"`, `"floor_epoch": 3`},
		"unknown member":         {`"floor_epoch": "3",`, `"floor_epoch": "3", "extra": "x",`},
	}
	for name, e := range edits {
		if !strings.Contains(string(b), e[0]) {
			t.Fatalf("%s: %q not in the vector", name, e[0])
		}
		if msg := try("edit.json", strings.Replace(string(b), e[0], e[1], 1)); msg == "" {
			t.Errorf("%s: verdict-1 accepted it", name)
		}
	}
}

// TestBaselineSchemaRefuses is the positive control for baseline-1: the
// provider-signed vector validates, and each out-of-contract edit fails.
func TestBaselineSchemaRefuses(t *testing.T) {
	s, err := compileSchemas(schemas)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../pkg/verdict/testdata/baseline/valid/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	try := func(doc string) string {
		p := filepath.Join(dir, "baseline.json")
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return check(s, target{path: p, schema: "baseline-1.schema.json"})
	}
	if msg := try(string(b)); msg != "" {
		t.Fatalf("valid vector refused: %s", msg)
	}
	edits := map[string][2]string{
		"missing member":     {`"approver": "alice@bobthecorp.example",`, ``},
		"empty identity":     {`"id": "bkt-1"`, ``},
		"extra id member":    {`"id": "bkt-1"`, `"id": "bkt-1", "arn": "x"`},
		"id kind without id": {`"id": "bkt-1"`, `"bucket": "bkt-1"`},
		"empty identity val": {`"id": "bkt-1"`, `"id": ""`},
		"bad kind":           {`"identity_kind": "id"`, `"identity_kind": "none"`},
		"bad major":          {`"control_major": "2"`, `"control_major": "v2"`},
		"bad digest":         {`"read_digest": "sha256:`, `"read_digest": "sha1:`},
		"statement role":     {`"role": "baseline_approver"`, `"role": "admin"`},
		"statement format":   {`"format": "compliancetf.baseline-approval/v1"`, `"format": "x"`},
		"statement member":   {`"run_id": "run-obs-1",`, `"run_id": "run-obs-1", "extra": "x",`},
		"offset time":        {`"expires": "2026-12-01T00:00:00Z"`, `"expires": "2026-12-01T00:00:00+01:00"`},
		"number":             {`"control_major": "2"`, `"control_major": 2`},
		"wrong format":       {`"format": "compliancetf.baseline/v1"`, `"format": "compliancetf.baseline/v2"`},
	}
	for name, e := range edits {
		if !strings.Contains(string(b), e[0]) {
			t.Fatalf("%s: %q not in the vector", name, e[0])
		}
		if msg := try(strings.Replace(string(b), e[0], e[1], 1)); msg == "" {
			t.Errorf("%s: baseline-1 accepted it", name)
		}
	}
}

// TestBreakGlassSchemasRefuse is the positive control for override-1 and
// consume-receipt-1: the signed samples validate, a verdict embedding the
// receipt validates against verdict-1, and each edit pkg/verdict refuses
// fails the schema.
func TestBreakGlassSchemasRefuse(t *testing.T) {
	s, err := compileSchemas(schemas)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	try := func(schema, doc string) string {
		p := filepath.Join(dir, "doc.json")
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return check(s, target{path: p, schema: schema})
	}
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	bg := "../../pkg/verdict/testdata/breakglass/"
	cases := map[string]struct {
		file, schema string
		edits        map[string][2]string
	}{
		"override": {"override.json", "override-1.schema.json", map[string][2]string{
			"three approvals": {`"approvals": [`, `"approvals": [{"approver": "dave", "role": "break_glass_approver", "approved_at": "2026-10-19T08:10:00Z", ` +
				`"expires_at": "2026-10-19T19:00:00Z", "signature": {"kid": "sha256:` + strings.Repeat("0", 64) + `", "alg": "ES256", "value": "AA"}},`},
			"empty approver": {`"approver": "bob@bobthecorp.example"`, `"approver": ""`},
			"offset time":    {`"issued_at": "2026-10-19T08:00:00Z"`, `"issued_at": "2026-10-19T09:00:00+01:00"`},
			"dup control":    {"\"CTF.RDS.1\"\n", "\"CTF.S3.2\"\n"},
			"other alg":      {`"alg": "ES256"`, `"alg": "Ed25519"`},
		}},
		"receipt": {"consume-receipt.json", "consume-receipt-1.schema.json", map[string][2]string{
			"number":         {`"run_id": "run-1"`, `"run_id": 1`},
			"bad token":      {`"override_id": "ovr-01"`, `"override_id": "ovr 01"`},
			"missing format": {`"format": "compliancetf.consume-receipt/v1",`, ``},
			"bad digest":     {`"request_digest": "sha256:`, `"request_digest": "sha512:`},
		}},
	}
	for name, c := range cases {
		doc := read(bg + c.file)
		if msg := try(c.schema, doc); msg != "" {
			t.Fatalf("%s sample refused: %s", name, msg)
		}
		for e, ed := range c.edits {
			if !strings.Contains(doc, ed[0]) {
				t.Fatalf("%s %s: %q not in the sample", name, e, ed[0])
			}
			if msg := try(c.schema, strings.Replace(doc, ed[0], ed[1], 1)); msg == "" {
				t.Errorf("%s %s: %s accepted it", name, e, c.schema)
			}
		}
	}
	v := read("../../pkg/verdict/testdata/sig/valid/verdict.json")
	const empty = `"break_glass_receipts": []`
	if !strings.Contains(v, empty) {
		t.Fatalf("%q not in the verdict vector", empty)
	}
	rc := read(bg + "consume-receipt.json")
	if msg := try("verdict-1.schema.json", strings.Replace(v, empty, `"break_glass_receipts": [`+rc+`]`, 1)); msg != "" {
		t.Fatalf("verdict embedding the receipt refused: %s", msg)
	}
	bad := strings.Replace(rc, `"run_id": "run-1"`, `"run_id": ""`, 1)
	if msg := try("verdict-1.schema.json", strings.Replace(v, empty, `"break_glass_receipts": [`+bad+`]`, 1)); msg == "" {
		t.Error("verdict-1 accepted an embedded receipt consume-receipt-1 refuses")
	}
}

// TestEmptyMigrateExpectedFails is the PM-T02 oracle: the migrate fixture
// skeleton ships no expected files, and an empty placeholder committed in
// their place must fail make schemacheck, not pass as a filled case.
func TestEmptyMigrateExpectedFails(t *testing.T) {
	for _, name := range []string{"migrate-plan.json", "journal.json", "000001.wal.json"} {
		t.Run(name, func(t *testing.T) {
			dir := copyFixtures(t)
			rel := filepath.Join("migrate", "01-single-root-local", "expected", name)
			path := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			err := run(schemas, []string{dir}, io.Discard)
			var fail *failures
			if !errors.As(err, &fail) {
				t.Fatalf("an empty %s must fail, got %v", name, err)
			}
			if !strings.Contains(fail.Error(), rel) || !strings.Contains(fail.Error(), "not valid JSON") {
				t.Fatalf("failure does not name the empty %s:\n%v", rel, fail)
			}
		})
	}
}

// TestMigrateSchemasRefuse is the positive control for the three migrate
// schemas: the examples under schema/testdata/migrate validate, an empty
// object does not, and each out-of-contract edit fails.
func TestMigrateSchemasRefuse(t *testing.T) {
	s, err := compileSchemas(schemas)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	try := func(schema, doc string) string {
		p := filepath.Join(dir, "doc.json")
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return check(s, target{path: p, schema: schema})
	}
	ex := filepath.Join(schemas, "testdata", "migrate")
	cases := map[string]struct {
		file, schema string
		edits        map[string][2]string
	}{
		"plan": {"migrate-plan.json", "migrate-plan-1.schema.json", map[string][2]string{
			"credential value":       {`"backend_env": ["TFE_TOKEN"],`, `"backend_env": ["TFE_TOKEN"], "token": "x",`},
			"env value not name":     {`"backend_env": ["TFE_TOKEN"]`, `"backend_env": ["TFE_TOKEN=x"]`},
			"relative tf_bin":        {`"tf_bin": "/usr/local/bin/terraform"`, `"tf_bin": "terraform"`},
			"prefixed sha256":        {`"tf_bin_sha256": "`, `"tf_bin_sha256": "sha256:`},
			"unknown proof":          {`"proof": "no_op"`, `"proof": "skip"`},
			"unknown blocked kind":   {`"kind": "remote_module"`, `"kind": "other"`},
			"local without paths":    {`"backend": "s3"`, `"backend": "local"`},
			"paths on remote state":  {`"backend": "local"`, `"backend": "s3"`},
			"cli with remote":        {`"kind": "hcp"`, `"kind": "cli"`},
			"hcp without remote":     {",\n      \"remote\": { \"org\": \"bobthecorp\", \"id\": \"ws-bobthecorp0001\", \"name\": \"network\" }", ""},
			"edit escapes the root":  {`"file": "live/prod/versions.tf"`, `"file": "live/../../etc/passwd"`},
			"absolute edit path":     {`"file": "live/prod/versions.tf"`, `"file": "/live/prod/versions.tf"`},
			"no workspace":           {`"workspaces": ["default"]`, `"workspaces": []`},
			"short provider address": {`"from": "registry.terraform.io/hashicorp/aws"`, `"from": "hashicorp/aws"`},
			"offset time":            {`"created_at": "2026-10-20T09:00:00Z"`, `"created_at": "2026-10-20T10:00:00+01:00"`},
		}},
		"journal": {"journal.json", "migrate-journal-1.schema.json", map[string][2]string{
			"state bytes member": {`"lineage": "`, `"state": "{}", "lineage": "`},
			"unknown status":     {`"status": "migrated"`, `"status": "ok"`},
			"unknown step":       {`"name": "preflight"`, `"name": "push"`},
			"negative serial":    {`"serial_before": 41`, `"serial_before": -1`},
			"string serial":      {`"serial_before": 41`, `"serial_before": "41"`},
			"missing plan bind":  {`"plan_sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",`, ``},
		}},
		"wal": {"000002.wal.json", "migrate-wal-1.schema.json", map[string][2]string{
			"inline image":         {`"path": "images/live-prod-versions.tf",`, `"path": "images/live-prod-versions.tf", "content": "x",`},
			"file image no source": {`"source": "live/prod/versions.tf", "sha256"`, `"sha256"`},
			"unknown status":       {`"status": "done"`, `"status": "maybe"`},
			"zero seq":             {`"seq": 2`, `"seq": 0`},
			"no operation id":      {`"operation_id": "op-0002",`, ``},
			"state image source":   {`{ "kind": "file", "path": "images/live-prod-versions.tf.after"`, `{ "kind": "state", "path": "images/live-prod-versions.tf.after"`},
		}},
		"wal intent": {"000001.wal.json", "migrate-wal-1.schema.json", map[string][2]string{
			"serial without lineage": {`"serial": 41, "lineage": "3f1c2e5a-0000-4000-8000-bobthecorp01"`, `"serial": 41`},
			"lineage without serial": {`"serial": 41, "lineage"`, `"lineage"`},
		}},
	}
	for name, c := range cases {
		b, err := os.ReadFile(filepath.Join(ex, c.file))
		if err != nil {
			t.Fatal(err)
		}
		doc := string(b)
		if msg := try(c.schema, doc); msg != "" {
			t.Fatalf("%s example refused: %s", name, msg)
		}
		if msg := try(c.schema, "{}"); msg == "" {
			t.Errorf("%s: %s accepted {}", name, c.schema)
		}
		for e, ed := range c.edits {
			if !strings.Contains(doc, ed[0]) {
				t.Fatalf("%s %s: %q not in the example", name, e, ed[0])
			}
			if msg := try(c.schema, strings.Replace(doc, ed[0], ed[1], 1)); msg == "" {
				t.Errorf("%s %s: %s accepted it", name, e, c.schema)
			}
		}
	}
}
