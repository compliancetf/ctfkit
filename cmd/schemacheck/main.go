// Command schemacheck validates the fixture pack against the JSON Schemas in
// schema/.
//
// The fixture pack is the oracle every analyzer and renderer is built against,
// and the schemas are the machine-checkable form of the report specification
// and the findings format. This command keeps the two from drifting: it walks a
// fixture tree, picks a schema per file name, and reports every file that does
// not validate. Evidence chains (*.jsonl, the provider's goldens under
// schema/testdata/provider-evidence) are checked line by line.
//
//	go run ./cmd/schemacheck testdata/fixtures
//
// It exits 0 when everything validates, 1 when something does not, and 2 when
// it could not run at all (bad arguments, unreadable schema, no fixtures).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/internal/catalog"
)

// byFileName maps a fixture file name to the schema that validates it.
var byFileName = map[string]string{
	"receipt.json":                 "receipt-1.schema.json",
	"ctfkit.custom.spacelift.json": "spacelift-1.schema.json",
	"findings.sarif":               "cff-1.schema.json",
	"compliancetf-manifest.json":   "manifest-3.schema.json",
	"verdict.json":                 "verdict-1.schema.json",
	"expected.verdict.json":        "verdict-1.schema.json",
	"baseline.json":                "baseline-1.schema.json",
	"override.json":                "override-1.schema.json",
	"consume-receipt.json":         "consume-receipt-1.schema.json",
	"migrate-plan.json":            "migrate-plan-1.schema.json",
	"journal.json":                 "migrate-journal-1.schema.json",
}

// catalogSchema validates a control catalog. A catalog is found by its content
// rather than its file name, because a fixture directory also holds .ctfkit.yaml
// settings and .ctf-exceptions.yaml, and neither is a catalog.
const (
	catalogSchema = "catalog-1.schema.json"
	// catalogMarker is a prefix, not the whole value, so a catalog declaring a
	// schema other than ctf.catalog/1 is still recognized as a catalog and
	// then refused by the schema, rather than passing unnoticed.
	catalogMarker = "ctf.catalog/"
	// embeddedCatalogName is what the release catalog embedded in the binary
	// is reported as. It is not a fixture and has no path under the fixture
	// root, but it is a catalog, and a release that broke catalog-1 would ship
	// remediation nothing could read.
	embeddedCatalogName = "the embedded release catalog"
	// evidenceSchema validates every line of a provider evidence chain
	// (*.jsonl). The chain rules (canonical form, prev links, segments) are
	// internal/evidence's; this checks each record against the format.
	evidenceSchema = "evidence-record-1.schema.json"
	// walSchema validates a migrate write-ahead log record. Each record is its
	// own file (000001.wal.json, ...), so it is found by suffix.
	walSchema = "migrate-wal-1.schema.json"
	walSuffix = ".wal.json"
)

// exitCodes are the only values an expected/exit-code file may hold: 0 ok,
// 1 findings at or above --fail-on, 2 environment error.
var exitCodes = map[string]bool{"0": true, "1": true, "2": true}

func main() {
	fs := flag.NewFlagSet("schemacheck", flag.ContinueOnError)
	schemaDir := fs.String("schema-dir", "schema", "directory holding the *.schema.json files")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if err := run(*schemaDir, fs.Args(), os.Stdout); err != nil {
		var fail *failures
		if errors.As(err, &fail) {
			fmt.Fprint(os.Stderr, fail.Error())
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "schemacheck: %v\n", err)
		os.Exit(2)
	}
}

// failures is every file that did not validate. It is a distinct type from an
// environment error so the caller can tell exit 1 from exit 2.
type failures struct{ msgs []string }

func (f *failures) Error() string {
	var b strings.Builder
	for _, m := range f.msgs {
		b.WriteString(m)
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "schemacheck: %d file(s) failed\n", len(f.msgs))
	return b.String()
}

func run(schemaDir string, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: schemacheck [-schema-dir DIR] <fixtures-dir>")
	}
	root := args[0]

	schemas, err := compileSchemas(schemaDir)
	if err != nil {
		return err
	}

	targets, err := collect(root)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no fixture files found under %s", root)
	}

	// The example beside the schemas is a catalog outside the fixture root, so
	// it is walked separately. A catalog inside the fixture tree is picked up
	// by the walk above.
	extra, err := collect(filepath.Join(schemaDir, "testdata"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	targets = append(targets, extra...)

	// The release catalog has no path at all: it is compiled into the binary.
	// Validating the bytes the package embeds, rather than a file found by a
	// path relative to the working directory, is what makes this check run
	// wherever the command is invoked from, a test binary included.
	targets = append(targets, target{
		path:      embeddedCatalogName,
		schema:    catalogSchema,
		isCatalog: true,
		content:   catalog.EmbeddedBytes(),
	})

	var fail failures
	for _, t := range targets {
		if msg := check(schemas, t); msg != "" {
			fail.msgs = append(fail.msgs, msg)
		}
	}
	if len(fail.msgs) > 0 {
		return &fail
	}
	_, _ = fmt.Fprintf(out, "schemacheck: %d file(s) validated under %s\n", len(targets), root)
	return nil
}

// compileSchemas compiles every schema in dir, keyed by file name. Schemas are
// added as resources under their file name so a cross-schema $ref resolves
// locally and nothing reaches the network.
func compileSchemas(dir string) (map[string]*jsonschema.Schema, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.schema.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no *.schema.json under %s", dir)
	}

	c := jsonschema.NewCompiler()
	c.AssertFormat() // a date-time that is not a real time fails, not just annotates
	for _, p := range paths {
		f, err := os.Open(p) // #nosec G304 -- p comes from the fixture walk under the operator-chosen root
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		closeErr := f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err := c.AddResource(filepath.Base(p), doc); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		// A relative $ref resolves against the referring schema's $id, so
		// each schema is also registered under its own $id.
		if m, ok := doc.(map[string]any); ok {
			if id, ok := m["$id"].(string); ok {
				if err := c.AddResource(id, doc); err != nil {
					return nil, fmt.Errorf("%s: %w", p, err)
				}
			}
		}
	}

	out := make(map[string]*jsonschema.Schema, len(paths))
	for _, p := range paths {
		name := filepath.Base(p)
		s, err := c.Compile(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = s
	}
	return out, nil
}

// target is one fixture file and how it must be treated.
type target struct {
	path string
	// schema is the schema file name, empty for an exit-code file.
	schema string
	// wantInvalid marks a fixture recorded as deliberately out of contract:
	// report/schema-4-stub carries a manifest declaring schema 4, and the case
	// exists to assert that an unsupported major is refused. Validating it
	// would be the wrong answer, so the check is inverted and the manifest
	// major pin gets a positive control instead of passing vacuously.
	wantInvalid bool
	// isExitCode marks expected/exit-code.
	isExitCode bool
	// content holds the bytes to check when they do not come from a file,
	// which is how the embedded release catalog is checked.
	content []byte
	// isCatalog marks a control catalog, which is YAML and carries a
	// uniqueness rule no JSON Schema can express.
	isCatalog bool
	// isJSONL marks an evidence chain: one record per LF-terminated line.
	isJSONL bool
}

func collect(root string) ([]target, error) {
	var out []target
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		switch {
		case name == "exit-code" && filepath.Base(filepath.Dir(path)) == "expected":
			out = append(out, target{path: path, isExitCode: true})
		case strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
			if isCatalog(path) {
				out = append(out, target{path: path, schema: catalogSchema, isCatalog: true})
			}
		case strings.HasSuffix(name, walSuffix):
			out = append(out, target{path: path, schema: walSchema})
		case strings.HasSuffix(name, ".jsonl"):
			out = append(out, target{path: path, schema: evidenceSchema, isJSONL: true})
		case byFileName[name] != "":
			out = append(out, target{
				path:        path,
				schema:      byFileName[name],
				wantInvalid: unsupportedMajor(path),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

// isCatalog reports whether path is a control catalog, by reading its schema
// key. Anything that is not valid YAML, or declares another schema, is not one.
func isCatalog(path string) bool {
	b, err := os.ReadFile(path) // #nosec G304 -- path comes from the fixture walk under the operator-chosen root
	if err != nil {
		return false
	}
	var head struct {
		Schema string `yaml:"schema"`
	}
	if yaml.Unmarshal(b, &head) != nil {
		return false
	}
	return strings.HasPrefix(head.Schema, catalogMarker)
}

// unsupportedMajor reports whether a manifest declares a schema major other
// than 3. Such a manifest is an input the command refuses, so schemacheck
// expects it to fail validation.
func unsupportedMajor(path string) bool {
	if filepath.Base(path) != "compliancetf-manifest.json" {
		return false
	}
	b, err := os.ReadFile(path) // #nosec G304 -- path comes from the fixture walk under the operator-chosen root
	if err != nil {
		return false
	}
	var head struct {
		SchemaVersion string `json:"schema_version"`
	}
	if json.Unmarshal(b, &head) != nil {
		return false
	}
	return !strings.HasPrefix(head.SchemaVersion, "3.")
}

// check validates one fixture file and returns a failure message, or "" when
// it is fine.
func check(schemas map[string]*jsonschema.Schema, t target) string {
	b := t.content
	if b == nil {
		var err error
		b, err = os.ReadFile(t.path)
		if err != nil {
			return fmt.Sprintf("%s: %v", t.path, err)
		}
	}

	if t.isExitCode {
		code := strings.TrimSpace(string(b))
		if !exitCodes[code] {
			return fmt.Sprintf("%s: exit code %q is not 0, 1 or 2", t.path, code)
		}
		return ""
	}

	s := schemas[t.schema]
	if s == nil {
		return fmt.Sprintf("%s: no compiled schema %s", t.path, t.schema)
	}
	if t.isJSONL {
		return checkLines(s, t.path, b)
	}

	doc, err := decode(b, t.isCatalog)
	if err != nil {
		return fmt.Sprintf("%s: %v", t.path, err)
	}

	err = s.Validate(doc)
	if t.wantInvalid {
		if err == nil {
			return fmt.Sprintf("%s: validates against %s, but the fixture is recorded as out of contract and the schema must refuse it", t.path, t.schema)
		}
		return ""
	}
	if err != nil {
		return fmt.Sprintf("%s: does not validate against %s:\n%v", t.path, t.schema, err)
	}

	if t.isCatalog {
		if msgs := catalog.Check(b); len(msgs) > 0 {
			return fmt.Sprintf("%s: %s", t.path, strings.Join(msgs, "\n  "))
		}
	}
	return ""
}

// checkLines validates every complete line of an evidence chain. Bytes after
// the last LF are a cut line (a truncated chain is a valid golden) and are the
// chain verifier's to report, not the schema's.
func checkLines(s *jsonschema.Schema, path string, b []byte) string {
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		return fmt.Sprintf("%s: no complete line", path)
	}
	var msgs []string
	for i, l := range lines[:len(lines)-1] {
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(l))
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("line %d: not a single JSON value", i+1))
			continue
		}
		var verr *jsonschema.ValidationError
		if err := s.Validate(doc); errors.As(err, &verr) {
			for _, w := range valueFree(verr) {
				msgs = append(msgs, fmt.Sprintf("line %d: %s", i+1, w))
			}
		} else if err != nil {
			msgs = append(msgs, fmt.Sprintf("line %d: validate failed", i+1))
		}
	}
	if len(msgs) > 0 {
		return fmt.Sprintf("%s: does not validate against %s:\n%s", path, evidenceSchema, strings.Join(msgs, "\n"))
	}
	return ""
}

// valueFree names each failing leaf by instance location and schema keyword
// only: the validator's own messages quote record values (a pattern miss
// prints the string), and evidence records must not reach output.
func valueFree(e *jsonschema.ValidationError) []string {
	if len(e.Causes) == 0 {
		kw := strings.Join(e.ErrorKind.KeywordPath(), "/")
		if kw == "" {
			kw = "not allowed" // a false schema, e.g. a property additionalProperties refuses
		}
		return []string{fmt.Sprintf("/%s: %s", strings.Join(e.InstanceLocation, "/"), kw)}
	}
	var out []string
	for _, c := range e.Causes {
		out = append(out, valueFree(c)...)
	}
	return out
}

// decode turns a fixture's bytes into the value the validator walks. A catalog
// is YAML, so it goes through JSON on the way, which keeps the types and the
// validation semantics identical to every other file here.
func decode(b []byte, isYAML bool) (any, error) {
	if isYAML {
		var v any
		if err := yaml.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("not valid YAML: %w", err)
		}
		j, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("not representable as JSON: %w", err)
		}
		b = j
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(b)))
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	return doc, nil
}
