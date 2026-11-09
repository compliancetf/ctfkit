// Package catalog is the file backend of ctfkit.ControlCatalog: it turns a
// ctf.catalog/1 document into an immutable snapshot an analyzer can read.
//
// A catalog is never discovered from the repository under analysis, because a
// scanned repository that could plant one could hide findings. Only three
// sources are read, in this order: the file named on the command line, the
// file at the home path, and the release catalog embedded in the binary.
// A file replaces the embedded catalog wholesale; nothing is merged. An
// unreadable or invalid file is an error at either location, never a silent
// fallback, so a typo in a vendored catalog cannot quietly turn into a
// different set of requirements. Only a missing home file falls through to the
// embedded release.
//
// Every error this package returns wraps ErrCatalog, which the command layer
// maps to exit 2 with the catalog diagnostic prefix.
package catalog

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// ErrCatalog marks every error this package returns. The command layer tests
// for it with errors.Is and reports exit 2 under the catalog prefix.
var ErrCatalog = errors.New("catalog error")

// schemaMajor is the only catalog major this build reads. A document
// declaring another one is an environment error, the manifest rule applied to
// the catalog.
const (
	schemaPrefix = "ctf.catalog/"
	schemaMajor  = "1"
)

// homeRelPath is where a vendored catalog lives when the operator names none.
// It is under the home directory, not the working directory, so a scanned
// repository cannot supply it.
var homeRelPath = filepath.Join(".ctf", "control-requirements.yaml")

// embeddedSentinel pins the release catalog and ignores the home file.
const embeddedSentinel = "embedded"

// Provenance values recorded in ctfkit.CatalogVersion. They are descriptive,
// not trust claims.
const (
	provenanceEmbedded = "embedded"
	provenanceFile     = "file"
	provenanceHome     = "home"
)

// EmbeddedSubsetNote is what a finding message adds about a control id the
// loaded catalog lacks: when that catalog is the embedded one, which holds the
// CIS v6.0 controls only, it says so and names the way to a full catalog. The
// test is the version, not the provenance, so a file copy of the embedded
// catalog gets the same text. Any other catalog gets nothing, since the hint
// would be wrong for it.
func EmbeddedSubsetNote(v ctfkit.CatalogVersion) string {
	if v.Version != Embedded().Version().Version {
		return ""
	}
	return " (the embedded catalog holds the CIS v6.0 controls only; name a full catalog with --catalog)"
}

//go:embed data/catalog.yaml
var embeddedYAML []byte

// semverPattern is the semver.org grammar, the same one catalog-1.schema.json
// states. A version that does not match cannot be ordered against the embedded
// release, so staleness could never be detected and the file is refused.
var semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// FileCatalog is a loaded catalog: a preloaded, immutable snapshot that is
// safe for concurrent use. Every method answers from memory and hands back
// copies, so a caller cannot reach back into it.
type FileCatalog struct {
	ctfkit.CatalogSeal

	version      ctfkit.CatalogVersion
	controls     map[ctfkit.ControlID]ctfkit.ControlRef
	byType       map[string][]ctfkit.ControlID
	modules      []ctfkit.ModuleRef
	moduleByType map[string]int
	hosts        map[string]string
	defaultHost  string
}

// EmbeddedBytes returns the raw bytes of the embedded release catalog, which
// is what a validator reads to hold the release to the same rules as a
// vendored file.
func EmbeddedBytes() []byte { return embeddedYAML }

// embedded parses the release catalog once. A build whose embedded catalog
// does not load is broken at the source, not misconfigured by an operator, so
// it fails loudly rather than degrading a run.
var embedded = sync.OnceValue(func() *FileCatalog {
	c, err := parse(embeddedYAML, provenanceEmbedded)
	if err != nil {
		panic(fmt.Sprintf("the embedded release catalog does not load: %v", err))
	}
	return c
})

// Embedded returns the release catalog compiled into the binary. It is what a
// run with no catalog file uses, which is what makes control ids available
// with no network, no credentials and no configuration.
func Embedded() *FileCatalog { return embedded() }

// Load reads a catalog file. It returns an error wrapping ErrCatalog when the
// file cannot be read, does not parse, declares an unsupported schema major,
// carries an unusable version, or breaks one of the rules Check states.
func Load(path string) (*FileCatalog, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the path is the operator's own --catalog value or the home path, never a value from the repository under analysis
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrCatalog, path, err)
	}
	c, err := parse(b, provenanceFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Resolve applies the lookup order to the --catalog value: a file when one is
// named, the literal "embedded" to pin the release catalog past a home file,
// otherwise the home file when it exists and the release catalog when it does
// not. The returned version carries the origin, which the run object reports
// so a later reader can tell which requirements were in force.
func Resolve(flag string) (*FileCatalog, ctfkit.CatalogVersion, error) {
	switch {
	case flag == embeddedSentinel:
		c := Embedded()
		return c, c.Version(), nil

	case flag != "":
		c, err := Load(flag)
		if err != nil {
			return nil, ctfkit.CatalogVersion{}, err
		}
		return c, c.Version(), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		// No home directory is not a misconfigured catalog; the embedded
		// release is the answer and the run goes on.
		c := Embedded()
		return c, c.Version(), nil
	}

	path := filepath.Join(home, homeRelPath)
	if _, statErr := os.Stat(path); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			c := Embedded()
			return c, c.Version(), nil
		}
		return nil, ctfkit.CatalogVersion{}, fmt.Errorf("%w: reading %s: %w", ErrCatalog, path, statErr)
	}

	c, err := Load(path)
	if err != nil {
		return nil, ctfkit.CatalogVersion{}, err
	}
	c.version.Provenance = provenanceHome
	return c, c.Version(), nil
}

// parse turns catalog bytes into a snapshot. The returned error always wraps
// ErrCatalog so a caller that skips Load still reports the right exit code.
func parse(b []byte, provenance string) (*FileCatalog, error) {
	var doc document
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: the catalog does not parse as YAML: %w", ErrCatalog, err)
	}

	if err := checkSchema(doc.Schema); err != nil {
		return nil, err
	}
	if err := checkRequired(b); err != nil {
		return nil, err
	}
	if !semverPattern.MatchString(doc.Version) {
		return nil, fmt.Errorf("%w: version %q is not a semantic version", ErrCatalog, doc.Version)
	}
	if msgs := checkDocument(doc); len(msgs) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrCatalog, strings.Join(msgs, "; "))
	}

	c := &FileCatalog{
		version:      ctfkit.CatalogVersion{Version: doc.Version, Provenance: provenance},
		controls:     make(map[ctfkit.ControlID]ctfkit.ControlRef, len(doc.Controls)),
		byType:       make(map[string][]ctfkit.ControlID),
		modules:      make([]ctfkit.ModuleRef, 0, len(doc.Modules)),
		moduleByType: make(map[string]int),
		hosts:        make(map[string]string, len(doc.Hosts)),
		defaultHost:  doc.DefaultHost,
	}

	for k, v := range doc.Hosts {
		c.hosts[k] = v
	}

	for _, dc := range doc.Controls {
		id := ctfkit.ControlID(dc.ID)
		ref := ctfkit.ControlRef{
			ID:                 id,
			Name:               dc.Name,
			ResourceTypes:      append([]string(nil), dc.ResourceTypes...),
			ClausesByFramework: make(map[string][]string, len(dc.ClausesByFramework)),
		}
		for fw, clauses := range dc.ClausesByFramework {
			ref.ClausesByFramework[fw] = append([]string(nil), clauses...)
		}
		c.controls[id] = ref
		for _, rt := range dc.ResourceTypes {
			c.byType[rt] = append(c.byType[rt], id)
		}
	}

	for _, dm := range doc.Modules {
		mod := ctfkit.ModuleRef{
			ResourceTypes: append([]string(nil), dm.ResourceTypes...),
			Source:        dm.Source,
			Version:       dm.Version,
			Controls:      make([]ctfkit.ControlID, 0, len(dm.Controls)),
		}
		for _, id := range dm.Controls {
			mod.Controls = append(mod.Controls, ctfkit.ControlID(id))
		}
		c.modules = append(c.modules, mod)
		for _, rt := range dm.ResourceTypes {
			c.moduleByType[rt] = len(c.modules) - 1
		}
	}

	return c, nil
}

// checkRequired reports a document missing one of the keys catalog-1 requires.
// A missing key unmarshals to the zero value, which a rule over the parsed
// document cannot tell from an empty one, so a catalog with no controls at all
// would otherwise load and quietly find nothing. schemacheck gets this from
// the JSON Schema; a run reading an operator's file gets it here.
func checkRequired(b []byte) error {
	var keys map[string]yaml.Node
	if err := yaml.Unmarshal(b, &keys); err != nil {
		return fmt.Errorf("%w: the catalog does not parse as YAML: %w", ErrCatalog, err)
	}
	var missing []string
	for _, k := range []string{"schema", "version", "hosts", "defaultHost", "controls", "modules"} {
		if _, ok := keys[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: the catalog is missing the required key(s) %s", ErrCatalog, strings.Join(missing, ", "))
	}
	return nil
}

func checkSchema(schema string) error {
	if !strings.HasPrefix(schema, schemaPrefix) {
		return fmt.Errorf("%w: %q is not a control catalog; expected a %s1 document", ErrCatalog, schema, schemaPrefix)
	}
	if major := strings.TrimPrefix(schema, schemaPrefix); major != schemaMajor {
		return fmt.Errorf("%w: catalog schema major %s is not supported; this build reads %s%s", ErrCatalog, major, schemaPrefix, schemaMajor)
	}
	return nil
}

// ControlsFor returns the controls that apply to a Terraform resource type, in
// catalog order.
func (c FileCatalog) ControlsFor(resourceType string) []ctfkit.ControlID {
	return append([]ctfkit.ControlID(nil), c.byType[resourceType]...)
}

// Control returns the full catalog entry for a control id.
func (c FileCatalog) Control(id ctfkit.ControlID) (ctfkit.ControlRef, bool) {
	ref, ok := c.controls[id]
	if !ok {
		return ctfkit.ControlRef{}, false
	}
	return copyControl(ref), true
}

// Frameworks returns the framework ids that control maps to, sorted.
func (c FileCatalog) Frameworks(id ctfkit.ControlID) []string {
	ref, ok := c.controls[id]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(ref.ClausesByFramework))
	for fw := range ref.ClausesByFramework {
		out = append(out, fw)
	}
	sort.Strings(out)
	return out
}

// Framework returns the clauses that control satisfies in the named framework.
func (c FileCatalog) Framework(id ctfkit.ControlID, framework string) []string {
	ref, ok := c.controls[id]
	if !ok {
		return nil
	}
	return append([]string(nil), ref.ClausesByFramework[framework]...)
}

// ModuleFor returns the module that covers a resource type.
func (c FileCatalog) ModuleFor(resourceType string) (ctfkit.ModuleRef, bool) {
	i, ok := c.moduleByType[resourceType]
	if !ok {
		return ctfkit.ModuleRef{}, false
	}
	return copyModule(c.modules[i]), true
}

// Modules returns every module entry, in catalog order.
func (c FileCatalog) Modules() []ctfkit.ModuleRef {
	out := make([]ctfkit.ModuleRef, 0, len(c.modules))
	for _, m := range c.modules {
		out = append(out, copyModule(m))
	}
	return out
}

// Hosts maps a framework id to the label of its registry endpoint.
func (c FileCatalog) Hosts() map[string]string {
	out := make(map[string]string, len(c.hosts))
	for k, v := range c.hosts {
		out[k] = v
	}
	return out
}

// DefaultHost returns the host label to substitute when the operator named
// none. It is always a key of Hosts.
func (c FileCatalog) DefaultHost() string { return c.defaultHost }

// Version returns the version and provenance of the loaded catalog.
func (c FileCatalog) Version() ctfkit.CatalogVersion { return c.version }

func copyControl(ref ctfkit.ControlRef) ctfkit.ControlRef {
	out := ctfkit.ControlRef{
		ID:                 ref.ID,
		Name:               ref.Name,
		ResourceTypes:      append([]string(nil), ref.ResourceTypes...),
		ClausesByFramework: make(map[string][]string, len(ref.ClausesByFramework)),
	}
	for fw, clauses := range ref.ClausesByFramework {
		out.ClausesByFramework[fw] = append([]string(nil), clauses...)
	}
	return out
}

func copyModule(m ctfkit.ModuleRef) ctfkit.ModuleRef {
	return ctfkit.ModuleRef{
		ResourceTypes: append([]string(nil), m.ResourceTypes...),
		Source:        m.Source,
		Version:       m.Version,
		Controls:      append([]ctfkit.ControlID(nil), m.Controls...),
	}
}

// ClauseIdentifiers shortens the clause titles the catalog stores to the
// identifiers a finding's ctf.frameworks carries, each once, in input order,
// by ClauseIdentifier.
func ClauseIdentifiers(titles []string) []string {
	out := make([]string, 0, len(titles))
	seen := make(map[string]bool, len(titles))
	for _, title := range titles {
		id := ClauseIdentifier(title)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// ClauseIdentifier shortens one clause title to its identifier. It is the one
// rule every analyzer and renderer applies, catalog and manifest clauses
// alike, so a clause is spelled the same way everywhere. In order:
//
//   - A title that leads with an identifier keeps it, trailing colon dropped:
//     "CC7.2: The entity ..." and "A1.2 The entity ..." become "CC7.2", "A1.2".
//   - A title that ends in a parenthesized control id keeps the id:
//     "Denial Of Service Protection (SC-5)" becomes "SC-5".
//   - A title with a number in its first three words keeps those words:
//     "Article 25 Data protection ..." becomes "Article 25".
//   - Any other title has no identifier, so it is kept whole, never cut to
//     its first word: "Data protection" stays "Data protection".
func ClauseIdentifier(title string) string {
	fields := strings.Fields(title)
	if len(fields) == 0 {
		return ""
	}
	if hasDigit(fields[0]) {
		return strings.TrimSuffix(fields[0], ":")
	}
	last := fields[len(fields)-1]
	if id, ok := strings.CutPrefix(last, "("); ok && strings.HasSuffix(id, ")") &&
		hasDigit(id) && strings.IndexFunc(id, unicode.IsLetter) >= 0 {
		return strings.TrimSuffix(id, ")")
	}
	for i := 1; i < min(3, len(fields)); i++ {
		if hasDigit(fields[i]) {
			return strings.TrimSuffix(strings.Join(fields[:i+1], " "), ":")
		}
	}
	return strings.Join(fields, " ")
}

func hasDigit(s string) bool {
	return strings.IndexFunc(s, unicode.IsDigit) >= 0
}
