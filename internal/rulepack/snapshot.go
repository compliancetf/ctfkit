package rulepack

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// SnapshotFile is the name of the trimmed provider schema kept next to a
// pack. It is not embedded in the binary: only the tests and the generator
// read it.
const SnapshotFile = "schema.json"

// Snapshot is a trimmed `terraform providers schema -json`: every attribute of
// each resource type a pack's rules or controls name, and, for every other
// resource type, the attributes Tracked matches. A pack is validated against
// it, and the generator diffs the tracked attributes to propose draft rules.
type Snapshot struct {
	// Provider is the full provider address the schema came from.
	Provider string `json:"provider"`
	// Version is the provider version the schema came from.
	Version string `json:"version"`
	// Resources maps each resource type to its attributes and nested blocks.
	// A value is a kind, or for a nested block or object a map from each of
	// its fields to a kind.
	Resources map[string]map[string]any `json:"resources"`
}

// Attribute kinds a snapshot records.
const (
	KindBool    = "bool"
	KindNumber  = "number"
	KindString  = "string"
	KindList    = "list"
	KindMap     = "map"
	KindObject  = "object"
	KindDynamic = "dynamic"
)

// Tracked matches the attribute names the generator watches in resource types
// no rule names yet: the names a sensitive-change rule is most often about.
var Tracked = regexp.MustCompile(`^encrypted$|encryption|^kms_key_id$|^publicly_accessible$|^deletion_protection|logging|^retention_`)

// ReadSnapshot reads the snapshot of one pack, such as "aws/v6", from fsys
// rooted above rules/.
func ReadSnapshot(fsys fs.FS, pack string) (*Snapshot, error) {
	b, err := fs.ReadFile(fsys, path.Join(Root, pack, SnapshotFile))
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err = json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s/%s: %w", pack, SnapshotFile, err)
	}
	return &s, nil
}

// Kind returns the kind of attribute attr of a resource type, following one
// dot into a nested block or object, and whether the snapshot has it. A
// nested block or object has the kind KindObject.
func (s *Snapshot) Kind(resourceType, attr string) (string, bool) {
	attrs, ok := s.Resources[resourceType]
	if !ok {
		return "", false
	}
	name, field, nested := strings.Cut(attr, ".")
	v, ok := attrs[name]
	if !ok {
		return "", false
	}
	if nested {
		fields, isObject := v.(map[string]any)
		if !isObject {
			return "", false
		}
		v, ok = fields[field]
		if !ok {
			return "", false
		}
	}
	if _, isObject := v.(map[string]any); isObject {
		return KindObject, true
	}
	kind, _ := v.(string)
	return kind, true
}

// ReferencedTypes returns every resource type the pack's rules,
// controls.yaml or identities.yaml name, sorted.
func (p *Pack) ReferencedTypes() []string {
	seen := map[string]bool{}
	for _, r := range p.Rules {
		for _, t := range r.Types {
			seen[t] = true
		}
	}
	for t := range p.controls {
		seen[t] = true
	}
	for _, key := range p.Identities.Attributes() {
		t, _, _ := strings.Cut(key, ".")
		seen[t] = true
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
