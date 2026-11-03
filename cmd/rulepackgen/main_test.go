package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/rulepack"
)

// providerSchemas is a two-resource `terraform providers schema -json`.
const providerSchemas = `{"format_version": "1.0", "provider_schemas": {
  "registry.terraform.io/bobthecorp/demo": {"resource_schemas": {
    "demo_db": {"version": 0, "block": {
      "attributes": {
        "public": {"type": "bool", "optional": true},
        "name": {"type": "string", "optional": true},
        "ranges": {"type": ["set", "string"], "optional": true},
        "rules": {"type": ["list", ["object", {"cidr": ["list", "string"], "port": "number"}]], "optional": true}
      },
      "block_types": {"encryption": {"nesting_mode": "list", "block": {"attributes": {"enabled": {"type": "bool", "optional": true}}}}}
    }},
    "demo_cache": {"version": 0, "block": {"attributes": {
      "size": {"type": "number", "optional": true},
      "encrypted": {"type": "bool", "optional": true},
      "retention_days": {"type": "number", "optional": true},
      "kms_key_id": {"type": "string", "optional": true}
    }}}
  }}}}`

func writePack(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunWritesSnapshotAndDrafts(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, map[string]string{
		"rules/defaults.yaml":         "tags: {attribute: tags}\n",
		"rules/demo/v1/provider.yaml": "source: bobthecorp/demo\nresource_prefix: demo_\ntags: {attribute: tags}\n",
		"rules/demo/v1/rules.yaml":    "class: public_exposure\nrules:\n  - {types: [demo_db], attribute: public, predicate: turned_on, level: error}\n",
		// The previous snapshot already tracked demo_cache.encrypted.
		"rules/demo/v1/schema.json": `{"provider": "registry.terraform.io/bobthecorp/demo", "version": "1.0.0",
			"resources": {"demo_cache": {"encrypted": "bool"}}}`,
		"schema.json": providerSchemas,
	})
	drafts := filepath.Join(root, "drafts.md")
	err := run([]string{"-root", root, "-pack", "demo/v1", "-schema", filepath.Join(root, "schema.json"),
		"-version", "1.1.0", "-proposals", drafts}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	snap, err := rulepack.ReadSnapshot(os.DirFS(root), "demo/v1")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		// A referenced type keeps every attribute, nested ones one level down.
		"demo_db.public": "bool", "demo_db.name": "string", "demo_db.ranges": "list",
		"demo_db.rules": "object", "demo_db.rules.port": "number", "demo_db.rules.cidr": "list",
		"demo_db.encryption": "object", "demo_db.encryption.enabled": "bool",
		// Another type keeps its tracked attributes only.
		"demo_cache.encrypted": "bool", "demo_cache.retention_days": "number", "demo_cache.kms_key_id": "string",
	}
	for key, want := range cases {
		typ, attr, _ := strings.Cut(key, ".")
		if got, ok := snap.Kind(typ, attr); !ok || got != want {
			t.Errorf("%s is %q (present %v), want %q", key, got, ok, want)
		}
	}
	if _, ok := snap.Kind("demo_cache", "size"); ok {
		t.Error("an untracked attribute of an unreferenced type was kept")
	}
	if snap.Version != "1.1.0" || snap.Provider != "registry.terraform.io/bobthecorp/demo" {
		t.Errorf("snapshot names %s %s", snap.Provider, snap.Version)
	}

	b, err := os.ReadFile(drafts)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{
		"(was 1.0.0)",
		"### audit_log_removal.yaml", "attribute: retention_days\n    predicate: shortened",
		"### encryption_disablement.yaml", "attribute: kms_key_id\n    predicate: removed",
		"attribute: encryption\n    predicate: block_removed",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("drafts lack %q:\n%s", want, text)
		}
	}
	// Tracked before, or already read by a rule: no draft.
	if strings.Contains(text, "attribute: encrypted\n") || strings.Contains(text, "attribute: public\n") {
		t.Errorf("drafts repeat an attribute already tracked or read:\n%s", text)
	}
}

func TestRunNeedsItsFlags(t *testing.T) {
	if err := run([]string{"-pack", "demo/v1"}, io.Discard); err == nil {
		t.Error("run accepted a call with no schema or version")
	}
}
