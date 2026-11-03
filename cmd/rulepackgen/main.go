// Command rulepackgen regenerates a rule pack's schema.json from the output of
// `terraform providers schema -json`, and writes draft rules for tracked
// attributes that are new since the previous snapshot. The drafts are for a
// person to review: nothing it writes is merged without one.
//
//	rulepackgen -pack aws/v6 -schema schema.json -version 6.66.0 [-proposals drafts.md]
//
// scripts/refresh-rule-pack-schemas.sh runs it for every pack, and the
// weekly rule-pack-schemas workflow opens a pull request with the result.
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

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/zclconf/go-cty/cty"

	"github.com/compliancetf/ctfkit/internal/rulepack"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rulepackgen:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("rulepackgen", flag.ContinueOnError)
	root := flags.String("root", "internal/rulepack", "directory that holds rules/")
	packName := flags.String("pack", "", "pack to regenerate, for example aws/v6")
	schemaPath := flags.String("schema", "", "output of terraform providers schema -json")
	version := flags.String("version", "", "provider version the schema came from")
	proposals := flags.String("proposals", "", "markdown file for draft-rule proposals; empty for none")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *packName == "" || *schemaPath == "" || *version == "" {
		return errors.New("-pack, -schema and -version are required")
	}

	set, err := rulepack.Parse(os.DirFS(*root))
	if err != nil {
		return err
	}
	var pack *rulepack.Pack
	for _, p := range set.Packs() {
		if p.Name == *packName {
			pack = p
		}
	}
	if pack == nil {
		return fmt.Errorf("no pack %s under %s", *packName, *root)
	}

	raw, err := os.ReadFile(*schemaPath)
	if err != nil {
		return err
	}
	var schemas tfjson.ProviderSchemas
	if err = json.Unmarshal(raw, &schemas); err != nil {
		return fmt.Errorf("%s: %w", *schemaPath, err)
	}
	address, schema := providerSchema(&schemas, pack.Source)
	if schema == nil {
		return fmt.Errorf("%s has no schema for %s", *schemaPath, pack.Source)
	}

	previous, err := rulepack.ReadSnapshot(os.DirFS(*root), pack.Name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	next := &rulepack.Snapshot{Provider: address, Version: *version, Resources: trim(schema, pack.ReferencedTypes())}

	out, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	file := filepath.Join(*root, rulepack.Root, filepath.FromSlash(pack.Name), rulepack.SnapshotFile)
	if err = os.WriteFile(file, append(out, '\n'), 0o600); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "%s: wrote %s from %s %s, %d resource types\n", pack.Name, file, address, *version, len(next.Resources))

	if *proposals == "" {
		return nil
	}
	return os.WriteFile(*proposals, []byte(propose(pack, previous, next)), 0o600)
}

// providerSchema finds the schema of the provider whose address ends in
// source, whatever its registry host.
func providerSchema(schemas *tfjson.ProviderSchemas, source string) (string, *tfjson.ProviderSchema) {
	for address, s := range schemas.Schemas {
		if strings.HasSuffix(strings.ToLower(address), "/"+source) {
			return address, s
		}
	}
	return "", nil
}

// trim keeps every attribute of the referenced types and the tracked
// attributes of every other type.
func trim(schema *tfjson.ProviderSchema, referenced []string) map[string]map[string]any {
	keep := map[string]bool{}
	for _, t := range referenced {
		keep[t] = true
	}
	out := map[string]map[string]any{}
	for t, rs := range schema.ResourceSchemas {
		if rs == nil || rs.Block == nil {
			continue
		}
		attrs := describe(rs.Block, true)
		if !keep[t] {
			for name := range attrs {
				if !rulepack.Tracked.MatchString(name) {
					delete(attrs, name)
				}
			}
		}
		if len(attrs) > 0 {
			out[t] = attrs
		}
	}
	return out
}

// describe records each attribute and nested block of a schema block as a
// kind. With fields, a nested block or object attribute records its own
// fields one level down; below that it is KindObject.
func describe(b *tfjson.SchemaBlock, fields bool) map[string]any {
	out := map[string]any{}
	for name, a := range b.Attributes {
		switch {
		case a.AttributeNestedType != nil && fields:
			nested := map[string]any{}
			for n, na := range a.AttributeNestedType.Attributes {
				nested[n] = kind(na.AttributeType, false)
				if na.AttributeNestedType != nil {
					nested[n] = rulepack.KindObject
				}
			}
			out[name] = nested
		case a.AttributeNestedType != nil:
			out[name] = rulepack.KindObject
		default:
			out[name] = kind(a.AttributeType, fields)
		}
	}
	for name, bt := range b.NestedBlocks {
		if fields && bt.Block != nil {
			out[name] = describe(bt.Block, false)
		} else {
			out[name] = rulepack.KindObject
		}
	}
	return out
}

func kind(t cty.Type, fields bool) any {
	switch {
	case t == cty.Bool:
		return rulepack.KindBool
	case t == cty.Number:
		return rulepack.KindNumber
	case t == cty.String:
		return rulepack.KindString
	case t.IsListType() || t.IsSetType():
		if t.ElementType().IsObjectType() {
			return kind(t.ElementType(), fields)
		}
		return rulepack.KindList
	case t.IsTupleType():
		return rulepack.KindList
	case t.IsMapType():
		return rulepack.KindMap
	case t.IsObjectType() && fields:
		out := map[string]any{}
		for n, at := range t.AttributeTypes() {
			out[n] = kind(at, false)
		}
		return out
	case t.IsObjectType():
		return rulepack.KindObject
	}
	return rulepack.KindDynamic
}

// propose writes a draft rule for each tracked attribute that is new since
// the previous snapshot and that no rule reads yet.
func propose(pack *rulepack.Pack, previous, next *rulepack.Snapshot) string {
	var b strings.Builder
	from := "no previous snapshot"
	if previous != nil {
		from = previous.Version
	}
	fmt.Fprintf(&b, "## %s: %s %s (was %s)\n\n", pack.Name, next.Provider, next.Version, from)
	if previous == nil {
		b.WriteString("First snapshot of this pack: nothing to compare, so no drafts.\n")
		return b.String()
	}

	read := map[string]bool{}
	for _, r := range pack.Rules {
		for _, t := range r.Types {
			read[t+"."+r.Attribute] = true
		}
	}
	drafts := map[string][]string{}
	var undrafted []string
	for _, t := range sortedKeys(next.Resources) {
		for _, name := range sortedKeys(next.Resources[t]) {
			if !rulepack.Tracked.MatchString(name) || read[t+"."+name] {
				continue
			}
			if _, had := previous.Kind(t, name); had {
				continue
			}
			kind, _ := next.Kind(t, name)
			class, yaml := draft(t, name, kind)
			if class == "" {
				undrafted = append(undrafted, fmt.Sprintf("`%s.%s` (%s)", t, name, kind))
				continue
			}
			drafts[class] = append(drafts[class], yaml)
		}
	}
	if len(drafts) == 0 && len(undrafted) == 0 {
		b.WriteString("No new tracked attributes.\n")
		return b.String()
	}
	b.WriteString("Draft rules for tracked attributes that are new since the last snapshot. Each is a starting " +
		"point: check the attribute's meaning in the provider documentation before adding it to a rule file.\n")
	for _, class := range sortedKeys(drafts) {
		fmt.Fprintf(&b, "\n### %s.yaml\n\n```yaml\n%s```\n", class, strings.Join(drafts[class], ""))
	}
	if len(undrafted) > 0 {
		fmt.Fprintf(&b, "\nNew tracked attributes with no draft: %s\n", strings.Join(undrafted, ", "))
	}
	return b.String()
}

// draft maps a tracked attribute to the class and rule its name suggests,
// or to no class when the name and kind suggest nothing reliable.
func draft(resourceType, name, kind string) (string, string) {
	rule := func(predicate, level, extra string) string {
		return fmt.Sprintf("  - types: [%s]\n    attribute: %s\n    predicate: %s\n%s    level: %s\n",
			resourceType, name, predicate, extra, level)
	}
	switch {
	case name == "publicly_accessible" && kind == rulepack.KindBool:
		return "public_exposure", rule("turned_on", "error", "")
	case strings.HasPrefix(name, "deletion_protection") && kind == rulepack.KindBool:
		return "destructive_stateful", rule("turned_off", "warning", "")
	case strings.HasPrefix(name, "retention_") && kind == rulepack.KindNumber:
		return "audit_log_removal", rule("shortened", "warning", "")
	case strings.Contains(name, "logging"):
		switch kind {
		case rulepack.KindBool:
			return "audit_log_removal", rule("turned_off", "error", "")
		case rulepack.KindObject:
			return "audit_log_removal", rule("block_removed", "error", "")
		case rulepack.KindList:
			return "audit_log_removal", rule("narrowed", "error", "")
		}
	case name == "encrypted" || strings.Contains(name, "encryption") || name == "kms_key_id":
		switch kind {
		case rulepack.KindBool:
			return "encryption_disablement", rule("turned_off", "error", "    or_removed: true\n")
		case rulepack.KindObject:
			return "encryption_disablement", rule("block_removed", "error", "")
		case rulepack.KindString:
			return "encryption_disablement", rule("removed", "error", "")
		}
	}
	return "", ""
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
