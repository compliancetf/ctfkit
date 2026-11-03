package fixturepin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// moduleSchema is the one thing ValidateConfig reads from a configuration
// file: module blocks and their source argument.
var moduleSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "module", LabelNames: []string{"name"}}}}

var sourceSchema = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "source", Required: true}}}

// ValidateConfig runs before tofu init: every module block in every .tf or .tofu file
// under caseDir must name a literal source that is either a local path whose
// real path stays inside caseDir, or a registry address on host. Anything
// else would make init fetch from a place the pin does not cover.
func ValidateConfig(caseDir, host string) error {
	root, err := filepath.EvalSymlinks(caseDir)
	if err != nil {
		return err
	}
	parser := hclparse.NewParser()
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", p)
		}
		if d.IsDir() && d.Name() == ".terraform" {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		// OpenTofu loads .tf and .tofu files, and their .json forms. The
		// recorder reads the native syntax only, so a JSON configuration file
		// is refused rather than passed to init unread.
		if strings.HasSuffix(p, ".tf.json") || strings.HasSuffix(p, ".tofu.json") {
			return fmt.Errorf("%s: JSON configuration (.tf.json, .tofu.json) is not supported by the recorder", p)
		}
		if !strings.HasSuffix(p, ".tf") && !strings.HasSuffix(p, ".tofu") {
			return nil
		}
		file, diags := parser.ParseHCLFile(p)
		if diags.HasErrors() {
			return fmt.Errorf("%s: %s", p, diags.Error())
		}
		content, _, diags := file.Body.PartialContent(moduleSchema)
		if diags.HasErrors() {
			return fmt.Errorf("%s: %s", p, diags.Error())
		}
		for _, block := range content.Blocks {
			attrs, _, attrDiags := block.Body.PartialContent(sourceSchema)
			if attrDiags.HasErrors() {
				return fmt.Errorf("%s: module %s: %s", p, block.Labels[0], attrDiags.Error())
			}
			val, valDiags := attrs.Attributes["source"].Expr.Value(nil)
			if valDiags.HasErrors() || !val.Type().Equals(cty.String) || !val.IsKnown() || val.IsNull() {
				return fmt.Errorf("%s: module %s: source is not a literal string", p, block.Labels[0])
			}
			if srcErr := validSource(root, filepath.Dir(p), val.AsString(), host); srcErr != nil {
				return fmt.Errorf("%s: module %s: %w", p, block.Labels[0], srcErr)
			}
		}
		return nil
	})
}

func validSource(root, from, source, host string) error {
	if !IsLocalSource(source) {
		_, err := RegistrySource(source, host)
		return err
	}
	target, err := filepath.EvalSymlinks(filepath.Join(from, filepath.FromSlash(source)))
	if err != nil {
		return fmt.Errorf("local source %q: %w", source, err)
	}
	if !within(root, target) {
		return fmt.Errorf("local source %q resolves outside the case directory", source)
	}
	return nil
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Assemble runs after tofu init. It validates every modules.json entry tofu
// wrote under dataDir (TF_DATA_DIR) for the configuration in caseDir, then
// writes into dest (a fresh case's input/ directory) the modules.json with
// every Dir relative to input/, and each manifest byte for byte. Nothing else
// tofu fetched is copied.
func Assemble(caseDir, dataDir, dest, host string) error {
	caseRoot, err := filepath.EvalSymlinks(caseDir)
	if err != nil {
		return err
	}
	modRoot, err := filepath.EvalSymlinks(filepath.Join(dataDir, "modules"))
	if err != nil {
		return err
	}
	mf, err := ReadModules(filepath.Join(modRoot, "modules.json"))
	if err != nil {
		return err
	}

	out := ModulesFile{Modules: make([]ModuleEntry, 0, len(mf.Modules))}
	manifests := Files{}
	for _, e := range mf.Modules {
		if e.Key == "" && e.Source == "" {
			out.Modules = append(out.Modules, e)
			continue
		}
		dir := filepath.FromSlash(e.Dir)
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(caseRoot, dir)
		}
		resolved, dirErr := filepath.EvalSymlinks(dir)
		if dirErr != nil {
			return fmt.Errorf("module %s: Dir %q: %w", e.Key, e.Dir, dirErr)
		}

		var rel string
		switch {
		case IsLocalSource(e.Source) && within(caseRoot, resolved):
			rel, _ = filepath.Rel(caseRoot, resolved)
		case IsLocalSource(e.Source) && within(modRoot, resolved):
			// a registry module's own local submodule
			r, _ := filepath.Rel(modRoot, resolved)
			rel = filepath.Join(modulesDir, r)
		case IsLocalSource(e.Source):
			return fmt.Errorf("module %s: local source %q resolves outside the case directory", e.Key, e.Source)
		default:
			if _, srcErr := RegistrySource(e.Source, host); srcErr != nil {
				return fmt.Errorf("module %s: %w", e.Key, srcErr)
			}
			if !within(modRoot, resolved) {
				return fmt.Errorf("module %s: Dir %q resolves outside the module cache", e.Key, e.Dir)
			}
			r, _ := filepath.Rel(modRoot, resolved)
			rel = filepath.Join(modulesDir, r)
		}
		e.Dir = filepath.ToSlash(rel)
		out.Modules = append(out.Modules, e)

		manifest, readErr := readRegular(filepath.Join(resolved, ManifestName))
		switch {
		case readErr == nil:
			manifests[e.Dir+"/"+ManifestName] = manifest
		case !os.IsNotExist(readErr):
			return fmt.Errorf("module %s: %w", e.Key, readErr)
		}
	}

	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	manifests[modulesDir+"/modules.json"] = raw
	return WriteFiles(dest, manifests)
}

// Synthesize writes every synthesized case of pin under reportDir from its
// base case's input tree, which must already be in reportDir.
func Synthesize(reportDir string, pin *Pin) error {
	for _, name := range pinCaseNames(pin) {
		c := pin.Cases[name]
		if c.Role != RoleSynthesized {
			continue
		}
		tf, ok := Transforms[c.Transform]
		if !ok {
			return fmt.Errorf("%s: transform %q is not known", name, c.Transform)
		}
		base, err := ReadFiles(filepath.Join(reportDir, c.BaseCase, "input"))
		if err != nil {
			return fmt.Errorf("%s: base %s: %w", name, c.BaseCase, err)
		}
		files, err := tf(base)
		if err != nil {
			return fmt.Errorf("%s: transform %s: %w", name, c.Transform, err)
		}
		if err = WriteFiles(filepath.Join(reportDir, name, "input"), files); err != nil {
			return err
		}
	}
	return nil
}

// BuildPin computes the pin of the pack at reportDir, taking every case's role,
// base case and transform from prev.
func BuildPin(reportDir string, prev *Pin, host, tofuVersion, recordedOn string) (*Pin, error) {
	pin := &Pin{Cases: map[string]Case{}, PinFormat: PinFormat, RecordedOn: recordedOn, RegistryHost: host, TofuVersion: tofuVersion}
	for _, name := range pinCaseNames(prev) {
		c := prev.Cases[name]
		c.Modules = []Module{}
		input := filepath.Join(reportDir, name, "input")
		mf, err := ReadModules(filepath.Join(input, modulesDir, "modules.json"))
		if err != nil {
			return nil, err
		}
		for _, e := range mf.Modules {
			if (e.Key == "" && e.Source == "") || IsLocalSource(e.Source) {
				continue
			}
			manifest, readErr := readRegular(filepath.Join(input, filepath.FromSlash(e.Dir), ManifestName))
			if readErr != nil {
				return nil, fmt.Errorf("%s: module %s: %w", name, e.Key, readErr)
			}
			schema, schemaErr := SchemaVersion(manifest)
			if schemaErr != nil {
				return nil, fmt.Errorf("%s: module %s: %w", name, e.Key, schemaErr)
			}
			sum := sha256.Sum256(manifest)
			c.Modules = append(c.Modules, Module{
				Key: e.Key, Source: e.Source, Version: e.Version,
				ManifestSchemaVersion: schema, ManifestSHA256: hex.EncodeToString(sum[:]),
			})
		}
		pin.Cases[name] = c
	}
	return pin, nil
}

// Drift is the difference between a live pack and a freshly recorded one:
// every added, removed or changed file, with PIN.json compared after its
// recorded_on is set equal.
func Drift(live, fresh string) ([]string, error) {
	a, err := ReadFiles(live)
	if err != nil {
		return nil, err
	}
	b, err := ReadFiles(fresh)
	if err != nil {
		return nil, err
	}
	for _, f := range []Files{a, b} {
		if raw, ok := f[PinFile]; ok {
			f[PinFile] = normalizeRecordedOn(raw)
		}
	}
	var out []string
	for _, p := range sortedKeys(a) {
		switch g, ok := b[p]; {
		case !ok:
			out = append(out, "removed: "+p)
		case !bytes.Equal(g, a[p]):
			out = append(out, "changed: "+p)
		}
	}
	for _, p := range sortedKeys(b) {
		if _, ok := a[p]; !ok {
			out = append(out, "added:   "+p)
		}
	}
	return out, nil
}

func normalizeRecordedOn(raw []byte) []byte {
	var p Pin
	if err := json.Unmarshal(raw, &p); err != nil {
		return raw // an unreadable pin is drift in its own right
	}
	p.RecordedOn = ""
	b, err := p.Encode()
	if err != nil {
		return raw
	}
	return b
}

func pinCaseNames(p *Pin) []string {
	names := make([]string, 0, len(p.Cases))
	for n := range p.Cases {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// readRegular reads a file that must be a regular file itself: a symlink,
// even one pointing inside the tree, is refused, so the bytes read are the
// bytes at that path and no other. A missing file is an os.IsNotExist error.
func readRegular(p string) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (%s)", p, info.Mode().Type())
	}
	return os.ReadFile(p) //nolint:gosec // the caller contained the directory
}
