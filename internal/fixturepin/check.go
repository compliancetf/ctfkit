package fixturepin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// ModuleEntry is one entry of .terraform/modules/modules.json, in the field
// order tofu writes.
type ModuleEntry struct {
	Key     string `json:"Key"`
	Source  string `json:"Source"`
	Version string `json:"Version,omitempty"`
	Dir     string `json:"Dir"`
}

// ModulesFile is .terraform/modules/modules.json.
type ModulesFile struct {
	Modules []ModuleEntry `json:"Modules"`
}

// modulesDir is where tofu installs fetched modules, relative to a case's
// input/ directory.
const modulesDir = ".terraform/modules"

// Check holds the report pack at dir to its PIN.json, offline. It returns
// every violation it finds rather than the first.
func Check(dir string) []error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	pin, raw, err := ReadPin(filepath.Join(dir, PinFile))
	if err != nil {
		return []error{err}
	}
	if canon, encErr := pin.Encode(); encErr != nil || !bytes.Equal(canon, raw) {
		fail("%s is not canonical JSON (sorted keys, no whitespace, no trailing newline, modules in key order)", PinFile)
	}
	if pin.PinFormat != PinFormat {
		fail("pin_format is %d, want %d", pin.PinFormat, PinFormat)
	}
	if !ValidHost(pin.RegistryHost) {
		fail("registry_host %q is not a DNS name", pin.RegistryHost)
	}
	if pin.TofuVersion != "unknown" && !versionRE.MatchString(pin.TofuVersion) {
		fail("tofu_version %q is neither a version nor \"unknown\"", pin.TofuVersion)
	}
	if !dateRE.MatchString(pin.RecordedOn) {
		fail("recorded_on %q is not a UTC date YYYY-MM-DD", pin.RecordedOn)
	}

	onDisk, err := caseDirs(dir)
	if err != nil {
		return append(errs, err)
	}
	for _, name := range onDisk {
		if _, ok := pin.Cases[name]; !ok {
			fail("case %s is on disk but not in %s", name, PinFile)
		}
	}
	names := pinCaseNames(pin)

	versions := map[string]string{} // package address -> version, pack-wide
	for _, name := range names {
		c := pin.Cases[name]
		if !ValidCaseName(name) {
			fail("case name %q is not lower-case letters, digits and hyphens", name)
			continue
		}
		if !slices.Contains(onDisk, name) {
			fail("case %s is in %s but not on disk", name, PinFile)
			continue
		}
		errs = append(errs, checkRole(pin, name, c)...)
		errs = append(errs, checkModules(dir, pin, name, c, versions)...)
	}
	for _, name := range names {
		if c := pin.Cases[name]; c.Role == RoleSynthesized && slices.Contains(onDisk, name) {
			errs = append(errs, checkSynthesized(dir, name, c)...)
		}
	}

	hits, err := Scan(dir, nil)
	if err != nil {
		fail("scan: %v", err)
	}
	for _, h := range hits {
		fail("scan: %s", h)
	}
	return errs
}

func checkRole(pin *Pin, name string, c Case) []error {
	switch c.Role {
	case RoleRecorded:
		if c.BaseCase != "" || c.Transform != "" {
			return []error{fmt.Errorf("%s: a recorded case names no base_case or transform", name)}
		}
	case RoleSynthesized:
		var errs []error
		if base, ok := pin.Cases[c.BaseCase]; !ok || base.Role != RoleRecorded {
			errs = append(errs, fmt.Errorf("%s: base_case %q is not a recorded case", name, c.BaseCase))
		}
		if _, ok := Transforms[c.Transform]; !ok {
			errs = append(errs, fmt.Errorf("%s: transform %q is not known", name, c.Transform))
		}
		return errs
	default:
		return []error{fmt.Errorf("%s: role %q is neither %s nor %s", name, c.Role, RoleRecorded, RoleSynthesized)}
	}
	return nil
}

// checkModules holds one case's modules.json and manifests to its pin entry.
func checkModules(dir string, pin *Pin, name string, c Case, versions map[string]string) []error {
	var errs []error
	fail := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf(name+": "+format, a...))
	}
	input := filepath.Join(dir, name, "input")
	mf, err := ReadModules(filepath.Join(input, modulesDir, "modules.json"))
	if err != nil {
		fail("%v", err)
		return errs
	}

	var got []Module
	for _, e := range mf.Modules {
		if e.Key == "" && e.Source == "" {
			continue // the root module
		}
		if IsLocalSource(e.Source) {
			if _, dirErr := containedDir(input, input, e.Dir); dirErr != nil {
				fail("module %s: %v", e.Key, dirErr)
			}
			continue
		}
		pkg, srcErr := RegistrySource(e.Source, pin.RegistryHost)
		if srcErr != nil {
			fail("module %s: %v", e.Key, srcErr)
			continue
		}
		if prev, seen := versions[pkg]; seen && prev != e.Version {
			fail("module %s: %s is pinned at %s here and %s elsewhere in the pack", e.Key, pkg, e.Version, prev)
		}
		versions[pkg] = e.Version

		abs, dirErr := containedDir(input, filepath.Join(input, modulesDir), e.Dir)
		if dirErr != nil {
			fail("module %s: %v", e.Key, dirErr)
			continue
		}
		manifest, readErr := readRegular(filepath.Join(abs, ManifestName))
		if readErr != nil {
			fail("module %s: manifest: %v", e.Key, readErr)
			continue
		}
		sum := sha256.Sum256(manifest)
		m := Module{Key: e.Key, Source: e.Source, Version: e.Version, ManifestSHA256: hex.EncodeToString(sum[:])}
		m.ManifestSchemaVersion, err = SchemaVersion(manifest)
		if err != nil {
			fail("module %s: manifest: %v", e.Key, err)
		}
		got = append(got, m)
	}

	pinned := map[string]Module{}
	for _, m := range c.Modules {
		pinned[m.Key] = m
	}
	for _, m := range got {
		p, ok := pinned[m.Key]
		switch {
		case !ok:
			fail("module %s is in modules.json but not pinned", m.Key)
		case p.Source != m.Source || p.Version != m.Version:
			fail("module %s is %s %s on disk, pinned %s %s", m.Key, m.Source, m.Version, p.Source, p.Version)
		case p.ManifestSHA256 != m.ManifestSHA256:
			fail("module %s: manifest sha256 is %s, pinned %s", m.Key, m.ManifestSHA256, p.ManifestSHA256)
		case p.ManifestSchemaVersion != m.ManifestSchemaVersion:
			fail("module %s: manifest schema_version is %s, pinned %s", m.Key, m.ManifestSchemaVersion, p.ManifestSchemaVersion)
		}
		delete(pinned, m.Key)
	}
	for key := range pinned {
		fail("module %s is pinned but not a registry module in modules.json", key)
	}
	return errs
}

// checkSynthesized holds a synthesized case's input tree to the transform of
// its base case's, byte for byte, file set included.
func checkSynthesized(dir, name string, c Case) []error {
	tf, ok := Transforms[c.Transform]
	if !ok {
		return nil // reported by checkRole
	}
	base, err := ReadFiles(filepath.Join(dir, c.BaseCase, "input"))
	if err != nil {
		return []error{fmt.Errorf("%s: base %s: %w", name, c.BaseCase, err)}
	}
	want, err := tf(base)
	if err != nil {
		return []error{fmt.Errorf("%s: transform %s: %w", name, c.Transform, err)}
	}
	got, err := ReadFiles(filepath.Join(dir, name, "input"))
	if err != nil {
		return []error{fmt.Errorf("%s: %w", name, err)}
	}
	var errs []error
	for _, p := range sortedKeys(want) {
		switch g, ok := got[p]; {
		case !ok:
			errs = append(errs, fmt.Errorf("%s: input/%s is missing; transform %s of %s produces it", name, p, c.Transform, c.BaseCase))
		case !bytes.Equal(g, want[p]):
			errs = append(errs, fmt.Errorf("%s: input/%s differs from transform %s of %s", name, p, c.Transform, c.BaseCase))
		}
	}
	for _, p := range sortedKeys(got) {
		if _, ok := want[p]; !ok {
			errs = append(errs, fmt.Errorf("%s: input/%s is not produced by transform %s of %s", name, p, c.Transform, c.BaseCase))
		}
	}
	return errs
}

// ReadModules strictly decodes a modules.json.
func ReadModules(file string) (*ModulesFile, error) {
	raw, err := os.ReadFile(file) //nolint:gosec // a path under the tree being checked or recorded
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var mf ModulesFile
	if err = dec.Decode(&mf); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &mf, nil
}

// SchemaVersion is a manifest's schema_version.
func SchemaVersion(manifest []byte) (string, error) {
	var m struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return "", err
	}
	if m.SchemaVersion == "" {
		return "", errors.New("no schema_version")
	}
	return m.SchemaVersion, nil
}

// containedDir resolves a modules.json Dir, which must be a clean relative
// path, against base, and requires its real path to lie inside within. It
// returns the resolved absolute path.
func containedDir(base, within, dir string) (string, error) {
	if dir == "" || filepath.IsAbs(dir) || strings.Contains(dir, `\`) || path.Clean(dir) != dir {
		return "", fmt.Errorf("modules.json Dir %q is not a clean relative path", dir)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(base, filepath.FromSlash(dir)))
	if err != nil {
		return "", fmt.Errorf("modules.json Dir %q: %w", dir, err)
	}
	root, err := filepath.EvalSymlinks(within)
	if err != nil {
		return "", err
	}
	if rel, relErr := filepath.Rel(root, resolved); relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("modules.json Dir %q resolves outside %s", dir, within)
	}
	return resolved, nil
}

// ReadFiles reads every regular file under root into a Files map. A symlink
// is an error.
func ReadFiles(root string) (Files, error) {
	out := Files{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", p)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		raw, readErr := os.ReadFile(p) //nolint:gosec // walking a fixture tree
		if readErr != nil {
			return readErr
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = raw
		return nil
	})
	return out, err
}

// WriteFiles writes files under root, creating directories.
func WriteFiles(root string, files Files) error {
	for _, p := range sortedKeys(files) {
		dst := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // a committed fixture tree
			return err
		}
		if err := os.WriteFile(dst, files[p], 0o644); err != nil { //nolint:gosec // a committed fixture, read by everyone
			return err
		}
	}
	return nil
}

func caseDirs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func sortedKeys(f Files) []string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
