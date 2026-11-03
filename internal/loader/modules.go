package loader

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// modulesJSONPath is where Terraform and OpenTofu record the installed module
// instances, relative to the root module.
const modulesJSONPath = ".terraform/modules/modules.json"

// manifestFileName is the compliance manifest a served build installs in its
// own directory.
const manifestFileName = "compliancetf-manifest.json"

// manifestSchemaMajor is the only manifest schema major this build reads. A
// minor bump is additive by contract and needs no change here; another major
// is an environment error.
const manifestSchemaMajor = "3"

// testKeyPrefix is the first segment of the key init gives a module a test
// run block installs. Such an instance is test scaffolding, not configuration
// under analysis, so it never reaches the inventory or a finding; isTestHarness
// tells it from a root module call that happens to be named test.
const testKeyPrefix = "test."

// modulesFile is the decode shape of modules.json. Terraform writes the field
// names in this case, and an entry it adds that this build does not know
// about is ignored rather than fatal.
type modulesFile struct {
	Modules []moduleRecord `json:"Modules"`
}

// moduleRecord is one entry of modules.json.
type moduleRecord struct {
	// Key is the module call key, empty for the root module itself.
	Key string `json:"Key"`
	// Source is the source string as written in the configuration.
	Source string `json:"Source"`
	// Dir is the install directory, relative to the root module.
	Dir string `json:"Dir"`
}

// LoadModules reads .terraform/modules/modules.json under root and the
// manifest of every instance it lists.
//
// The inventory is what a post_init analyzer sees, so it is the whole of what
// the configuration installed: the root module entry is dropped because it is
// not a module call, and a key under the test. prefix is dropped because a
// test harness module is scaffolding rather than configuration. Every other
// entry is kept whether or not it has a manifest, because an instance with no
// manifest is a finding the analyzer makes and not an error here.
//
// A manifest is read only from the instance directory that modules.json
// names. There is no override flag, which is what stops a hand-written
// manifest from becoming evidence. The bytes read are digested as they are,
// so the digest in a receipt is over the file on disk rather than over a
// re-serialization of the parsed value.
func LoadModules(root string) (*ctfkit.ModuleInventory, error) {
	// The root is resolved once, for the same reason LoadConfig resolves it:
	// a temporary directory is itself reached through a symlink on some
	// systems, so containment is judged against where the root really is.
	realRoot, err := resolve(root)
	if err != nil {
		return nil, cannotReadDir(root, err)
	}

	path := filepath.Join(root, filepath.FromSlash(modulesJSONPath))
	if _, statErr := os.Lstat(path); errors.Is(statErr, fs.ErrNotExist) {
		// path is the caller's root joined to a fixed name: no repository text.
		where := root
		if filepath.Clean(root) == "." {
			where = "the working directory"
		}
		return nil, fmt.Errorf("%w: no module cache at %s; run terraform init (or tofu init) in %s, then run the same ctfkit report again", ErrInput, path, where)
	}
	content, err := readContained(realRoot, path)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrInput, shown(path), err)
	}

	var file modulesFile
	if decodeErr := json.Unmarshal(content, &file); decodeErr != nil {
		// The decoder quotes the input it choked on, and that input is
		// written by the repository under analysis, so the reason is reported
		// without it. path is printed as it is: it is the caller's root, from
		// --path or the working directory, joined to a fixed name, so it holds
		// no repository text; shown would mangle a CI workspace named job@2.
		return nil, fmt.Errorf("%w: %s is not a valid modules.json file", ErrInput, path)
	}

	// Every record's directory by key, the root's included, so a local
	// source can be resolved against the directory of the module that calls
	// it the way init resolved it.
	dirs := make(map[string]string, len(file.Modules))
	for _, record := range file.Modules {
		dirs[record.Key] = filepath.ToSlash(record.Dir)
		// init records the root module at ".". A root record
		// anywhere else would make every top-level "./" call a join from that
		// place, so a crafted ../outside root reads ../outside/sub as if the
		// configuration had named it. No path is printed: the record is the
		// repository's text.
		if record.Key == "" {
			if anchored, anchorErr := resolve(absDir(root, record.Dir)); anchorErr != nil || anchored != realRoot {
				return nil, fmt.Errorf("%w: modules.json records the root module at a directory other than the configuration directory", ErrInput)
			}
		}
	}

	targets, err := explicitTargets(root, realRoot, file.Modules, dirs)
	if err != nil {
		return nil, err
	}
	instances := make([]ctfkit.ModuleInstance, 0, len(file.Modules))
	for _, record := range file.Modules {
		if record.Key == "" || isTestHarness(record.Key, dirs) {
			continue
		}

		instance, loadErr := loadInstance(root, realRoot, record, targets)
		if loadErr != nil {
			return nil, loadErr
		}
		instances = append(instances, instance)
	}

	// The order is the order modules.json lists, which Terraform writes
	// sorted by key. Preserving it keeps the inventory a faithful reading of
	// the file; a renderer that wants another order sorts a copy.
	return &ctfkit.ModuleInventory{Root: root, Instances: instances}, nil
}

// loadInstance turns one modules.json entry into an inventory instance,
// reading the manifest beside it when there is one.
func loadInstance(root, realRoot string, record moduleRecord, targets map[string]bool) (ctfkit.ModuleInstance, error) {
	instance := ctfkit.ModuleInstance{
		Key:    record.Key,
		Source: record.Source,
		Dir:    filepath.ToSlash(record.Dir),
		// Provenance describes how far this instance has been verified, and
		// the answer is the same whether or not a manifest was found: it was
		// read from the local module directory and no party attested to it.
		// Open source ctfkit never emits another value.
		Provenance: ctfkit.ProvenanceLocalUnverified,
	}

	// The directory is resolved first and judged by where it really is: inside
	// the root, or the directory of an explicit local source outside it. Any
	// other place is a symlink that leads out of the root or a record init did
	// not write, and a directory that does not resolve was never installed;
	// neither is one ctfkit can vouch for. A directory is named after its
	// source, so diagnostics print it through shown.
	full := absDir(root, record.Dir)
	resolved, err := resolve(full)
	if err != nil {
		return ctfkit.ModuleInstance{}, fmt.Errorf("%w: module directory %s of %s does not resolve",
			ErrInput, shown(record.Dir), shown(record.Key))
	}
	if !within(realRoot, resolved) && !targets[resolved] {
		return ctfkit.ModuleInstance{}, fmt.Errorf("%w: module directory %s of %s leaves the configuration directory",
			ErrInput, shown(record.Dir), shown(record.Key))
	}

	// A directory that exists and cannot be listed is an error in
	// readDirFiles: init installed it, so terraform reads it. A file in it,
	// the manifest included, is read when it resolves inside the root or
	// inside this module's own directory; a file symlink that resolves
	// anywhere else is an error, since terraform would read it.
	bases := []string{realRoot, resolved}
	files, err := readDirFiles(full, instance.Dir, bases)
	if err != nil {
		return ctfkit.ModuleInstance{}, err
	}
	instance.Files = files

	path := filepath.Join(full, manifestFileName)

	// Absence is decided by Lstat, which does not follow the link, so an
	// instance that simply has no manifest is the nil case while a broken
	// link where one should be is an error rather than a silent nil.
	if _, statErr := os.Lstat(path); errors.Is(statErr, fs.ErrNotExist) {
		// Only a manifest-less instance is judged: a served one is evidence
		// whatever its directory declares.
		instance.DeclaresNoResources = declaresNoResources(files)

		return instance, nil
	}

	content, err := readWithin(bases, path)
	if err != nil {
		return ctfkit.ModuleInstance{}, fmt.Errorf("%w: reading %s: %w",
			ErrInput, shown(pathpkg.Join(instance.Dir, manifestFileName)), err)
	}

	// The digest is taken before the parse, over the exact bytes read, so it
	// records the file that was on disk and not what decoding made of it.
	sum := sha256.Sum256(content)

	var manifest ctfkit.Manifest
	if decodeErr := json.Unmarshal(content, &manifest); decodeErr != nil {
		// As with modules.json, the decoder's own message quotes input text.
		return ctfkit.ModuleInstance{}, fmt.Errorf("%w: %s is not a valid compliance manifest",
			ErrInput, shown(pathpkg.Join(instance.Dir, manifestFileName)))
	}

	if gateErr := checkSchemaMajor(root, path, manifest.SchemaVersion); gateErr != nil {
		return ctfkit.ModuleInstance{}, gateErr
	}

	instance.Manifest = &manifest
	instance.ManifestSHA256 = hex.EncodeToString(sum[:])

	return instance, nil
}

// checkSchemaMajor gates a manifest on its schema version major. It names the
// manifest by its path relative to root, because that is the path the reader
// of a diagnostic can act on, and it names the version the file declared.
//
// The version string is the producer's, and it belongs in the diagnostic: the
// reader cannot fix a version mismatch without being told which version was
// found. It is still text from a file a downloaded module ships, so it is
// printed through ctfkit.RedactSource like any other text of the repository's:
// "4.0" stays "4.0", while userinfo is dropped and a version holding a control
// character, whitespace or an encoded "@" prints as the placeholder.
func checkSchemaMajor(root, path, version string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	name := shown(rel)

	if version == "" {
		return fmt.Errorf("%w: %s declares no schema_version; this release supports manifest schema major %s",
			ErrInput, name, manifestSchemaMajor)
	}
	if major, _, _ := strings.Cut(version, "."); major != manifestSchemaMajor {
		return fmt.Errorf("%w: %s declares schema_version %s; this release supports manifest schema major %s",
			ErrInput, name, ctfkit.RedactSource(version), manifestSchemaMajor)
	}

	return nil
}

// isTestHarness reports whether a modules.json key names a module a test run
// block installed. Terraform and OpenTofu key such a module
// test.<test file directories>.<test file name without .tftest.hcl>.<run name>
// (buildTestModules: internal/terraform/config_graph_build.go in Terraform
// v1.17.0, internal/configs/config_build.go in OpenTofu v1.13.1) and write no
// record for any shorter prefix of it, while every module the configuration
// calls has a record for each of its ancestors. A root module call named test
// therefore keeps test, test.hook and every deeper key: each prefix is
// recorded. A key that starts with test. and lacks a record for some prefix is
// a test run module or a module one calls.
//
// Only that exact shape is skipped: the run module's key has at least three
// segments (test, the file name, the run name), every prefix from two segments
// up to it is unrecorded, and every prefix from it on is recorded. The bare
// "test" prefix is left out of the check: a root module call named test
// records it (testdata/loader/tofu-local-layout holds both), and a key under
// that call has its two-segment prefix recorded, so it never takes this shape.
// Any other test. key, such as a two-segment test.x or one with a gap in its
// recorded prefixes, is not a shape init writes for a run block, so it is read
// and inspected like configuration.
func isTestHarness(key string, dirs map[string]string) bool {
	if !strings.HasPrefix(key, testKeyPrefix) {
		return false
	}
	segments := strings.Split(key, ".")
	recorded := func(n int) bool {
		_, ok := dirs[strings.Join(segments[:n], ".")]
		return ok
	}
	// run is the segment count of the run module: the shortest recorded
	// prefix of two or more segments, the key itself when there is none.
	run := len(segments)
	for n := 2; n < len(segments); n++ {
		if recorded(n) {
			run = n
			break
		}
	}
	if run < 3 {
		return false
	}
	for n := run; n < len(segments); n++ {
		if !recorded(n) {
			return false
		}
	}
	return true
}

// explicitTargets resolves the directory of every "./" or "../" local module
// source that leads out of the root by path: what a configuration names
// explicitly, terraform reads, and ctfkit therefore reads too.
//
// Terraform and OpenTofu record a local module's directory as
// filepath.Join(parent.Dir, source) with its symlinks resolved
// (installLocalModule, internal/initwd/module_install.go in both), so a
// "../shared" call from the root is Dir "../shared" and a ./sub call inside it
// is "../shared/sub". The set returned holds each such directory resolved. A
// source whose directory does not resolve, or whose record names another
// place, is an input error.
//
// modules.json alone authorizes nothing outside the root: it
// is written in the CI job, and a repository can ship a crafted one. A join
// that leads out counts only when a module block of the calling module, its
// own files read from its validated directory, declares the call by name with
// that source. A record no such block declares is an input error rather than
// an instance read from inside the root only: init writes a record for a call
// it found in the configuration and for nothing else, so the record was not
// written by init over this configuration, and the existing refusal of a
// record whose directory its source does not name is the same judgment.
//
// The caller's directory has to be validated first, so records are taken
// shallowest first: the root, which LoadModules has anchored at the root
// directory itself, then each depth in turn. A parent whose directory lies
// outside the root and is no explicit target authorizes nothing; its own
// instance is refused when it is loaded. A record whose parent is not in
// modules.json cannot be joined and contributes nothing, so its directory is
// read only if it lies inside the root.
func explicitTargets(root, realRoot string, records []moduleRecord, dirs map[string]string) (map[string]bool, error) {
	targets := map[string]bool{}
	// The files of each calling module by key, read the first time one of
	// its calls leads out of the root.
	callers := map[string][]ctfkit.ConfigFile{}
	ordered := slices.Clone(records)
	slices.SortStableFunc(ordered, func(a, b moduleRecord) int {
		return cmp.Compare(strings.Count(a.Key, "."), strings.Count(b.Key, "."))
	})
	for _, record := range ordered {
		if record.Key == "" || isTestHarness(record.Key, dirs) || !isLocalSource(record.Source) {
			continue
		}
		parent, name := "", record.Key
		if i := strings.LastIndexByte(record.Key, '.'); i >= 0 {
			parent, name = record.Key[:i], record.Key[i+1:]
		}
		parentResolved, parentDir := realRoot, "."
		if parent != "" {
			var ok bool
			if parentDir, ok = dirs[parent]; !ok {
				continue
			}
			// The source is joined to the parent's resolved directory, as init
			// joins it, so a ../alias that resolves to ../libs/pkg calling
			// ../hook names ../libs/hook.
			var err error
			if parentResolved, err = resolve(absDir(root, parentDir)); err != nil {
				return nil, fmt.Errorf("%w: module directory %s does not resolve", ErrInput, shown(parentDir))
			}
			if !within(realRoot, parentResolved) && !targets[parentResolved] {
				continue
			}
		}
		// The join counts as explicit when it leads out of the root before any
		// symlink of its own is followed.
		joined := filepath.Join(parentResolved, filepath.FromSlash(localPath(record.Source)))
		if within(realRoot, joined) {
			continue
		}
		files, read := callers[parent]
		if !read {
			var err error
			if files, err = readDirFiles(parentResolved, parentDir, []string{realRoot, parentResolved}); err != nil {
				return nil, err
			}
			callers[parent] = files
		}
		if !declares(files, name, record.Source) {
			return nil, fmt.Errorf("%w: modules.json records %s at a local source outside the configuration directory that no module block of its caller declares",
				ErrInput, shown(record.Key))
		}
		resolved, err := resolve(joined)
		if err != nil {
			return nil, fmt.Errorf("%w: local module %s (source %s) does not resolve",
				ErrInput, shown(record.Key), shown(record.Source))
		}
		recorded, err := resolve(absDir(root, record.Dir))
		if err != nil || recorded != resolved {
			return nil, fmt.Errorf("%w: modules.json records %s at a directory its source does not name",
				ErrInput, shown(record.Key))
		}
		targets[resolved] = true
	}
	return targets, nil
}

// declares reports whether a module block in files is the call name with the
// local source source. Both sides are compared in the form init records:
// Terraform and OpenTofu clean a local source before writing it
// (parseModuleSourceLocal, internal/addrs/module_source.go: backslashes to
// slashes, path.Clean, a "./" kept in front of anything that is not "../"),
// so "./a//b/" in a block is "./a/b" in modules.json. A file that does not
// parse contributes the blocks that did; init refuses it in any case.
func declares(files []ctfkit.ConfigFile, name, source string) bool {
	want := cleanLocal(source)
	for _, file := range files {
		for _, m := range parser.ParseConfigContent(file.Bytes, file.Path).Modules {
			if m.Name == name && isLocalSource(m.Source) && cleanLocal(m.Source) == want {
				return true
			}
		}
	}
	return false
}

// cleanLocal is a "./" or "../" source as init records it.
func cleanLocal(source string) string {
	clean := pathpkg.Clean(localPath(source))
	if !strings.HasPrefix(clean, "../") {
		clean = "./" + clean
	}
	return clean
}

// declaresNoResources reports whether the files of one instance directory
// were all parsed and hold no resource block.
//
// Anything the loader cannot judge answers false, which keeps the instance in
// the manifest_missing findings: a directory with no configuration file and a
// file that does not parse, in either syntax. This is a reading
// for the analyzer and never an error: whether the module is valid is
// terraform's answer to give.
func declaresNoResources(files []ctfkit.ConfigFile) bool {
	for _, file := range files {
		parsed := parser.ParseConfigContent(file.Bytes, file.Path)
		if len(parsed.Errors) > 0 || len(parsed.Resources) > 0 {
			return false
		}
	}

	return len(files) > 0
}
