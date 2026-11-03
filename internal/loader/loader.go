// Package loader turns the files of a repository under analysis into the
// inputs an analyzer reads. It is pure I/O: it reads, it parses, it orders,
// and it returns; it never evaluates a configuration, never decides anything
// about compliance, and never runs terraform or tofu.
//
// Everything that can go wrong here is an environment error, never a finding:
// a missing directory, a plan file that is not a plan, a lock file that does
// not parse. Each one wraps ErrInput so the command layer can map it to exit 2
// with the input diagnostic category.
package loader

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// ErrInput marks every error this package returns. The command layer tests for
// it with errors.Is and exits 2 with the input diagnostic category.
var ErrInput = errors.New("input error")

// ReadReason is the reason a path could not be read, without the path the OS
// error repeats, so a diagnostic names the path once and as the user gave it.
// It still matches fs.ErrNotExist and fs.ErrPermission.
func ReadReason(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// ReadStep is the next step for a path that could not be read, chosen by the
// error class and never by its text, which differs between platforms:
// notFound (default "check the path") when it does not exist, a permission
// check when it cannot be read, else "check the path".
func ReadStep(err error, notFound string) string {
	switch {
	case errors.Is(err, fs.ErrNotExist) && notFound != "":
		return notFound
	case errors.Is(err, fs.ErrPermission):
		return "check that this user can read it"
	}
	return "check the path"
}

// cannotReadDir is the error of a configuration directory that cannot be
// read. root is the caller's argument, not repository text, so it is printed
// as given.
func cannotReadDir(root string, err error) error {
	return fmt.Errorf("%w: cannot read configuration directory %s: %w; %s", ErrInput, root, ReadReason(err), ReadStep(err, ""))
}

// configSuffixes are the file names a configuration directory contributes.
// The order is longest-match irrelevant: a name matches at most one of them.
var configSuffixes = []string{".tf", ".tf.json", ".tofu", ".tofu.json"}

// skippedDirs are directories that live inside a configuration directory but
// are not part of the configuration: Terraform's own working directory and the
// plugin cache.
var skippedDirs = map[string]bool{
	".terraform":   true,
	".terraform.d": true,
}

// lockFileName is the dependency lock file of a root module.
const lockFileName = ".terraform.lock.hcl"

// planFormatMajor is the only plan JSON format major this build accepts.
const planFormatMajor = "1"

// LoadConfig reads the configuration files under root into a ConfigArchive.
//
// Files are returned in ascending order of their POSIX relative path and hold
// the exact bytes on disk: nothing here evaluates HCL, because an analyzer
// that needs structure parses the bytes itself. The lock file of the root
// module is parsed when it is present and left nil when it is not, which is
// itself reportable rather than an error.
func LoadConfig(root string) (*ctfkit.ConfigArchive, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, cannotReadDir(root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: configuration path %s is not a directory", ErrInput, root)
	}

	// The root is resolved once so that a symlink inside it can be compared
	// against where the root really is. A temporary directory is itself
	// reached through a symlink on some systems, so comparing against the
	// unresolved root would call every file an escape.
	realRoot, err := resolve(root)
	if err != nil {
		return nil, cannotReadDir(root, err)
	}

	// The walk starts at the resolved root: WalkDir does not follow a
	// symlink, so a root given as a link to the configuration directory
	// would otherwise yield no file at all. Paths stay relative to it.
	files, err := readConfigFiles(realRoot, realRoot)
	if err != nil {
		return nil, err
	}

	lock, err := readLockfile(realRoot, filepath.Join(root, lockFileName))
	if err != nil {
		return nil, err
	}

	return &ctfkit.ConfigArchive{Root: root, Files: files, Lockfile: lock}, nil
}

// readConfigFiles walks root and returns every configuration file it holds, in
// path order. realRoot is root with its own symlinks resolved, and it is what
// a symlink found during the walk is contained against.
func readConfigFiles(root, realRoot string) ([]ctfkit.ConfigFile, error) {
	var files []ctfkit.ConfigFile

	// Every error a walk step returns names the entry through shown and none
	// of the OS error, which carries the absolute path: a module directory
	// in the tree is named after its source.
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = "."
			}
			return fmt.Errorf("%s %w", shown(rel), errUnreadable)
		}
		if entry.IsDir() {
			if path != root && skippedDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !isConfigFile(entry.Name()) {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := readContained(realRoot, path)
		if err != nil {
			return fmt.Errorf("%s %w", shown(rel), err)
		}

		files = append(files, ctfkit.ConfigFile{Path: filepath.ToSlash(rel), Bytes: content})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("%w: reading configuration under %s: %w", ErrInput, root, walkErr)
	}

	// A walk visits a directory before a sibling file whose name sorts after
	// it, so the walk order is not path order. The archive contract is path
	// order, which is what makes a receipt over it reproducible.
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	return files, nil
}

// readContained reads path after resolving it and verifying that it is still
// inside realRoot.
//
// Every byte this package takes from the repository under analysis comes
// through here, because the repository is untrusted input: a walk does not
// descend into a symlinked directory, but it does hand back a symlinked file,
// and reading one follows it wherever it points. A link that leaves the root
// would pull bytes from outside the repository into the archive under an
// in-root name, so it is refused loudly; a link that stays inside the root is
// ordinary content.
//
// The read is of the resolved target rather than of path, so the symlink is
// followed once, at the moment it is checked, and not a second time by the
// open that follows.
//
// Its errors name no path: the OS error of a failed resolve or read carries
// the resolved path, which for a module directory is named after its source.
// The caller names the file, through shown.
func readContained(realRoot, path string) ([]byte, error) {
	target, err := resolve(path)
	if err != nil {
		return nil, errUnresolved
	}

	if !within(realRoot, target) {
		return nil, errEscapes
	}

	// ponytail: no size ceiling on the read, so a deliberately huge file in
	// the repository under analysis is read whole. A cap is a policy number
	// this specification does not set, and a real estate's plan.json is
	// legitimately large, so the limit belongs to the command layer that
	// knows the run's budget rather than here.
	//
	// #nosec G304 -- target is the resolved path, already verified to be
	// inside the operator-chosen root
	content, err := os.ReadFile(target)
	if err != nil {
		return nil, errUnreadable
	}
	return content, nil
}

// within reports whether target is base or lies below it, comparing the two
// cleaned paths component by component, so "/repo-other" is never inside
// "/repo" the way a string prefix would have it. Both are resolved paths;
// resolving is the caller's job, and one that cannot resolve never asks. A
// relative path, as EvalSymlinks returns for a relative input, is made
// absolute against the working directory first.
func within(base, target string) bool {
	var err error
	if base, err = filepath.Abs(base); err != nil {
		return false
	}
	if target, err = filepath.Abs(target); err != nil {
		return false
	}
	if filepath.VolumeName(base) != filepath.VolumeName(target) {
		return false
	}
	sep := string(filepath.Separator)
	b := strings.Split(strings.TrimSuffix(base, sep), sep)
	t := strings.Split(strings.TrimSuffix(target, sep), sep)
	if len(t) < len(b) {
		return false
	}
	for i := range b {
		if b[i] != t[i] {
			return false
		}
	}
	return true
}

// isConfigFile reports whether name is a Terraform or OpenTofu configuration
// file. A file whose whole name is a suffix, such as ".tf", is a dotfile and
// not a configuration file.
func isConfigFile(name string) bool {
	for _, suffix := range configSuffixes {
		if len(name) > len(suffix) && strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// lockFile and lockProvider are the decode shapes of .terraform.lock.hcl.
// Unknown attributes inside a provider block are not tolerated by gohcl, which
// is the behavior we want: an attribute Terraform writes and this build does
// not know about is worth failing on rather than silently dropping.
type lockFile struct {
	Providers []lockProvider `hcl:"provider,block"`
}

type lockProvider struct {
	Source      string   `hcl:"source,label"`
	Version     string   `hcl:"version"`
	Constraints string   `hcl:"constraints,optional"`
	Hashes      []string `hcl:"hashes,optional"`
}

// LoadLockfiles parses the dependency lock file of each directory dirs names,
// archive-relative to root as tfroots.Root.Dir is, and returns them by that
// directory. A directory with no lock file has no key; a lock file that does
// not parse, or that holds an attribute this build does not know, is an
// input error, never an empty lock.
func LoadLockfiles(root string, dirs []string) (map[string]*ctfkit.Lockfile, error) {
	realRoot, err := resolve(root)
	if err != nil {
		return nil, cannotReadDir(root, err)
	}
	locks := make(map[string]*ctfkit.Lockfile, len(dirs))
	for _, dir := range dirs {
		lock, err := readLockfile(realRoot, filepath.Join(root, filepath.FromSlash(dir), lockFileName))
		if err != nil {
			return nil, err
		}
		if lock != nil {
			locks[dir] = lock
		}
	}
	return locks, nil
}

// readLockfile parses the dependency lock file at path. A file that is not
// there returns a nil lock file and no error; a file that is there and does
// not parse is an input error.
func readLockfile(realRoot, path string) (*ctfkit.Lockfile, error) {
	// Absence is decided by Lstat, which does not follow the link, so a lock
	// file that is simply not there is the nil case while a broken link where
	// one should be is an error rather than a silent nil.
	if _, statErr := os.Lstat(path); errors.Is(statErr, fs.ErrNotExist) {
		return nil, nil
	}

	// The lock file is repository content like any other file, so it is read
	// through the same containment check rather than opened directly.
	content, err := readContained(realRoot, path)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrInput, shown(path), err)
	}

	parsed, diags := hclparse.NewParser().ParseHCL(content, path)
	if diags.HasErrors() {
		return nil, lockfileError(path, diags)
	}

	var decoded lockFile
	if decodeDiags := gohcl.DecodeBody(parsed.Body, nil, &decoded); decodeDiags.HasErrors() {
		return nil, lockfileError(path, decodeDiags)
	}

	providers := make([]ctfkit.LockedProvider, 0, len(decoded.Providers))
	for _, p := range decoded.Providers {
		providers = append(providers, ctfkit.LockedProvider{
			Source:      p.Source,
			Version:     p.Version,
			Constraints: p.Constraints,
			Hashes:      p.Hashes,
		})
	}

	return &ctfkit.Lockfile{Providers: providers}, nil
}

// lockfileError reports that the lock file did not parse, naming the file and
// the position of the first diagnostic.
//
// The diagnostic text itself is deliberately dropped. HCL quotes the
// identifier it did not expect, and that identifier is written by the
// repository under analysis, so passing the diagnostic through would put
// input text into a diagnostic that the specification says carries the file
// and the reason only.
func lockfileError(path string, diags hcl.Diagnostics) error {
	first := diags.Errs()[0]
	if diag, ok := first.(*hcl.Diagnostic); ok && diag.Subject != nil {
		return fmt.Errorf("%w: %s does not parse as a dependency lock file: first error at line %d, column %d",
			ErrInput, path, diag.Subject.Start.Line, diag.Subject.Start.Column)
	}

	return fmt.Errorf("%w: %s does not parse as a dependency lock file", ErrInput, path)
}

// LoadPlan reads the plan JSON at path.
//
// The plan is the output of `terraform show -json tfplan`, produced by the
// caller; this package never runs terraform. A file that is not valid plan
// JSON, or whose format version major is not 1, is an input error and never a
// partly filled plan.
func LoadPlan(path string) (*tfjson.Plan, error) {
	plan, _, err := LoadPlanBytes(path)
	return plan, err
}

// LoadPlanBytes is LoadPlan that also returns the bytes it read, so a caller
// verifies and evaluates the same in-memory bytes. The parsed plan holds
// numbers as float64; instance keys are computed from the raw bytes
// (pkg/verdict/tfjson), never from it.
func LoadPlanBytes(path string) (*tfjson.Plan, []byte, error) {
	// #nosec G304 -- path comes from the operator-chosen plan flag
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cannot read plan %s: %w; %s", ErrInput, path, ReadReason(err),
			ReadStep(err, "write it with terraform show -json PLANFILE > "+path+" (or tofu show -json PLANFILE > "+path+")"))
	}
	plan, err := ParsePlanNamed(path, content)
	if err != nil {
		return nil, nil, err
	}
	return plan, content, nil
}

// ParsePlanNamed parses plan JSON bytes that name read from, with the checks
// of LoadPlan: valid plan JSON and format version major 1.
func ParsePlanNamed(name string, content []byte) (*tfjson.Plan, error) {
	plan, err := ParsePlan(content)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a valid plan JSON file: %w", ErrInput, name, err)
	}

	if major, _, _ := strings.Cut(plan.FormatVersion, "."); major != planFormatMajor {
		return nil, fmt.Errorf(
			"%w: plan %s has format version %q, and only format version major %s is supported",
			ErrInput, name, plan.FormatVersion, planFormatMajor)
	}

	return plan, nil
}

// ParsePlan decodes plan JSON into the analyzer view, numbers as float64.
//
// A number beyond the float64 range, which the instance_key format accepts
// (pkg/verdict/testdata/instancekey/FORMAT.md, Numbers), reads as +-1e308
// instead of failing the plan. The error never quotes the
// input: encoding/json errors carry the offending literal, which is plan
// content.
func ParsePlan(content []byte) (*tfjson.Plan, error) {
	var plan tfjson.Plan
	// Plan.UnmarshalJSON validates as it decodes, so a truncated file and a
	// JSON document that is not a plan both fail here rather than yielding an
	// empty plan.
	err := json.Unmarshal(content, &plan)
	// The common plan decodes on the first pass; only an out-of-range number
	// pays for the token walk.
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) && strings.HasPrefix(typeErr.Value, "number") {
		var saturated []byte
		if saturated, err = saturateNumbers(content); err == nil {
			err = json.Unmarshal(saturated, &plan)
		}
	}
	if err != nil {
		return nil, errors.New(jsonErrorText(err))
	}
	return &plan, nil
}

// saturateNumbers returns a copy of content in which every number literal
// beyond the float64 range is overwritten by +-1e308 and padded with spaces,
// so the byte offset of a later decode error still points into content.
//
// shortcut: such a number reads as +-1e308 in the analyzer view, so two of
// them compare equal; the exact values stay in the raw bytes
// (pkg/verdict/tfjson). Upgrade if an analyzer needs to order them.
func saturateNumbers(content []byte) ([]byte, error) {
	out := bytes.Clone(content)
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		n, ok := tok.(json.Number)
		if !ok {
			continue
		}
		// The JSON number grammar is a subset of ParseFloat's, so the only
		// error is ErrRange. No out-of-range literal is shorter than its
		// replacement: the shortest are 2e308 and -2e308.
		if _, parseErr := strconv.ParseFloat(string(n), 64); parseErr == nil {
			continue
		}
		end := int(dec.InputOffset())
		literal := out[end-len(n) : end]
		replacement := "1e308"
		if n[0] == '-' {
			replacement = "-1e308"
		}
		copy(literal, replacement+strings.Repeat(" ", len(n)-len(replacement)))
	}
}

// jsonErrorText describes a decode error by kind and byte offset only.
// Errors other than encoding/json's keep their text: terraform-json's own
// name the format version, never a value.
func jsonErrorText(err error) string {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntaxErr):
		return fmt.Sprintf("invalid JSON at byte offset %d", syntaxErr.Offset)
	case errors.As(err, &typeErr):
		kind, _, _ := strings.Cut(typeErr.Value, " ")
		return fmt.Sprintf("a JSON %s where %v is expected, at byte offset %d", kind, typeErr.Type, typeErr.Offset)
	}
	return err.Error()
}
