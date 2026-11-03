package loader

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// errEscapes and errUnresolved are the reasons readWithin refuses a file. They
// carry no path: the caller names the file, through shown.
var (
	errEscapes    = errors.New("leaves the configuration directory")
	errUnresolved = errors.New("does not resolve to a file")
	// errUnreadable replaces the OS error of a failed read, which names the
	// resolved absolute path and so, for a module directory, its source.
	errUnreadable = errors.New("cannot be read")
)

// isLocalSource reports whether a module source is a "./" or "../" path, the
// form Terraform and OpenTofu read from the caller's own directory rather than
// fetch. They take ".\" and "..\" as the same prefixes on every platform
// (moduleSourceLocalPrefixes, internal/addrs/module_source.go), so localPath
// is judged rather than the source as written.
func isLocalSource(source string) bool {
	s := localPath(source)
	return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}

// localPath is a local source as a slash path: every backslash is a slash,
// as init replaces them whatever the platform, and nothing is trimmed, since
// init does not trim either. A source with a trailing space names a directory
// whose name ends in one, and a join of the trimmed source would name another.
func localPath(source string) string {
	return strings.ReplaceAll(source, `\`, "/")
}

// shown is a path or source as a diagnostic may print it: through
// ctfkit.RedactPath, so no userinfo or query reaches it, and a fixed
// placeholder for a component it cannot read. A module directory is named
// after its source, so a diagnostic that names one echoes the source.
func shown(path string) string {
	return ctfkit.RedactPath(filepath.ToSlash(path))
}

// absDir is a directory of a record or a source joined to root, or the
// directory itself when it is already absolute: init records a symlinked
// local module by its resolved path, which can be absolute.
func absDir(root, dir string) string {
	d := filepath.FromSlash(dir)
	if filepath.IsAbs(d) {
		return d
	}
	return filepath.Join(root, d)
}

// resolve is path made absolute and then resolved, so two spellings of one
// directory, relative and absolute, compare equal. Absolute first: resolving a
// relative path leaves the working directory's own symlinks in place.
func resolve(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// readWithin reads path after resolving it and verifying that it lies within
// one of bases, each a resolved directory. The read is of the resolved target,
// so the link is followed once, at the moment it is checked. The error names
// no path; the caller does.
func readWithin(bases []string, path string) ([]byte, error) {
	target, err := resolve(path)
	if err != nil {
		return nil, errUnresolved
	}
	for _, base := range bases {
		if within(base, target) {
			// #nosec G304 -- target is the resolved path, verified to be inside
			// the root or an explicit local module directory
			content, readErr := os.ReadFile(target)
			if readErr != nil {
				return nil, errUnreadable
			}
			return content, nil
		}
	}
	return nil, errEscapes
}

// readDirFiles reads the configuration files directly in the directory full,
// in path order, each within bases, with Path dir/name. Subdirectories are not
// read: a child module is read from its own directory.
//
// A directory that cannot be listed is an error, never an empty module: it
// exists, so terraform reads it, and a module ctfkit was not shown is one it
// cannot say runs nothing. So is a file in it that cannot be read or that a
// symlink leads out of every base.
func readDirFiles(full, dir string, bases []string) ([]ctfkit.ConfigFile, error) {
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, fmt.Errorf("%w: module directory %s cannot be listed", ErrInput, shown(dir))
	}
	var files []ctfkit.ConfigFile
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !isConfigFile(name) {
			continue
		}
		display := pathpkg.Join(dir, name)
		content, readErr := readWithin(bases, filepath.Join(full, name))
		if readErr != nil {
			return nil, fmt.Errorf("%w: %s %w", ErrInput, shown(display), readErr)
		}
		files = append(files, ctfkit.ConfigFile{Path: display, Bytes: content})
	}
	// os.ReadDir lists by file name, so the files are already in path order.
	return files, nil
}

// LoadLocalModules reads, for a pre_plan directory scan, the "./" and "../"
// local modules the configuration calls that LoadConfig did not read: those
// outside root, and those in a directory its walk skips, such as
// .terraform.d. It follows their own local calls too, so a module a shared
// module calls is read as well.
//
// A local source is explicit in the configuration and terraform runs what it
// names, so reading it adds no risk; it is what lets the ctf.exec rules see
// code beside the repository. Each child source is joined to the resolved
// directory of the module that calls it, as Terraform and OpenTofu do
// (installLocalModule: filepath.Join(parent.Dir, source), then EvalSymlinks),
// so a "../alias" that resolves to "../libs/pkg" calling "../hook" reads
// "../libs/hook". Directories are tracked by resolved path: each is read once,
// and one that calls itself, directly or through others, is an error.
//
// Scan runs before init, so a "../" directory that does not exist is returned
// with Unread set rather than failing the scan; a sparse checkout may lack it.
// Every other failure is an input error: a directory that exists and cannot be
// listed or does not resolve, a "./" call that a symlink leads out of root
// (unless it lands on the directory of an explicit "../" source), and a file
// that a symlink leads out of its module's directory.
//
// The calls it returns are every local call of every file read, the root's
// and the modules', each with the directory it resolved to, so the analyzer
// addresses a module by the call that reaches it rather than by source text.
func LoadLocalModules(root string, files []ctfkit.ConfigFile) ([]ctfkit.LocalModule, []ctfkit.LocalCall, error) {
	realRoot, err := resolve(root)
	if err != nil {
		return nil, nil, cannotReadDir(root, err)
	}
	l := &localLoader{
		realRoot: realRoot,
		walked:   map[string]bool{},
		done:     map[string]bool{},
		onStack:  map[string]bool{},
		targets:  map[string]bool{},
		absent:   map[string]bool{},
	}
	// The directories LoadConfig read files from, by resolved path. Its walk
	// starts at the resolved root and does not follow a symlink, so each is
	// already a real directory.
	for _, f := range files {
		l.walked[filepath.Join(realRoot, filepath.FromSlash(pathpkg.Dir(f.Path)))] = true
	}
	for _, f := range files {
		dir := filepath.Join(realRoot, filepath.FromSlash(pathpkg.Dir(f.Path)))
		l.onStack[dir] = true
		err := l.follow(f, dir)
		delete(l.onStack, dir)
		if err != nil {
			return nil, nil, err
		}
	}
	for _, resolved := range l.links {
		if !l.targets[resolved] {
			return nil, nil, fmt.Errorf("%w: a ./ local module directory leaves the configuration directory through a symlink", ErrInput)
		}
	}
	return l.out, l.calls, nil
}

// localLoader is the state of one LoadLocalModules traversal.
type localLoader struct {
	realRoot string
	// walked are the directories LoadConfig read; done the ones read here.
	walked, done map[string]bool
	// onStack are the directories on the current call path, for the cycle
	// check.
	onStack map[string]bool
	// targets are the resolved directories of sources whose join leads out of
	// the root before any symlink is followed: the explicit "../" modules.
	targets map[string]bool
	// links are directories a "./" join inside the root resolved to outside
	// it, allowed only when one of targets names them too.
	links []string
	// absent are the joined directories already reported as not there.
	absent map[string]bool
	out    []ctfkit.LocalModule
	calls  []ctfkit.LocalCall
}

// follow follows every local module call in file, whose module directory is
// the resolved directory parent, and records where each one leads.
func (l *localLoader) follow(file ctfkit.ConfigFile, parent string) error {
	for _, m := range parser.ParseConfigContent(file.Bytes, file.Path).Modules {
		if !isLocalSource(m.Source) {
			continue
		}
		joined := filepath.Join(parent, filepath.FromSlash(localPath(m.Source)))
		to, err := l.module(joined)
		if err != nil {
			return err
		}
		l.calls = append(l.calls, ctfkit.LocalCall{From: l.display(parent), Name: m.Name, To: to})
	}
	return nil
}

// module reads one joined local module directory, unless it is read already,
// and returns the directory the call leads to, as LocalCall.To names it.
func (l *localLoader) module(joined string) (string, error) {
	display := l.display(joined)
	resolved, err := resolve(joined)
	if errors.Is(err, fs.ErrNotExist) {
		if !within(l.realRoot, joined) && !l.absent[joined] {
			l.absent[joined] = true
			l.out = append(l.out, ctfkit.LocalModule{Dir: display, Unread: true})
		}
		// A ./ directory inside the root that is not there holds no code;
		// init will refuse the call.
		return display, nil
	}
	if err != nil {
		return "", fmt.Errorf("%w: local module directory %s does not resolve", ErrInput, shown(display))
	}
	dir := l.display(resolved)
	if l.onStack[resolved] {
		return "", fmt.Errorf("%w: a local module calls itself through a cycle of ./ or ../ sources", ErrInput)
	}
	if l.walked[resolved] || l.done[resolved] {
		return dir, nil
	}

	insideJoin, insideResolved := within(l.realRoot, joined), within(l.realRoot, resolved)
	if insideJoin && !insideResolved {
		l.links = append(l.links, resolved)
		return dir, nil
	}
	if !insideJoin {
		l.targets[resolved] = true
	}
	l.done[resolved] = true

	// The module is named by where it really is, relative to the root, so a
	// file's path says which directory it came from. A file in it is read
	// when it resolves inside the root or inside this module's directory; a
	// file symlink that resolves anywhere else is an error.
	files, err := readDirFiles(resolved, dir, []string{l.realRoot, resolved})
	if err != nil {
		return "", err
	}
	l.out = append(l.out, ctfkit.LocalModule{Dir: dir, Files: files})

	l.onStack[resolved] = true
	defer delete(l.onStack, resolved)
	for _, f := range files {
		if err := l.follow(f, resolved); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// display is an absolute path relative to the root, POSIX separated, the way
// a LocalModule names its directory and its files.
func (l *localLoader) display(abs string) string {
	rel, err := filepath.Rel(l.realRoot, abs)
	if err != nil {
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(rel)
}
