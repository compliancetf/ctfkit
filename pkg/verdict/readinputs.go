package verdict

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
)

// maxBundles bounds the bundle directories ReadInputs reads.
const maxBundles = 64

// ReadInputs reads the files of a gate run from fsys, each exactly once and
// within its size limit, so VerifyInputs and evaluation use the same bytes
// and nothing is read from disk again. bundleDir holds one directory per
// bundle with its manifest.dsse.json and the files that manifest lists;
// any other entry, a symlink included, is an error. VerifyInputs then
// rejects a file the manifest does not list.
func ReadInputs(fsys fs.FS, orgID, keyring, profile, floor, bundleDir string) (Inputs, error) {
	in := Inputs{OrgID: orgID}
	var err error
	if in.Keyring, err = readBounded(fsys, keyring, maxKeyringBytes); err != nil {
		return Inputs{}, err
	}
	if in.Profile, err = readBounded(fsys, profile, maxEnvelopeBytes); err != nil {
		return Inputs{}, err
	}
	if in.Floor, err = readBounded(fsys, floor, maxEnvelopeBytes); err != nil {
		return Inputs{}, err
	}
	dirs, err := fs.ReadDir(fsys, bundleDir)
	if err != nil {
		return Inputs{}, err
	}
	if len(dirs) > maxBundles {
		return Inputs{}, fmt.Errorf("%s: more than %d bundles", bundleDir, maxBundles)
	}
	for _, d := range dirs { // ReadDir sorts by name, so the order is stable
		dir := path.Join(bundleDir, d.Name())
		if !d.IsDir() {
			return Inputs{}, fmt.Errorf("%s: not a bundle directory", dir)
		}
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			return Inputs{}, err
		}
		b := BundleFiles{Files: map[string][]byte{}}
		for _, e := range entries {
			p := path.Join(dir, e.Name())
			switch {
			case !e.Type().IsRegular():
				return Inputs{}, fmt.Errorf("%s: not a regular file", p)
			case e.Name() == ManifestFile:
				b.Manifest, err = readBounded(fsys, p, maxEnvelopeBytes)
			case knownFiles[e.Name()]:
				b.Files[e.Name()], err = readBounded(fsys, p, maxFile)
			default:
				return Inputs{}, fmt.Errorf("%s: not a bundle file", p)
			}
			if err != nil {
				return Inputs{}, err
			}
		}
		if b.Manifest == nil {
			return Inputs{}, fmt.Errorf("%s: %s missing", dir, ManifestFile)
		}
		in.Bundles = append(in.Bundles, b)
	}
	return in, nil
}

// readBounded reads name once, failing above limit bytes or when the
// opened file is not a regular file.
// shortcut: fs.FS has no no-follow open, so an entry swapped for a symlink
// or FIFO between ReadDir and Open is followed (a FIFO blocks Open); the
// signed manifest digests still reject changed bytes. Move to os.Root with
// O_NOFOLLOW if inputs ever come from a directory others write during a run.
func readBounded(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New(name + ": not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New(name + ": file too large")
	}
	return b, nil
}
