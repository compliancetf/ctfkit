package tfexec

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// Sealed is a file sealed into the owned root: read once, written 0400 with
// O_EXCL|O_NOFOLLOW. Show and Apply take only a Sealed, never a path.
type Sealed struct{ name string }

func (s Sealed) template() string { return "<owned>/sealed/" + s.name }

// Seal writes body as the sealed copy name.
func (s *Session) Seal(name string, body []byte) (Sealed, error) {
	if !reSealed.MatchString("<owned>/sealed/" + name) {
		return Sealed{}, fmt.Errorf("sealed name %q", name)
	}
	return Sealed{name}, writeExclusive(s.owned("sealed/"+name), body, 0o400)
}

// SealOwned reads the owned file terraform wrote (planfile, pre.tfplan, ...)
// through one open, capped at limit bytes, and seals those bytes as the
// sealed copy as; the returned bytes and the sealed copy are the same, so a
// later write to the owned file changes nothing.
func (s *Session) SealOwned(name, as string, limit int64) (Sealed, []byte, error) {
	b, err := ReadCapped(s.owned(name), limit)
	if err != nil {
		return Sealed{}, nil, err
	}
	sl, err := s.Seal(as, b)
	return sl, b, err
}

// maxTerraformBytes caps the sealed copy, so a swapped (or sparse) binary
// cannot fill the owned root before its digest is refused.
var maxTerraformBytes int64 = 1 << 30 // a var so a test can lower it

// sealTerraform copies the pinned binary into the sealed dir, hashing the
// bytes it copies, and returns the copy's path. A digest that differs from
// the recorded one removes the copy: nothing of it runs.
func (s *Session) sealTerraform() (string, error) {
	// O_NONBLOCK: a fifo planted at the path fails the regular-file check instead of blocking the open.
	in, err := os.OpenFile(s.cfg.Terraform, os.O_RDONLY|oNonblock, 0) // #nosec G304 -- the pinned binary; a final symlink is allowed, the digest is over its bytes
	if err != nil {
		return "", err
	}
	defer in.Close() //nolint:errcheck // read-only
	if st, serr := in.Stat(); serr != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", s.cfg.Terraform)
	}
	s.seq++
	dst := s.owned(fmt.Sprintf("sealed/terraform-%d", s.seq))
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o700) // #nosec G302 G304 -- the sealed binary in the owned 0700 root, 0500 once written
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, maxTerraformBytes+1))
	if err == nil && n > maxTerraformBytes {
		err = fmt.Errorf("terraform binary %s is larger than %d bytes", s.cfg.Terraform, maxTerraformBytes)
	}
	if err == nil {
		err = out.Sync()
	}
	if err == nil {
		err = out.Chmod(0o500)
	}
	err = errors.Join(err, out.Close())
	if d := "sha256:" + hex.EncodeToString(h.Sum(nil)); err == nil && d != s.cfg.Digest {
		err = fmt.Errorf("terraform binary %s is %s, not the pinned %s", s.cfg.Terraform, d, s.cfg.Digest)
	}
	if err != nil {
		return "", errors.Join(err, os.Remove(dst))
	}
	return dst, nil
}

// writeExclusive creates path (never an existing file or symlink), writes
// body and fsyncs it.
func writeExclusive(path string, body []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, mode) // #nosec G304 -- inside the owned root
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// OpenRegular opens path without following a final symlink and refuses
// anything but a regular file.
func OpenRegular(path string) (*os.File, error) {
	// Lstat first so a FIFO or device is refused before an open can block on it.
	if st, err := os.Lstat(path); err != nil {
		return nil, err
	} else if !st.Mode().IsRegular() {
		return nil, errors.New(path + ": not a regular file")
	}
	// O_NONBLOCK: a fifo swapped in after the Lstat fails the check below instead of blocking the open.
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow|oNonblock, 0) // #nosec G304 -- an operator flag or an owned path
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = errors.New(path + ": not a regular file")
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// ReadCapped reads a regular file through one open, refusing more than
// limit bytes.
func ReadCapped(path string, limit int64) ([]byte, error) {
	f, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("larger than %d bytes", limit)
	}
	return b, err
}
