package tfexec

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
)

// TestRealTerraformProviderSealing runs a session with the binary
// CTFKIT_TEST_TF names (terraform or tofu) and the provider binary
// CTFKIT_TEST_PROVIDER names (terraform-provider-aws test/fakeupstream,
// `go build ./v5`), served as registry.terraform.io/bobthecorp/fake 1.0.0 (a
// namespace OpenTofu does not rewrite to its own registry) from
// a packed implied local mirror (~/.terraform.d/plugins of the owned HOME).
// Nothing leaves the machine: no registry, local state, nothing applied.
//
// It checks the [verify] of the exec rule on a real CLI: after the mirror
// init the data dir's package is a link to the sealed copy, and schema and
// plan run the provider from there.
func TestRealTerraformProviderSealing(t *testing.T) {
	tf, provider := os.Getenv("CTFKIT_TEST_TF"), os.Getenv("CTFKIT_TEST_PROVIDER")
	if tf == "" || provider == "" {
		t.Skip("CTFKIT_TEST_TF and CTFKIT_TEST_PROVIDER are not set")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const main = `terraform {
  required_providers {
    fake = { source = "registry.terraform.io/bobthecorp/fake", version = "1.0.0" }
  }
}
`
	platform := runtime.GOOS + "_" + runtime.GOARCH
	zipped, h1 := packProvider(t, provider)
	zh := sha256.Sum256(zipped)
	// The lock file records the package's h1: and its zip's zh:, as a
	// registry install does.
	lock := fmt.Sprintf("provider \"registry.terraform.io/bobthecorp/fake\" {\n  version = \"1.0.0\"\n  constraints = \"1.0.0\"\n  hashes = [%q, %q]\n}\n", h1, "zh:"+hex.EncodeToString(zh[:]))
	for name, body := range map[string]string{"main.tf": main, ".terraform.lock.hcl": lock} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s := open(t, Config{Terraform: tf, Digest: digestOf(t, tf), Dir: dir, Workspace: "default"})
	// The first init finds the package in the implied local mirror of the
	// owned HOME, so it never reaches a registry.
	mirror := s.Owned("home/.terraform.d/plugins/registry.terraform.io/bobthecorp/fake")
	if err = os.MkdirAll(mirror, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(mirror, "terraform-provider-fake_1.0.0_"+platform+".zip"), zipped, 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	for _, c := range []Call{Version(), Init(), Schema(), Plan(), Init()} {
		if err = s.Run(c, io.Discard, &stderr); err != nil {
			t.Fatalf("%s: %v\n%s", c.Row(), err, stderr.String())
		}
	}
	pkg := "registry.terraform.io/bobthecorp/fake/1.0.0/" + platform
	link, err := os.Lstat(s.Owned("data/providers/" + pkg))
	if err != nil || link.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the data dir package is not a link: %v %v", link, err)
	}
	if target, lerr := filepath.EvalSymlinks(s.Owned("data/providers/" + pkg)); lerr != nil || target != s.Owned("sealed/providers/"+pkg) {
		t.Fatalf("link target %s (%v)", target, lerr)
	}
	if _, _, err = s.SealOwned("planfile", "planfile", 1<<26); err != nil {
		t.Fatal(err)
	}
}

// packProvider returns the provider zip and the h1: of its unpacked package.
func packProvider(t *testing.T, bin string) ([]byte, string) {
	t.Helper()
	body, err := os.ReadFile(bin) // #nosec G304 -- a test input
	if err != nil {
		t.Fatal(err)
	}
	const name = "terraform-provider-fake_v1.0.0_x5"
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(0o755)
	w, err := zw.CreateHeader(h)
	if err == nil {
		_, err = w.Write(body)
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	h1, err := dirhash.Hash1([]string{name}, func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), h1
}
