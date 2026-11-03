package fixturepin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// livePack is the committed report pack, the oracle these tests mutate copies of.
const livePack = "../../testdata/fixtures/report"

const host = "bobthecorp.compliance.tf"

// copyPack copies the live pack into a scratch directory.
func copyPack(t *testing.T) string {
	t.Helper()
	files, err := ReadFiles(livePack)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = WriteFiles(dir, files); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // a test path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // a test tree
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // a test tree
		t.Fatal(err)
	}
}

// editPin rewrites a copy's PIN.json canonically after fn changes it.
func editPin(t *testing.T, dir string, fn func(*Pin)) {
	t.Helper()
	p, _, err := ReadPin(filepath.Join(dir, PinFile))
	if err != nil {
		t.Fatal(err)
	}
	fn(p)
	raw, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, PinFile), raw)
}

// manifestOf is the root manifest path of a single-module case.
func manifestOf(dir, c string) string {
	return filepath.Join(dir, c, "input", ".terraform", "modules", "s3_bucket", ManifestName)
}

func TestLivePackPasses(t *testing.T) {
	for _, err := range Check(livePack) {
		t.Error(err)
	}
}

// Every manifest the registry served re-encodes byte for byte, which is what
// lets a transform edit one structurally and still produce the served layout.
func TestOrderedJSONRoundTrip(t *testing.T) {
	files, err := ReadFiles(livePack)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for p, raw := range files {
		if filepath.Base(p) != ManifestName {
			continue
		}
		n++
		doc, tail, parseErr := parseJSON(raw)
		if parseErr != nil {
			t.Fatalf("%s: %v", p, parseErr)
		}
		if got := append(doc.encode(), tail...); !bytes.Equal(got, raw) {
			t.Errorf("%s does not round-trip", p)
		}
	}
	if n == 0 {
		t.Fatal("no manifest found")
	}
}

// handAssembled is the one modules.json not written by tofu: helper-module was
// assembled in process (README, 2026-09-26) and carries a trailing newline.
// The next live re-record replaces it with tofu's encoding, which also changes
// the modulesJson sha256 in that case's receipt.
const handAssembled = "helper-module/input/.terraform/modules/modules.json"

// tofu writes modules.json with encoding/json; Assemble re-marshals it, so
// the committed bytes must be exactly that encoding.
func TestModulesJSONIsTofuEncoding(t *testing.T) {
	files, err := ReadFiles(livePack)
	if err != nil {
		t.Fatal(err)
	}
	for p, raw := range files {
		if filepath.Base(p) != "modules.json" {
			continue
		}
		if p == handAssembled {
			raw = bytes.TrimSuffix(raw, []byte("\n"))
		}
		var mf ModulesFile
		if err = json.Unmarshal(raw, &mf); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got, _ := json.Marshal(mf); !bytes.Equal(got, raw) {
			t.Errorf("%s is not tofu's encoding:\n%s\n%s", p, raw, got)
		}
	}
}

func TestCheckCatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, dir string)
		want   string
	}{
		{"a non-canonical pin", func(t *testing.T, dir string) {
			p := filepath.Join(dir, PinFile)
			mustWrite(t, p, append(mustRead(t, p), '\n'))
		}, "not canonical"},
		{"an unknown pin field", func(t *testing.T, dir string) {
			p := filepath.Join(dir, PinFile)
			mustWrite(t, p, bytes.Replace(mustRead(t, p), []byte(`{"cases"`), []byte(`{"extra":1,"cases"`), 1))
		}, "unknown field"},
		{"a wrong pin_format", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) { p.PinFormat = 2 })
		}, "pin_format is 2"},
		{"a case on disk but not pinned", func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, "new-case", "input", "main.tf"), nil)
		}, "new-case is on disk but not in PIN.json"},
		{"a pinned case not on disk", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) { p.Cases["gone"] = Case{Role: RoleRecorded, Modules: []Module{}} })
		}, "gone is in PIN.json but not on disk"},
		{"a manifest that changed", func(t *testing.T, dir string) {
			p := manifestOf(dir, "helper-module")
			mustWrite(t, p, bytes.Replace(mustRead(t, p), []byte("2026-09-20T16"), []byte("2026-09-21T16"), 1))
		}, "manifest sha256"},
		{"a schema version that disagrees with the pin", func(t *testing.T, dir string) {
			p := manifestOf(dir, "helper-module")
			mustWrite(t, p, bytes.Replace(mustRead(t, p), []byte(`"schema_version": "3.3"`), []byte(`"schema_version": "3.5"`), 1))
			editPin(t, dir, func(pin *Pin) {
				c := pin.Cases["helper-module"]
				for i := range c.Modules {
					c.Modules[i].ManifestSHA256 = sha(mustRead(t, p))
				}
				pin.Cases["helper-module"] = c
			})
		}, "schema_version is 3.5, pinned 3.3"},
		{"a registry module the pin does not list", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) {
				c := p.Cases["served-leaf"]
				c.Modules = []Module{}
				p.Cases["served-leaf"] = c
			})
		}, "s3_bucket_notification is in modules.json but not pinned"},
		{"a module version that moved", func(t *testing.T, dir string) {
			rewriteModules(t, dir, "served-leaf", func(e *ModuleEntry) { e.Version = "5.17.0" })
		}, "pinned at"},
		{"a source off the pinned host", func(t *testing.T, dir string) {
			rewriteModules(t, dir, "served-leaf", func(e *ModuleEntry) {
				e.Source = strings.Replace(e.Source, host, "registry.example.com", 1)
			})
		}, "not on the pinned registry host"},
		{"a git source", func(t *testing.T, dir string) {
			rewriteModules(t, dir, "served-leaf", func(e *ModuleEntry) { e.Source = "git::https://example.com/x.git" })
		}, "is not host/namespace/name/system"},
		{"an absolute Dir", func(t *testing.T, dir string) {
			rewriteModules(t, dir, "served-leaf", func(e *ModuleEntry) { e.Dir = "/tmp/modules/x" })
		}, "not a clean relative path"},
		{"a Dir outside .terraform/modules", func(t *testing.T, dir string) {
			rewriteModules(t, dir, "missing-manifest", func(e *ModuleEntry) {
				if e.Key == "s3_bucket" {
					e.Dir = "modules/replication_role"
				}
			})
		}, "resolves outside"},
		{"a synthesized input that differs from its transform", func(t *testing.T, dir string) {
			p := manifestOf(dir, "supporting-clauses")
			mustWrite(t, p, bytes.Replace(mustRead(t, p), []byte(`"soc_2": []`), []byte(`"soc_2": ["CC1.1"]`), 1))
		}, "differs from transform supporting-clauses"},
		{"a file a transform does not produce", func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, "schema-4-stub", "input", "extra.tf"), nil)
		}, "extra.tf is not produced by transform"},
		{"an unknown transform", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) {
				c := p.Cases["degraded-build"]
				c.Transform = "made-up"
				p.Cases["degraded-build"] = c
			})
		}, `transform "made-up" is not known`},
		{"a synthesized base that is not recorded", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) {
				c := p.Cases["degraded-build"]
				c.BaseCase = "schema-4-stub"
				p.Cases["degraded-build"] = c
			})
		}, "is not a recorded case"},
		{"a token in the pack", func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, "served-leaf", "input", "notes.txt"), []byte("TF_TOKEN_bobthecorp_compliance_tf=x\n"))
		}, "TF_TOKEN variable"},
		{"a pinned module absent from modules.json", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) {
				c := p.Cases["served-leaf"]
				c.Modules = append(c.Modules, Module{Key: "ghost", Source: host + "/a/b/aws", Version: "1.0.0", ManifestSchemaVersion: "3.3", ManifestSHA256: "00"})
				p.Cases["served-leaf"] = c
			})
		}, "module ghost is pinned but not a registry module in modules.json"},
		{"a contained registry Dir with no manifest", func(t *testing.T, dir string) {
			if err := os.Remove(manifestOf(dir, "helper-module")); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(filepath.Dir(manifestOf(dir, "helper-module")), "main.tf"), nil)
		}, "helper-module: module s3_bucket: manifest:"},
		{"a symlinked manifest", func(t *testing.T, dir string) {
			m := manifestOf(dir, "helper-module")
			if err := os.Rename(m, m+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(ManifestName+".real", m); err != nil {
				t.Skip(err)
			}
		}, "not a regular file"},
		{"an invalid registry_host", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) { p.RegistryHost = "Not A Host" })
		}, "is not a DNS name"},
		{"an invalid recorded_on", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) { p.RecordedOn = "20 Sep 2026" })
		}, "is not a UTC date"},
		{"an invalid tofu_version", func(t *testing.T, dir string) {
			editPin(t, dir, func(p *Pin) { p.TofuVersion = "latest" })
		}, `neither a version nor "unknown"`},
		{"a transform output missing on disk", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "schema-4-stub", "input", "main.tf")); err != nil {
				t.Fatal(err)
			}
		}, "input/main.tf is missing; transform schema-major-4"},
		{"a symlink in the pack", func(t *testing.T, dir string) {
			if err := os.Symlink("main.tf", filepath.Join(dir, "served-leaf", "input", "link.tf")); err != nil {
				t.Skip(err)
			}
		}, "symlink"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := copyPack(t)
			tt.mutate(t, dir)
			errs := Check(dir)
			var msgs []string
			for _, e := range errs {
				msgs = append(msgs, e.Error())
			}
			if !strings.Contains(strings.Join(msgs, "\n"), tt.want) {
				t.Errorf("Check() = %q, want an error containing %q", msgs, tt.want)
			}
		})
	}
}

func rewriteModules(t *testing.T, dir, c string, fn func(*ModuleEntry)) {
	t.Helper()
	p := filepath.Join(dir, c, "input", ".terraform", "modules", "modules.json")
	mf, err := ReadModules(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := range mf.Modules {
		if mf.Modules[i].Key != "" {
			fn(&mf.Modules[i])
		}
	}
	raw, err := json.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, p, raw)
}

func TestTransformPostConditions(t *testing.T) {
	base, err := ReadFiles(filepath.Join(livePack, "delegated-without-sibling", "input"))
	if err != nil {
		t.Fatal(err)
	}
	withManifest := func(old, repl string) Files {
		out := Files{}
		for p, b := range base {
			if filepath.Base(p) == ManifestName {
				b = bytes.Replace(b, []byte(old), []byte(repl), 1)
			}
			out[p] = b
		}
		return out
	}
	tests := []struct {
		name  string
		tf    string
		input Files
		want  string
	}{
		{"schema 4 of a schema 4 base", "schema-major-4", withManifest(`"schema_version": "3.3"`, `"schema_version": "4.0"`), "want 3.x"},
		{"a base already degraded", "degraded-posture", withManifest(`"degraded": []`, `"degraded": ["x"]`), "not an empty list"},
		{"supporting clauses on a 3.5 base", "supporting-clauses", withManifest(`"schema_version": "3.3"`, `"schema_version": "3.5"`), "want 3.0 to 3.4"},
		{"a base without the logging control", "supporting-clauses", withManifest(`"s3_bucket_logging_enabled"`, `"s3_bucket_logging_renamed"`), "no soc_2 control s3_bucket_logging_enabled"},
		{"a base with two manifests", "schema-major-4", func() Files {
			f := withManifest("", "")
			f[".terraform/modules/other/"+ManifestName] = f[".terraform/modules/s3_bucket/"+ManifestName]
			return f
		}(), "want exactly 1"},
		{"a base main.tf without a bucket", "degraded-posture", func() Files {
			f := withManifest("", "")
			f["main.tf"] = []byte("module \"x\" {}\n")
			return f
		}(), "0 bucket arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Transforms[tt.tf](tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// A base re-recorded at schema 3.4 that already carries the field still
// transforms to the same case: the field is replaced, not duplicated.
func TestSupportingClausesOnA34Base(t *testing.T) {
	base, err := ReadFiles(filepath.Join(livePack, "delegated-without-sibling", "input"))
	if err != nil {
		t.Fatal(err)
	}
	once, err := supportingClauses(base)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := supportingClauses(once)
	if err != nil {
		t.Fatal(err)
	}
	for p := range once {
		if p != "main.tf" && !bytes.Equal(once[p], twice[p]) {
			t.Errorf("%s changed on a second application", p)
		}
	}
}

func TestRegistrySource(t *testing.T) {
	tests := []struct {
		source, pkg string
		ok          bool
	}{
		{host + "/terraform-aws-modules/s3-bucket/aws", host + "/terraform-aws-modules/s3-bucket/aws", true},
		{host + "/terraform-aws-modules/s3-bucket/aws//modules/notification", host + "/terraform-aws-modules/s3-bucket/aws", true},
		{host + "/a/b/aws//../escape", "", false},
		{host + "/a/b/aws//modules/../x", "", false},
		{host + "/a/b/aws//", "", false},
		{"registry.example.com/a/b/aws", "", false},
		{"terraform-aws-modules/s3-bucket/aws", "", false},
		{"git::https://example.com/x.git", "", false},
		{"https://" + host + "/a/b/aws", "", false},
		{host + "/a/b/aws?ref=x", "", false},
	}
	for _, tt := range tests {
		pkg, err := RegistrySource(tt.source, host)
		if (err == nil) != tt.ok || pkg != tt.pkg {
			t.Errorf("RegistrySource(%q) = %q, %v; want ok=%v %q", tt.source, pkg, err, tt.ok, tt.pkg)
		}
	}
}

func TestScan(t *testing.T) {
	tests := []struct {
		name, body string
		exit       int
	}{
		{"clean", `{"source": "bobthecorp.compliance.tf/a/b/aws//modules/x", "path": "testdata/fixtures/report/x/input"}`, 0},
		{"the literal token", "a secret-token-value b", 3},
		{"a signed S3 URL", "https://bucket.s3.amazonaws.com/x.zip?X-Amz-Signature=abc", 3},
		{"a signed URL, generic", "https://example.com/x.zip?Expires=1&Signature=abc", 3},
		{"an absolute macOS path", `"Dir": "/Users/user/scratch/.terraform"`, 2},
		{"an absolute temp path", `"Dir": "/tmp/scratch"`, 2},
		{"a URL with credentials", "git::https://user:pass@example.com/x.git", 2},
		{"an AWS key shape", "AKIAABCDEFGHIJKLMNOP", 2},
		{"a registry token shape", "abcdefghijklmn.atlasv1.abcdefghijklmnopqrstuvwxyz", 2},
		{"a bearer header", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz", 2},
		// The shapes below are assembled at run time so no token-shaped
		// literal sits in the source for a secret scanner to trip on.
		{"a GitHub token shape", "gh" + "p_" + strings.Repeat("A1", 18), 2},
		{"a GitLab token shape", "glp" + "at-" + strings.Repeat("x9", 11), 2},
		{"a Google API key shape", "AI" + "za" + strings.Repeat("Q", 35), 2},
		{"a JWT shape", "ey" + "J" + strings.Repeat("h", 10) + ".ey" + "J" + strings.Repeat("p", 10) + ".sig", 2},
		{"a private key", "-----BEGIN " + "RSA PRIVATE KEY-----", 2},
		{"a file URL", "file:///srv/modules/x", 2},
		{"a Windows path", `C:\work\modules`, 2},
		{"a signed GCS URL", "https://storage.googleapis.com/b/x.zip?X-Goog-Signature=abc", 3},
		{"a signed Azure URL", "https://acct.blob.core.windows.net/c/x.zip?sv=2020&sig=abc", 3},
		{"the literal token, URL-encoded", "https://example.com/x?t=tok%2Ben%2Fvalue%3D", 3},
		{"a sha256 field is not a token", `"manifest_sha256": "561d28c33b3778847004ceec25f125c2a3dbbfccbd947742dbd050dd001a5c39"`, 0},
		{"an h1: hash is not a token", `"h1:yYl8Xp1u6n1mF6ZyTPy0JHNe5cUpcRlEwtoY9qqkCkk=",`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, "f.json"), []byte(tt.body))
			hits, err := Scan(dir, []string{"secret-token-value", "tok+en/value="})
			if err != nil {
				t.Fatal(err)
			}
			if got := ScanExit(hits); got != tt.exit {
				t.Errorf("exit = %d, want %d (%v)", got, tt.exit, hits)
			}
			for _, h := range hits {
				if strings.Contains(h.String(), "secret-token-value") || strings.Contains(h.String(), "abcdefghijklmnopqrstuvwxyz") {
					t.Errorf("a hit prints the matched value: %s", h)
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name, tf string
		extra    map[string]string
		want     string // empty: valid
	}{
		{"a registry source", `module "a" { source = "` + host + `/terraform-aws-modules/s3-bucket/aws" }`, nil, ""},
		{"a local source inside", `module "a" { source = "./modules/x" }`, map[string]string{"modules/x/main.tf": ""}, ""},
		{"a local module calling off host", `module "a" { source = "./modules/x" }`,
			map[string]string{"modules/x/main.tf": `module "b" { source = "registry.example.com/a/b/aws" }`}, "not on the pinned registry host"},
		{"a local source outside", `module "a" { source = "../outside" }`, nil, "local source"},
		{"a git source", `module "a" { source = "git::https://example.com/x.git" }`, nil, "is not host/namespace/name/system"},
		{"an interpolated source", `module "a" { source = "${var.x}/a/b/aws" }`, nil, "not a literal string"},
		{"another host", `module "a" { source = "registry.example.com/a/b/aws" }`, nil, "not on the pinned registry host"},
		{"a .tofu file off the registry", "", map[string]string{"extra.tofu": `module "b" { source = "hg::https://hg.bobthecorp.example/x" }`}, "is not host/namespace/name/system"},
		{"a .tofu file on the registry", "", map[string]string{"extra.tofu": `module "b" { source = "` + host + `/terraform-aws-modules/s3-bucket/aws" }`}, ""},
		{"a .tofu.json file", "", map[string]string{"extra.tofu.json": `{"module": {}}`}, "JSON configuration"},
		{"a .tf.json file", "", map[string]string{"extra.tf.json": `{"module": {}}`}, "JSON configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "case")
			mustWrite(t, filepath.Join(dir, "main.tf"), []byte(tt.tf))
			mustWrite(t, filepath.Join(filepath.Dir(dir), "outside", "main.tf"), nil)
			for p, b := range tt.extra {
				mustWrite(t, filepath.Join(dir, p), []byte(b))
			}
			err := ValidateConfig(dir, host)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("err = %v, want none", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// Assemble takes what tofu wrote under TF_DATA_DIR, with absolute Dirs, and
// produces the committed layout: Dirs relative to input/, manifests byte for
// byte, nothing else.
func TestAssemble(t *testing.T) {
	scratch := t.TempDir()
	caseDir := filepath.Join(scratch, "case")
	data := filepath.Join(scratch, "data")
	mustWrite(t, filepath.Join(caseDir, "modules", "replication_role", "main.tf"), nil)

	live := filepath.Join(livePack, "missing-manifest", "input", ".terraform", "modules")
	manifest := mustRead(t, filepath.Join(live, "s3_bucket", ManifestName))
	mustWrite(t, filepath.Join(data, "modules", "s3_bucket", ManifestName), manifest)
	mustWrite(t, filepath.Join(data, "modules", "s3_bucket", "main.tf"), []byte("# module source, never copied\n"))

	mf, err := ReadModules(filepath.Join(live, "modules.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range mf.Modules {
		if strings.HasPrefix(e.Dir, ".terraform/modules/") {
			mf.Modules[i].Dir = filepath.ToSlash(filepath.Join(data, "modules", strings.TrimPrefix(e.Dir, ".terraform/modules/")))
		}
	}
	raw, _ := json.Marshal(mf)
	mustWrite(t, filepath.Join(data, "modules", "modules.json"), raw)

	dest := filepath.Join(scratch, "dest")
	if err = Assemble(caseDir, data, dest, host); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFiles(dest)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustRead(t, filepath.Join(live, "modules.json")); !bytes.Equal(got[".terraform/modules/modules.json"], want) {
		t.Errorf("modules.json =\n%s\nwant\n%s", got[".terraform/modules/modules.json"], want)
	}
	if !bytes.Equal(got[".terraform/modules/s3_bucket/"+ManifestName], manifest) {
		t.Error("the manifest was not copied byte for byte")
	}
	if len(got) != 2 {
		t.Errorf("Assemble wrote %d files, want modules.json and one manifest", len(got))
	}

	t.Run("a Dir outside the module cache is refused", func(t *testing.T) {
		outside := t.TempDir()
		bad := ModulesFile{Modules: []ModuleEntry{{Key: "x", Source: host + "/a/b/aws", Version: "1.0.0", Dir: outside}}}
		b, _ := json.Marshal(bad)
		mustWrite(t, filepath.Join(data, "modules", "modules.json"), b)
		if err := Assemble(caseDir, data, filepath.Join(scratch, "dest2"), host); err == nil || !strings.Contains(err.Error(), "outside the module cache") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a symlinked manifest is refused", func(t *testing.T) {
		dir := filepath.Join(data, "modules", "linked")
		mustWrite(t, filepath.Join(scratch, "elsewhere.json"), manifest)
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a test tree
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(scratch, "elsewhere.json"), filepath.Join(dir, ManifestName)); err != nil {
			t.Skip(err)
		}
		bad := ModulesFile{Modules: []ModuleEntry{{Key: "linked", Source: host + "/a/b/aws", Version: "1.0.0", Dir: dir}}}
		b, _ := json.Marshal(bad)
		mustWrite(t, filepath.Join(data, "modules", "modules.json"), b)
		if err := Assemble(caseDir, data, filepath.Join(scratch, "dest4"), host); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("err = %v, want a refused symlink", err)
		}
	})
	t.Run("a fetched module off the pinned host is refused", func(t *testing.T) {
		bad := ModulesFile{Modules: []ModuleEntry{{Key: "x", Source: "git::https://example.com/x.git", Dir: filepath.Join(data, "modules", "s3_bucket")}}}
		b, _ := json.Marshal(bad)
		mustWrite(t, filepath.Join(data, "modules", "modules.json"), b)
		if err := Assemble(caseDir, data, filepath.Join(scratch, "dest3"), host); err == nil {
			t.Error("a git source was assembled")
		}
	})
}

func TestDrift(t *testing.T) {
	a := copyPack(t)
	b := copyPack(t)
	if d, err := Drift(a, b); err != nil || len(d) != 0 {
		t.Fatalf("identical packs drift: %v %v", d, err)
	}
	editPin(t, b, func(p *Pin) { p.RecordedOn = "2026-10-01" })
	if d, _ := Drift(a, b); len(d) != 0 {
		t.Errorf("recorded_on alone is drift: %v", d)
	}
	editPin(t, b, func(p *Pin) { p.TofuVersion = "1.12.6" })
	mustWrite(t, filepath.Join(b, "new.txt"), nil)
	if err := os.Remove(filepath.Join(b, "served-leaf", "expected", "exit-code")); err != nil {
		t.Fatal(err)
	}
	d, _ := Drift(a, b)
	want := []string{"changed: PIN.json", "removed: served-leaf/expected/exit-code", "added:   new.txt"}
	if strings.Join(d, "|") != strings.Join(want, "|") {
		t.Errorf("Drift = %q, want %q", d, want)
	}
}

func TestBuildPinReproducesTheLivePin(t *testing.T) {
	prev, raw, err := ReadPin(filepath.Join(livePack, PinFile))
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildPin(livePack, prev, prev.RegistryHost, prev.TofuVersion, prev.RecordedOn)
	if err != nil {
		t.Fatal(err)
	}
	got, err := built.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("BuildPin does not reproduce the committed PIN.json")
	}
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
