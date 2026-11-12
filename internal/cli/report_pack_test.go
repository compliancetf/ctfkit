package cli

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/render/pack"
)

// TestReportEvidencePack is the golden gate of the evidence pack: every
// recorded case run with --out-dir writes evidence-pack.zip, whose pack.md and
// pack.json match expected/pack.md and expected/pack.json, and whose receipt,
// SARIF and PDF are the bytes the same run writes beside it. The PDF has no
// golden; internal/render/pack tests its structure and determinism.
func TestReportEvidencePack(t *testing.T) {
	t.Chdir(goldenRoot(t))
	// A CI runner names the repository it runs in, which the recorded release
	// name must not depend on.
	for _, k := range []string{"GITHUB_RUN_ID", "TF_VAR_spacelift_run_id", "CI_PIPELINE_ID"} {
		t.Setenv(k, "")
	}

	for _, name := range recordedCases(t) {
		if packExempt[name] {
			continue
		}

		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{
				"--path", fixturePath(name),
				"--format", "receipt,sarif",
				"--out-dir", dir,
			}, fixtureContext...)
			if testsJSON := filepath.Join(fixturePath(name), "tests.json"); exists(testsJSON) {
				args = append(args, "--tests-json", testsJSON)
			}

			if _, code := runReport(t, args...); code == ExitEnvironment {
				if rerecording() {
					return
				}
				t.Fatalf("report exited 2")
			}

			entries := readZip(t, filepath.Join(dir, pack.ZipName))
			if rerecording() {
				writeExpected(t, name, pack.FileMarkdown, entries[pack.FileMarkdown])
				writeExpected(t, name, pack.FileJSON, entries[pack.FileJSON])
			}

			expected := filepath.Join("testdata/fixtures/report", name, "expected")
			assertSameBytes(t, pack.FileMarkdown, readFile(t, filepath.Join(expected, pack.FileMarkdown)), entries[pack.FileMarkdown])
			assertSameBytes(t, pack.FileJSON, readFile(t, filepath.Join(expected, pack.FileJSON)), entries[pack.FileJSON])
			assertSameBytes(t, pack.FileReceipt, readFile(t, filepath.Join(dir, fileReceipt)), entries[pack.FileReceipt])
			assertSameBytes(t, pack.FileSARIF, readFile(t, filepath.Join(dir, fileSARIF)), entries[pack.FileSARIF])
			assertSameBytes(t, pack.FilePDF, readFile(t, filepath.Join(dir, pack.FilePDF)), entries[pack.FilePDF])
		})
	}
}

// packExempt are the recorded cases that stop with exit 2 before anything is
// rendered, so they have no pack golden. Every other case must have one.
var packExempt = map[string]bool{"schema-4-stub": true}

// The pack carries the receipt and the SARIF even when --format names
// neither, and a run with no --out-dir writes no pack.
func TestReportEvidencePackFollowsOutDir(t *testing.T) {
	t.Chdir(goldenRoot(t))
	name := "supporting-clauses"

	t.Run("--out-dir with markdown only", func(t *testing.T) {
		dir := t.TempDir()
		args := append([]string{"--path", fixturePath(name), "--out-dir", dir}, fixtureContext...)
		if _, code := runReport(t, args...); code != readExpectedExitCode(t, name) {
			t.Fatalf("exit code = %d, want the recorded one", code)
		}
		entries := readZip(t, filepath.Join(dir, pack.ZipName))
		for _, want := range []string{pack.FileReceipt, pack.FileSARIF, pack.FileSchema, pack.FileJSON, pack.FileMarkdown, pack.FilePDF,
			"manifests/s3_bucket/compliancetf-manifest.json"} {
			if entries[want] == nil {
				t.Errorf("the zip holds no %s", want)
			}
		}
		if exists(filepath.Join(dir, fileReceipt)) || exists(filepath.Join(dir, fileSARIF)) {
			t.Error("--format markdown wrote the receipt or the SARIF beside the pack")
		}
	})

	t.Run("--out writes no pack", func(t *testing.T) {
		dir := t.TempDir()
		args := append([]string{"--path", fixturePath(name), "--out", filepath.Join(dir, "report.md")}, fixtureContext...)
		runReport(t, args...)
		if exists(filepath.Join(dir, pack.ZipName)) || exists(filepath.Join(dir, pack.FilePDF)) {
			t.Error("a run with no --out-dir wrote an evidence pack")
		}
	})
}

// readZip returns every entry of a zip by name.
func readZip(t *testing.T, path string) map[string][]byte {
	t.Helper()
	body := readFile(t, path)
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = b
	}
	return out
}
