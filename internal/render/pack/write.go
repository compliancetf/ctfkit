package pack

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// ZipName is the file report --out-dir writes the pack to.
const ZipName = "evidence-pack.zip"

// Names of the rendered documents inside the zip.
const (
	FileJSON     = "pack.json"
	FileMarkdown = "pack.md"
)

// schemaJSON is the pack.json schema, shipped inside every zip. It is a copy
// of schema/pack-1.schema.json; a test holds the two byte-identical.
//
//go:embed pack-1.schema.json
var schemaJSON []byte

// zipTime is the modification time of every zip entry, the earliest a zip
// header can hold, so two runs over the same input write the same entries.
var zipTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// checkEntryName refuses a zip entry name that could leave the directory it
// is extracted into or that names one file two ways: an absolute path, a ".."
// or empty segment, a backslash, or any name path.Clean would change. A module
// key from modules.json is part of a manifest's entry name, so this is where
// a hostile key stops.
func checkEntryName(name string) error {
	bad := name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) ||
		path.Clean(name) != name
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			bad = true
		}
	}
	if bad {
		return fmt.Errorf("evidence pack: refusing the zip entry name %q", name)
	}
	return nil
}

// File is one entry of the zip.
type File struct {
	Name string
	Body []byte
}

// Renderer turns a pack into one document of the zip. A renderer reads the
// Pack only, so every document says the same thing.
type Renderer func(p *Pack) (File, error)

// renderers are the documents every zip holds. A new rendering, such as the
// PDF, is one more entry here.
var renderers = []Renderer{RenderJSON, RenderMarkdown}

// RenderJSON renders pack.json: indented JSON with a trailing newline.
func RenderJSON(p *Pack) (File, error) {
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return File{}, fmt.Errorf("evidence pack: %w", err)
	}
	return File{Name: FileJSON, Body: append(body, '\n')}, nil
}

// Documents renders every document of the pack.
func Documents(p *Pack) ([]File, error) {
	out := make([]File, 0, len(renderers))
	for _, render := range renderers {
		f, err := render(p)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// Write writes the zip: the rendered documents and the attachments, sorted
// by name, each stamped with the same fixed time.
func Write(w io.Writer, p *Pack, attachments []File) error {
	docs, err := Documents(p)
	if err != nil {
		return err
	}
	files := append(docs, attachments...) //nolint:gocritic // docs is not used again
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	zw := zip.NewWriter(w)
	for i, f := range files {
		if i > 0 && files[i-1].Name == f.Name {
			return fmt.Errorf("evidence pack: two entries named %s", f.Name)
		}
		if err := checkEntryName(f.Name); err != nil {
			return err
		}
		h := &zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: zipTime}
		h.SetMode(0o644)
		entry, err := zw.CreateHeader(h)
		if err != nil {
			return fmt.Errorf("evidence pack: %w", err)
		}
		if _, err = entry.Write(f.Body); err != nil {
			return fmt.Errorf("evidence pack: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("evidence pack: %w", err)
	}
	return nil
}
