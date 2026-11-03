package parser

import (
	"path"
	"strings"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// configExts are the configuration file extensions, longest first so that
// main.tf.json strips to "main" and not "main.tf".
var configExts = []string{".tofu.json", ".tf.json", ".tofu", ".tf"}

// configExt is the configuration extension of name, empty for any other file.
func configExt(name string) string {
	for _, ext := range configExts {
		if strings.HasSuffix(name, ext) {
			return ext
		}
	}
	return ""
}

// IsOverrideFile reports whether name is an override file: its base name,
// without the configuration extension, is "override" or ends in "_override".
// An override file changes blocks the primary files declare and never
// declares one of its own. The rule is the same in Terraform and OpenTofu:
// isOverride := baseName == "override" || strings.HasSuffix(baseName,
// "_override") (hashicorp/terraform internal/configs/parser_file_matcher.go
// at db4eef44; opentofu/opentofu internal/configs/parser_config_dir.go
// dirFiles at a7af95c1).
func IsOverrideFile(name string) bool {
	name = path.Base(name)
	ext := configExt(name)
	if ext == "" {
		return false
	}
	base := strings.TrimSuffix(name, ext)
	return base == "override" || strings.HasSuffix(base, "_override")
}

// PrimaryFiles are the files that declare the configuration, in their
// original order: every configuration file but the override files, and but a
// .tf or .tf.json file whose .tofu or .tofu.json twin sits in the same
// directory. OpenTofu reads the twin and ignores the .tf copy
// (filterTfPathsWithTofuAlternatives in opentofu/opentofu
// internal/configs/parser_config_dir.go at a7af95c1: main.tf gives way to
// main.tofu, main.tf.json to main.tofu.json). Terraform never reads a .tofu
// file, so under Terraform the .tf copy is the one read. ctfkit cannot tell
// which binary will run the configuration, and taking OpenTofu's reading when
// twins exist is a design decision, not a fact about Terraform. For twins that
// declare the same blocks the two readings agree.
//
// Files that are not configuration pass through unchanged.
func PrimaryFiles(files []ctfkit.ConfigFile) []ctfkit.ConfigFile {
	present := make(map[string]bool, len(files))
	for _, f := range files {
		present[f.Path] = true
	}
	out := make([]ctfkit.ConfigFile, 0, len(files))
	for _, f := range files {
		if IsOverrideFile(f.Path) {
			continue
		}
		switch ext := configExt(f.Path); ext {
		case ".tf", ".tf.json":
			twin := strings.TrimSuffix(f.Path, ext) + strings.Replace(ext, ".tf", ".tofu", 1)
			if present[twin] {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}
