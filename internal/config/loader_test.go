package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".ctfkit.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		path      string // set instead of body to load a path that is not a fixture file
		wantErr   string // substring; empty means the load must succeed
		wantCheck func(*testing.T, *Config)
	}{
		{
			name: "minimal file keeps its endpoint and defaults the rest",
			body: "allowed_endpoints:\n  - \"soc2.compliance.tf\"\n",
			wantCheck: func(t *testing.T, c *Config) {
				if want := []string{"soc2.compliance.tf"}; !reflect.DeepEqual(c.AllowedEndpoints, want) {
					t.Errorf("AllowedEndpoints = %v, want %v", c.AllowedEndpoints, want)
				}
				if len(c.DisablePatterns) != 5 {
					t.Errorf("DisablePatterns = %v, want the 5 defaults", c.DisablePatterns)
				}
			},
		},
		{
			name: "every field round trips",
			body: "allowed_endpoints:\n  - \"a.example\"\n" +
				"fail_on_control_disable: true\n" +
				"allowed_resources:\n  - \"aws_s3_bucket\"\n" +
				"disable_patterns:\n  - \"nope_\"\n" +
				"fail_fast: true\n",
			wantCheck: func(t *testing.T, c *Config) {
				want := Config{
					AllowedEndpoints:     []string{"a.example"},
					FailOnControlDisable: true,
					AllowedResources:     []string{"aws_s3_bucket"},
					DisablePatterns:      []string{"nope_"},
					FailFast:             true,
					endpointsSet:         true,
				}
				if !reflect.DeepEqual(*c, want) {
					t.Errorf("Load() = %+v, want %+v", *c, want)
				}
			},
		},
		{
			name: "empty file falls back to defaults entirely",
			body: "",
			wantCheck: func(t *testing.T, c *Config) {
				if !reflect.DeepEqual(c, Default()) {
					t.Errorf("Load() = %+v, want the default config %+v", c, Default())
				}
			},
		},
		{
			name:    "wrapped_providers outside the wrappable types",
			body:    "wrapped_providers:\n  - aws\n  - random\n",
			wantErr: "wrapped_providers[1]: must be one of aws, azurerm, google",
		},
		{
			name: "wrapped_providers reaches the settings",
			body: "wrapped_providers:\n  - google\n",
			wantCheck: func(t *testing.T, c *Config) {
				if got := c.Settings().WrappedProviders; !reflect.DeepEqual(got, []string{"google"}) {
					t.Errorf("Settings().WrappedProviders = %v, want [google]", got)
				}
			},
		},
		{
			name:    "missing file",
			path:    filepath.Join(t.TempDir(), "does-not-exist.yaml"),
			wantErr: "does-not-exist.yaml",
		},
		{
			name:    "directory instead of a file",
			path:    t.TempDir(),
			wantErr: "TestLoad",
		},
		{
			name:    "malformed YAML",
			body:    "allowed_endpoints:\n  - \"unterminated\n\tbad indent\n",
			wantErr: "not valid YAML (line ",
		},
		{
			name:    "YAML of the wrong shape for the struct",
			body:    "allowed_endpoints: \"not-a-list\"\n",
			wantErr: "not valid YAML (",
		},
		{
			name: "unknown keys are ignored",
			body: "allowed_endpoints:\n  - \"soc2.compliance.tf\"\nnot_a_real_key: 42\n",
			wantCheck: func(t *testing.T, c *Config) {
				if len(c.AllowedEndpoints) != 1 {
					t.Errorf("AllowedEndpoints = %v, want the one from the file", c.AllowedEndpoints)
				}
			},
		},
		{
			// policy_engine was removed. The loader never opted
			// into yaml.KnownFields, so an existing config still carrying the
			// key keeps loading rather than breaking on upgrade.
			name: "the legacy policy_engine key is ignored",
			body: "allowed_endpoints:\n  - \"soc2.compliance.tf\"\npolicy_engine: \"nonsense\"\n",
			wantCheck: func(t *testing.T, c *Config) {
				if len(c.AllowedEndpoints) != 1 || c.AllowedEndpoints[0] != "soc2.compliance.tf" {
					t.Errorf("AllowedEndpoints = %v, want [soc2.compliance.tf]", c.AllowedEndpoints)
				}
			},
		},
		{
			// An empty list is what the file says, so it is never swapped for
			// the defaults. It allows nothing, which Validate rejects.
			name:    "an explicitly empty allowlist is rejected",
			body:    "allowed_endpoints: []\n",
			wantErr: "at least one allowed endpoint",
		},
		{
			// The same rule for disable_patterns: a written [] is never
			// swapped for the defaults, and matching nothing is rejected.
			name:    "an explicitly empty disable_patterns is rejected",
			body:    "disable_patterns: []\n",
			wantErr: "disable_patterns: at least one pattern must be specified; omit the key to use the defaults",
		},
		{
			name: "a null disable_patterns takes the defaults",
			body: "disable_patterns:\n",
			wantCheck: func(t *testing.T, c *Config) {
				if len(c.DisablePatterns) != 5 {
					t.Errorf("DisablePatterns = %v, want the 5 defaults", c.DisablePatterns)
				}
			},
		},
		{
			// A key with no value decodes to nil, the same as an absent key.
			name: "a null allowlist takes the defaults",
			body: "allowed_endpoints:\n",
			wantCheck: func(t *testing.T, c *Config) {
				if len(c.AllowedEndpoints) != 7 {
					t.Errorf("AllowedEndpoints = %v, want the 7 defaults", c.AllowedEndpoints)
				}
				if c.Settings().Endpoints != nil {
					t.Errorf("Settings().Endpoints = %v, want nil for an unwritten list", c.Settings().Endpoints)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if path == "" {
				path = writeConfig(t, tt.body)
			}

			cfg, err := Load(path)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Load() succeeded, want an error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Load() error = %q, want it to contain %q", err, tt.wantErr)
				}
				if cfg != nil {
					t.Errorf("Load() returned a config alongside an error: %+v", cfg)
				}
				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg == nil {
				t.Fatal("Load() returned a nil config and no error")
			}
			tt.wantCheck(t, cfg)
		})
	}
}

// Validate's only allowlist error is what an operator who writes
// allowed_endpoints: [] sees through Load, and a hand-built Config gets the
// same answer.
func TestValidateRejectsAnEmptyAllowlist(t *testing.T) {
	err := (&Config{}).Validate()
	if err == nil {
		t.Fatal("Validate() on a config with no endpoints succeeded")
	}
	if !strings.Contains(err.Error(), "at least one allowed endpoint") {
		t.Errorf("Validate() error = %q", err)
	}

	err = (&Config{AllowedEndpoints: []string{"soc2.compliance.tf"}}).Validate()
	if err == nil || !strings.Contains(err.Error(), "disable_patterns: at least one pattern") {
		t.Errorf("Validate() with no disable patterns = %v, want the disable_patterns error", err)
	}

	if err := Default().Validate(); err != nil {
		t.Errorf("Validate() on the default config = %v, want nil", err)
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()

	if len(cfg.AllowedEndpoints) != 7 {
		t.Errorf("AllowedEndpoints = %v, want 7 endpoints", cfg.AllowedEndpoints)
	}
	if len(cfg.DisablePatterns) != 5 {
		t.Errorf("DisablePatterns = %v, want 5 patterns", cfg.DisablePatterns)
	}
	if cfg.FailOnControlDisable || cfg.FailFast {
		t.Errorf("the default config opts into behavior it should not: %+v", cfg)
	}
	if cfg.AllowedResources != nil {
		t.Errorf("AllowedResources = %v, want nil so that every resource type is allowed", cfg.AllowedResources)
	}
}

func TestSetDefaultsLeavesSuppliedValuesAlone(t *testing.T) {
	cfg := &Config{
		AllowedEndpoints: []string{"only.example"},
		DisablePatterns:  []string{"only_"},
	}
	cfg.setDefaults()

	if want := []string{"only.example"}; !reflect.DeepEqual(cfg.AllowedEndpoints, want) {
		t.Errorf("AllowedEndpoints = %v, want %v", cfg.AllowedEndpoints, want)
	}
	if want := []string{"only_"}; !reflect.DeepEqual(cfg.DisablePatterns, want) {
		t.Errorf("DisablePatterns = %v, want %v", cfg.DisablePatterns, want)
	}
}

// The generated file is the one most users start from, so it has to be a file
// this same loader accepts, and one that sets nothing a missing file does not.
func TestGenerateDefaultRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ctfkit.yaml")
	if err := GenerateDefault(path, false); err != nil {
		t.Fatalf("GenerateDefault() error = %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if !strings.HasPrefix(string(data), "# ctfkit settings file") {
		t.Errorf("generated config lost its header comment:\n%s", data)
	}
	for _, key := range []string{"policy_engine", "fail_on_control_disable", "disable_patterns", "fail_fast"} {
		if strings.Contains(string(data), key) {
			t.Errorf("generated config writes %s, which no command reads:\n%s", key, data)
		}
	}
	if !strings.Contains(string(data), "\n# allowed_endpoints:\n") {
		t.Errorf("generated config does not carry allowed_endpoints commented out:\n%s", data)
	}
	for i, b := range data {
		if b > 0x7f {
			t.Fatalf("generated config has a non-ASCII byte at %d:\n%s", i, data)
		}
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("the generated config does not load: %v", err)
	}
	if got := loaded.Settings(); got.Endpoints != nil || len(got.AllowedResources) != 0 || loaded.FailOn != "" {
		t.Errorf("the generated config sets what a missing file does not: %+v, fail_on %q", got, loaded.FailOn)
	}
}

// config init refuses to replace a file unless force is set.
func TestGenerateDefaultRefusesAnExistingFile(t *testing.T) {
	path := writeConfig(t, "fail_on: warning\n")
	err := GenerateDefault(path, false)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("GenerateDefault() over a file = %v, want fs.ErrExist", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "fail_on: warning\n" { //nolint:gosec // test-controlled temp path
		t.Errorf("the refused write changed the file:\n%s", data)
	}

	if err = GenerateDefault(path, true); err != nil {
		t.Fatalf("GenerateDefault(force) = %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != starter { //nolint:gosec // test-controlled temp path
		t.Errorf("force did not replace the file:\n%s", data)
	}
}

// --force replaces the path itself: a symlink there becomes a regular 0600
// file and its target is left as it was.
func TestGenerateDefaultForceReplacesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, []byte("fail_on: warning\n"), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".ctfkit.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := GenerateDefault(path, true); err != nil {
		t.Fatalf("GenerateDefault(force) = %v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "fail_on: warning\n" { //nolint:gosec // test-controlled temp path
		t.Errorf("--force wrote through the symlink:\n%s", data)
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Errorf("%s is %v (%v), want a regular 0600 file", path, st.Mode(), err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("--force left %d entries in the directory, want 2 (no temp file)", len(entries))
	}
}

func TestGenerateDefaultReportsAWriteFailure(t *testing.T) {
	// A path under a file rather than a directory: the write cannot succeed.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	err := GenerateDefault(filepath.Join(blocker, ".ctfkit.yaml"), false)
	if err == nil {
		t.Fatal("GenerateDefault() succeeded writing into a non-directory")
	}
	if !strings.Contains(err.Error(), "failed to write config file") {
		t.Errorf("GenerateDefault() error = %q", err)
	}
}

func TestSettingsResolvesPolicyKeys(t *testing.T) {
	cfg, err := Load(writeConfig(t, `allowed_providers: [registry.terraform.io/hashicorp/aws]
allowed_resources: [aws_s3_bucket]
tags:
  - key: Owner
    required: true
    resource_types: [aws_s3_bucket]
  - key: CostCentre
    pattern: "^CC-[0-9]{4}$"
required_tags: [Environment]
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	got := cfg.Settings()
	want := ctfkit.Settings{
		AllowedResources: []string{"aws_s3_bucket"},
		AllowedProviders: []string{"registry.terraform.io/hashicorp/aws"},
		Tags: []ctfkit.TagRule{
			{Key: "Owner", Required: true, ResourceTypes: []string{"aws_s3_bucket"}},
			{Key: "CostCentre", Pattern: "^CC-[0-9]{4}$"},
			{Key: "Environment", Required: true},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Settings() = %+v, want %+v", got, want)
	}
}

// The defaults setDefaults fills in are the legacy validator's list, not a
// policy the operator wrote, so they never reach an analyzer as an allowlist.
func TestSettingsEndpointsOnlyWhenWritten(t *testing.T) {
	if got := Default().Settings().Endpoints; got != nil {
		t.Errorf("default Settings().Endpoints = %v, want nil", got)
	}
	cfg, err := Load(writeConfig(t, "allowed_endpoints: [bobthecorp.compliance.tf]\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Settings().Endpoints; !reflect.DeepEqual(got, []string{"bobthecorp.compliance.tf"}) {
		t.Errorf("Settings().Endpoints = %v, want the written list", got)
	}
}

func TestTagRulesRejected(t *testing.T) {
	for name, body := range map[string]string{
		"missing key":        "tags:\n  - required: true\n",
		"values and pattern": "tags:\n  - key: A\n    allowed_values: [x]\n    pattern: x\n",
		"invalid RE2":        "tags:\n  - key: A\n    pattern: \"(?<=x)\"\n",
		"empty required_tag": "required_tags: [\"\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Errorf("Load() accepted %q", body)
			}
		})
	}
}

// A decode error never echoes the file's text.
func TestParseErrorMasksContent(t *testing.T) {
	_, err := Load(writeConfig(t, "allowed_endpoints: \"secret-looking-value\"\n"))
	if err == nil || strings.Contains(err.Error(), "secret-looking-value") {
		t.Errorf("Load() error = %v, want a parse error without the file content", err)
	}
}
