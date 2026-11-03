package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// quotedText matches the backtick-quoted input a YAML decode error carries.
var quotedText = regexp.MustCompile("`[^`]*`")

// ErrNotYAML marks a settings file that does not parse as YAML.
var ErrNotYAML = errors.New("not valid YAML")

// Load loads configuration from a file. A file that cannot be read returns the
// os error as it is, a *fs.PathError; one that does not parse wraps ErrNotYAML.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // Reading config file
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		// A YAML type error quotes the offending text between backticks. Every
		// caller prints this error, so it names the reason and never the file
		// content, which may hold a value the operator did not mean to echo.
		reason := strings.Join(strings.Fields(quotedText.ReplaceAllString(err.Error(), "`...`")), " ")
		return nil, fmt.Errorf("%w (%s)", ErrNotYAML, strings.TrimPrefix(reason, "yaml: "))
	}

	// yaml decodes an absent or null key to nil and a written [] to an empty
	// slice. Only nil takes the defaults; an empty allowed_endpoints or
	// disable_patterns reaches Validate.
	cfg.endpointsSet = cfg.AllowedEndpoints != nil

	// Set defaults for missing values
	cfg.setDefaults()

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Default returns default configuration
func Default() *Config {
	cfg := &Config{}
	cfg.setDefaults()
	return cfg
}

func (c *Config) setDefaults() {
	if c.AllowedEndpoints == nil {
		c.AllowedEndpoints = []string{
			"soc2.compliance.tf",
			"pcidss.compliance.tf",
			"nist.compliance.tf",
			"iso27001.compliance.tf",
			"hipaa.compliance.tf",
			"fedramp.compliance.tf",
			"registry.compliance.tf",
		}
	}

	if c.DisablePatterns == nil {
		c.DisablePatterns = []string{
			"disable_",
			"skip_",
			"ignore_",
			"bypass_",
			"no_",
		}
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if len(c.AllowedEndpoints) == 0 {
		return fmt.Errorf("allowed_endpoints: at least one allowed endpoint must be specified; omit the key to use the defaults")
	}
	if len(c.DisablePatterns) == 0 {
		return fmt.Errorf("disable_patterns: at least one pattern must be specified; omit the key to use the defaults")
	}

	switch c.FailOn {
	case "", "error", "warning", "note", "never":
	default:
		return fmt.Errorf("fail_on is not one of error, warning, note, never; set one of them or remove the key")
	}

	for i, rule := range c.Tags {
		if err := rule.validate(i); err != nil {
			return err
		}
	}
	for i, name := range c.WrappedProviders {
		if !slices.Contains(WrappableProviders, name) {
			return fmt.Errorf("wrapped_providers[%d]: must be one of %s", i, strings.Join(WrappableProviders, ", "))
		}
	}
	for i, key := range c.RequiredTags {
		if key == "" {
			return fmt.Errorf("required_tags[%d]: empty key", i)
		}
	}

	return nil
}

// validate holds a tag rule to the shape ctfkit.TagRule promises an analyzer:
// a key, and at most one value constraint that compiles.
// The rule is named by its index, never by its key or pattern: the settings
// file can come from the repository under analysis, and the RE2 error quotes
// the pattern text.
func (r TagRule) validate(i int) error {
	if r.Key == "" {
		return fmt.Errorf("tags[%d] has no key; add one", i)
	}
	if r.Pattern != "" && len(r.AllowedValues) > 0 {
		return fmt.Errorf("tags[%d] sets both allowed_values and pattern; remove one of them", i)
	}
	if r.Pattern != "" {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("tags[%d].pattern is not valid RE2; fix the pattern", i)
		}
	}
	return nil
}

// Settings resolves the policy keys into what an analyzer reads. required_tags
// entries follow the tags entries as required rules with no value constraint.
func (c *Config) Settings() ctfkit.Settings {
	s := ctfkit.Settings{
		AllowedResources: c.AllowedResources,
		AllowedProviders: c.AllowedProviders,
		WrappedProviders: c.WrappedProviders,
	}
	if c.endpointsSet {
		s.Endpoints = c.AllowedEndpoints
	}
	for _, r := range c.Tags {
		s.Tags = append(s.Tags, ctfkit.TagRule{
			Key:           r.Key,
			Required:      r.Required,
			AllowedValues: r.AllowedValues,
			Pattern:       r.Pattern,
			ResourceTypes: r.ResourceTypes,
		})
	}
	for _, key := range c.RequiredTags {
		s.Tags = append(s.Tags, ctfkit.TagRule{Key: key, Required: true})
	}
	return s
}

// starter is the file ctfkit config init writes. It sets nothing a missing
// file does not: allowed_endpoints stays commented out, because a written list
// replaces "any host ending in .compliance.tf" (see Settings). The keys no
// command reads (fail_on_control_disable, disable_patterns, fail_fast) are
// left out, and Load still accepts them.
const starter = `# ctfkit settings file. Every key is optional.
# Details: docs/configuration.md in the ctfkit repository.

# Registry hosts a module source may name. With the key absent, as here, any
# host ending in .compliance.tf counts, the same as with no settings file.
# ctfkit checks module sources against this list and sends no request to it.
# allowed_endpoints:
#   - soc2.compliance.tf
#   - registry.compliance.tf

# Resource types a configuration may declare. Empty allows every type.
allowed_resources: []

# Exit 1 at or above this level: error (the default), warning, note or never.
# The --fail-on flag and CTFKIT_FAIL_ON take precedence.
# fail_on: error
`

// GenerateDefault writes the starter settings file to path. It refuses an
// existing file, with an error that wraps fs.ErrExist, unless force is set.
// With force it writes a temporary file beside path and renames it over path,
// so a failed run leaves the old file as it was, and a symlink at path is
// replaced while its target stays as it was.
func GenerateDefault(path string, force bool) error {
	var f *os.File
	var err error
	if force {
		f, err = os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp") // mode 0600
	} else {
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the operator's own settings path
	}
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	_, err = f.WriteString(starter)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if force && err == nil {
		err = os.Rename(f.Name(), path)
	}
	if force && err != nil {
		err = errors.Join(err, os.Remove(f.Name()))
	}
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}
