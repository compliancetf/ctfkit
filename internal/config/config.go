package config

// Config is the ctfkit configuration. Field order here is the key order of
// `ctfkit config validate --format json`, which marshals this struct directly.
type Config struct {
	AllowedEndpoints     []string `yaml:"allowed_endpoints" json:"allowed_endpoints"`
	FailOnControlDisable bool     `yaml:"fail_on_control_disable" json:"fail_on_control_disable"`
	AllowedResources     []string `yaml:"allowed_resources" json:"allowed_resources"`
	DisablePatterns      []string `yaml:"disable_patterns" json:"disable_patterns"`
	FailFast             bool     `yaml:"fail_fast" json:"fail_fast"`
	// FailOn is the finding level at or above which a run exits 1:
	// error, warning, note or never. It is the third link of the --fail-on
	// precedence chain (flag, CTFKIT_FAIL_ON, this, then the error default),
	// and it is empty rather than defaulted here so that the command can tell
	// "the file said error" from "the file said nothing".
	FailOn string `yaml:"fail_on" json:"fail_on"`
	// AllowedProviders is the provider allowlist ctf.origin.provider reads:
	// full sources such as registry.terraform.io/hashicorp/aws, namespaces or
	// registry hosts. Empty allows every provider.
	AllowedProviders []string `yaml:"allowed_providers" json:"allowed_providers,omitempty"`
	// WrappedProviders are the provider types compliance.tf wraps here, each
	// one of WrappableProviders. ctfkit verify-lock checks them (default aws),
	// and scan --stage pre_plan runs the same checks when the key is set.
	WrappedProviders []string `yaml:"wrapped_providers" json:"wrapped_providers,omitempty"`
	// Tags is the tagging policy ctf.policy.tagging reads.
	Tags []TagRule `yaml:"tags" json:"tags,omitempty"`
	// RequiredTags is shorthand for Tags entries with required: true and no
	// value constraint, the spelling fixture 08-missing-tags records.
	RequiredTags []string `yaml:"required_tags" json:"required_tags,omitempty"`

	// endpointsSet records whether the file named allowed_endpoints itself.
	// setDefaults refills an absent list, and an analyzer handed the seven
	// shipped endpoints as an allowlist would call every custom org endpoint
	// foreign, so only a list the operator wrote reaches Settings.Endpoints.
	endpointsSet bool
}

// TagRule is one entry of the tags key. It mirrors ctfkit.TagRule with the
// snake_case spelling of the settings file.
type TagRule struct {
	Key           string   `yaml:"key" json:"key"`
	Required      bool     `yaml:"required" json:"required,omitempty"`
	AllowedValues []string `yaml:"allowed_values" json:"allowed_values,omitempty"`
	Pattern       string   `yaml:"pattern" json:"pattern,omitempty"`
	ResourceTypes []string `yaml:"resource_types" json:"resource_types,omitempty"`
}

// WrappableProviders are the provider types compliance.tf ships a wrapper
// for, the values wrapped_providers and verify-lock --provider accept.
var WrappableProviders = []string{"aws", "azurerm", "google"}

// FileName is the settings file every command discovers when --config names
// none. The discovery root is the process working directory.
const FileName = ".ctfkit.yaml"
