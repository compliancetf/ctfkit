package ctfkit

import (
	"time"

	tfjson "github.com/hashicorp/terraform-json"
)

// AnalyzerInput is everything an analyzer is allowed to see. A loader or an
// adapter builds it; the analyzer only reads it and never mutates it.
//
// Which fields carry a value depends on the stage the invocation runs at,
// which Stage names. The per-stage table in the package documentation is the
// contract; a loader honors it and an analyzer may assume it. An analyzer
// that reads a field its own stage does not populate is a bug in the analyzer,
// so each implementation guards the pointers it uses.
type AnalyzerInput struct {
	// Stage is the stage this invocation runs at. It equals the Stage of every
	// analyzer the runner selected for it, and it is the value that goes into
	// the ctf.stage property of a finding.
	Stage Stage
	// Config is the parsed configuration of the root module and its module
	// graph.
	Config *ConfigArchive
	// Modules is the inventory read from .terraform/modules. It is set from
	// post_init onwards and nil before it.
	Modules *ModuleInventory
	// PlanJSON is the plan in Terraform JSON form. It is set from post_plan
	// onwards and nil before it.
	PlanJSON *tfjson.Plan
	// State is the state in Terraform JSON form. It is set at post_apply only.
	State *tfjson.State
	// Catalog answers which controls apply to a resource type, which module
	// covers it, and how controls map to framework clauses. It is a preloaded
	// immutable snapshot and is never nil; a run with no catalog file is given
	// the release catalog embedded in the binary.
	Catalog ControlCatalog
	// Settings are the policy inputs the settings file supplied, already
	// resolved by the loader.
	Settings Settings
	// Metadata describes the run itself and is copied into finding evidence.
	Metadata RunMetadata
}

// Settings are the recorded settings-file keys an analyzer may read. The
// loader resolves precedence and defaults before an analyzer sees them, so
// each field holds the value that was in force, and the run object records it.
//
// The settings file is an input of the repository under analysis. It supplies
// policy inputs and may suppress findings; it can never add or change a
// control id, a rule id, remediation or the remediation host. Those come from
// the catalog alone.
type Settings struct {
	// Endpoints is the allowlist of module registry endpoints a module source
	// may come from. Empty means the analyzer falls back to its own
	// classification of compliance.tf endpoints.
	Endpoints []string
	// AllowedResources is the allowlist of resource types a configuration may
	// declare or plan. Empty means every type is allowed.
	AllowedResources []string
	// AllowedProviders is the allowed_providers settings key: the allowlist
	// of provider sources a configuration may use. An entry is a full source such as
	// "registry.terraform.io/hashicorp/aws", a namespace such as
	// "registry.terraform.io/hashicorp", or a registry host. Empty means every
	// provider is allowed.
	//
	// Additive field, v0.x: added after Settings shipped.
	AllowedProviders []string
	// WrappedProviders are the provider types compliance.tf wraps in this
	// estate (aws, azurerm, google): the wrapped_providers settings key, or
	// the --provider flags of verify-lock. The ctf.lock rules read it. Empty
	// means they report nothing.
	//
	// Additive field, v0.x: added after Settings shipped.
	WrappedProviders []string
	// Tags are the tag rules every matching resource must satisfy. Empty means
	// the tagging analyzer reports nothing.
	Tags []TagRule
}

// TagRule is one tag the settings file asks for: the key, optionally what its
// value may be, and optionally which resource types it applies to.
//
// AllowedValues and Pattern are mutually exclusive; a rule sets one, or
// neither when any value will do. The loader rejects a rule that sets both and
// rejects a Pattern that does not compile, so an analyzer never has to decide
// what a broken rule means.
type TagRule struct {
	// Key is the tag key the rule is about.
	Key string
	// Required is whether the key must be present. A rule that is not
	// required constrains the value only where the tag is set, which is how an
	// optional tag with a controlled vocabulary is expressed.
	Required bool
	// AllowedValues is the closed set the value must come from. Empty means
	// the rule does not constrain the value this way.
	AllowedValues []string
	// Pattern is an RE2 regular expression the value must match, in the syntax
	// of the standard library regexp package. Empty means the rule does not
	// constrain the value this way.
	Pattern string
	// ResourceTypes limits the rule to these Terraform resource types. Empty
	// means every taggable resource.
	ResourceTypes []string
}

// ConfigArchive is the parsed configuration an analyzer reads at every stage.
//
// v0.x holds the root path, the raw bytes of each configuration file and the
// dependency lock file. The typed module graph is added here by the loader;
// adding fields to this struct is an additive change under the stability
// policy.
type ConfigArchive struct {
	// Root is the directory passed to the command, as given by the caller.
	Root string
	// Files are the configuration files found under Root, in a stable order.
	Files []ConfigFile
	// Lockfile is the parsed dependency lock file of the root module. It is
	// nil when the configuration has none, which is itself reportable: an
	// unlocked provider is an unpinned dependency.
	Lockfile *Lockfile
	// ClassifyModules asks the analyzers to tell the reusable module
	// directories under Root from its deployable roots, from the configuration
	// alone, and to apply root-only rules to the roots. The command sets it
	// when it read a whole directory tree and never for an explicit file list.
	// The zero value keeps what every analyzer did before the field existed:
	// each directory is analyzed as it stands.
	//
	// Additive field, v0.x: added after ConfigArchive shipped. A keyed
	// composite literal keeps compiling; an unkeyed one does not.
	ClassifyModules bool
	// Lockfiles are the dependency lock files of the deployable roots under
	// Root, keyed by archive-relative directory ("." for Root). A root with no
	// lock file has no key. Nil when the command did not read them; the
	// analyzers then know the lock file of Root only, as Lockfile.
	//
	// Additive field, v0.x: added after ConfigArchive shipped.
	Lockfiles map[string]*Lockfile
	// LocalModules are the "./" and "../" local modules the configuration
	// calls that the walk did not read (outside Root, or in a directory it
	// skips), transitively, read at pre_plan for a directory scan. Nil for a file list and at every other stage,
	// where the module inventory carries them instead.
	//
	// Additive field, v0.x: added after ConfigArchive shipped.
	LocalModules []LocalModule
	// LocalCalls are the "./" and "../" module calls of a directory scan,
	// each resolved the way init resolves it, so an analyzer can give a
	// module directory the address Terraform gives it without joining
	// source text itself. Nil when LocalModules is.
	//
	// Additive field, v0.x: added after ConfigArchive shipped.
	LocalCalls []LocalCall
	// Partial marks the archive as an operator-chosen subset of a
	// configuration, such as the file list a pre-commit hook passes. A local
	// module call to a directory the archive does not carry is then outside
	// that subset and not a finding. The zero value is a complete archive, so
	// an SDK caller that builds one with default settings keeps the
	// ctf.exec.module_uninspected report of such a call.
	//
	// Additive field, v0.x: added after ConfigArchive shipped.
	Partial bool
}

// LocalCall is one "./" or "../" module call a directory scan resolved.
//
// Additive type, v0.x: reachable only through ConfigArchive.LocalCalls.
type LocalCall struct {
	// From is the directory of the file that holds the module block,
	// relative to Root, POSIX separated, "." for Root itself.
	From string
	// Name is the module call name, the label of the module block.
	Name string
	// To is the called directory relative to Root with its symlinks
	// resolved, as LocalModule.Dir and the files' paths name it; for a
	// directory that does not exist, the joined path unresolved.
	To string
}

// ConfigFile is one configuration file and its exact bytes.
type ConfigFile struct {
	// Path is relative to ConfigArchive.Root, POSIX separated.
	Path string
	// Bytes is the file as read, unmodified.
	Bytes []byte
}

// Lockfile is the typed subset of .terraform.lock.hcl that analyzers read. The
// loader parses the file; this package defines the shape only.
type Lockfile struct {
	// Providers are the locked providers, in the order the file lists them.
	Providers []LockedProvider
}

// LockedProvider is one provider block of the dependency lock file.
type LockedProvider struct {
	// Source is the fully qualified provider source, for example
	// "registry.terraform.io/hashicorp/aws".
	Source string
	// Version is the exact version the lock file pinned.
	Version string
	// Constraints is the version constraint the configuration asked for, empty
	// when the lock file records none.
	Constraints string
	// Hashes are the recorded package hashes, in file order. An empty list
	// means the lock file pinned a version without recording a hash, which is
	// a weaker pin than it looks.
	Hashes []string
}

// RunMetadata describes the run an analyzer is part of. It carries no
// credentials and nothing customer-identifying beyond what the customer's own
// CI already knows.
type RunMetadata struct {
	// RunID is the platform's identifier for this run, empty when unknown.
	RunID string
	// Platform names the runner, for example "github-actions" or "spacelift".
	Platform string
	// Workspace is the workspace, stack or project name, empty when unknown.
	Workspace string
	// Commit is the full commit SHA of the configuration under analysis.
	Commit string
	// Actor is the identity that triggered the run, empty when unknown.
	Actor string
	// Frameworks are the framework ids the run reports against, for example
	// "soc_2". Empty means framework agnostic.
	Frameworks []string
	// Now is the run clock, and it is UTC: the runner converts before setting
	// it, and everything that reads it may assume so. It is the only clock in
	// the contract. Analyzers and exception validity read it and never call
	// time.Now, so a run over recorded input produces the same findings on any
	// day, which is what lets a fixture be an oracle, and it is what the
	// evidence receipt records as the run time.
	Now time.Time
}

// ModuleInventory is what .terraform/modules holds after init.
type ModuleInventory struct {
	// Root is the path passed to the command, the same value as
	// ConfigArchive.Root.
	Root string
	// Instances are the module instances from modules.json. Keys under the
	// "test." prefix are excluded by the loader, because a test harness module
	// is not part of the configuration under analysis.
	Instances []ModuleInstance
	// Tests is the imported `tofu test -json` or `terraform test -json`
	// document for this root, nil when the operator imported none. ctfkit
	// never runs tofu or terraform, so this is only ever a file the caller
	// produced and named.
	//
	// Additive field, v0.x: added after ModuleInventory shipped, and a reader
	// written against the earlier shape keeps compiling.
	Tests *TestRun
}

// TestRun is an imported `tofu test -json` or `terraform test -json` document,
// summarized. It records what the test runner reported and nothing else: the
// loader counts, it never decides whether a run covers a resource.
//
// Additive type, v0.x: added after the contract shipped, reachable only
// through ModuleInventory.Tests.
type TestRun struct {
	// File is the path the document was read from, exactly as the operator
	// named it.
	File string
	// SHA256 is the lowercase hex digest of the exact bytes that were read,
	// not of a re-serialization of the parsed events.
	SHA256 string
	// Runs is the number of run blocks the document reports a result for.
	Runs int
	// Passed, Failed, Errored and Skipped are the run counts by status, as
	// the runner's own summary reported them.
	Passed  int
	Failed  int
	Errored int
	Skipped int
	// Cases are the individual run blocks, in the order the document lists
	// them.
	Cases []TestCase
}

// TestCase is one run block of an imported test document.
//
// Additive type, v0.x: added after the contract shipped, reachable only
// through TestRun.Cases.
type TestCase struct {
	// Name is the run block name, for example "archive_bucket_is_planned".
	Name string
	// Status is the status the runner reported, for example "pass", "fail",
	// "error" or "skip". It is the runner's own string, not a ctfkit
	// vocabulary.
	Status string
	// ModuleKey is the module call key the run block exercises, empty when
	// the document carries none. A test runner is not required to report it.
	ModuleKey string
}

// ModuleInstance is one entry of modules.json plus the manifest found in its
// directory, when there is one.
type ModuleInstance struct {
	// Key is the module call key from modules.json, for example
	// "s3_bucket.notification".
	Key string
	// Source is the source string exactly as written in the configuration.
	Source string
	// Dir is the directory the module was installed into, relative to Root.
	Dir string
	// Manifest is the parsed compliancetf-manifest.json from Dir. It is nil
	// when the instance has no manifest, which is a reportable finding rather
	// than an error.
	Manifest *Manifest
	// ManifestSHA256 is the lowercase hex digest of the exact manifest bytes
	// that were read, empty when Manifest is nil. It digests the bytes on
	// disk, not a re-serialization of the parsed value.
	ManifestSHA256 string
	// Provenance states how far the manifest has been verified. Open source
	// output is always "local-unverified": the file was read from disk and
	// nothing countersigned it. A hosted tier may raise it after a
	// countersignature.
	Provenance string
	// DeclaresNoResources is true when the loader read the configuration
	// files directly in Dir and found no resource block: a helper module of
	// data sources, locals and outputs that creates nothing. Subdirectories
	// are not read, because a child module is its own instance. False means
	// the module declares resources or the loader could not tell, so the zero
	// value never hides an instance.
	//
	// Additive field, v0.x: added after ModuleInstance shipped, and a reader
	// written against the earlier shape keeps compiling.
	DeclaresNoResources bool
	// Files are the configuration files directly in Dir (.tf, .tf.json,
	// .tofu and .tofu.json, override files included), in path order, with
	// Path relative to Root, for example ".terraform/modules/vpc/main.tf" or,
	// for a "../shared" local module, "../shared/main.tf". Subdirectories are
	// not read: a child module is its own instance. A directory that does not
	// resolve or cannot be listed is a loader error, never an empty Files.
	//
	// Additive field, v0.x: added after ModuleInstance shipped.
	Files []ConfigFile
}

// LocalModule is a "./" or "../" local module a configuration calls that the
// configuration walk did not read, because its directory lies outside
// ConfigArchive.Root or in a directory the walk skips. It is read at pre_plan
// so that code is inspected as code in Root is.
//
// Additive type, v0.x: reachable only through ConfigArchive.LocalModules.
type LocalModule struct {
	// Dir is the module directory relative to Root, POSIX separated, with its
	// symlinks resolved, for example "../shared".
	Dir string
	// Files are the configuration files directly in Dir, in path order, with
	// Path relative to Root, for example "../shared/main.tf". Nil when Unread.
	Files []ConfigFile
	// Unread is true when Dir, a "../" directory, does not exist: scan runs
	// before init, so it is reported rather than refused. Nothing in it was
	// inspected.
	Unread bool
}

// ProvenanceLocalUnverified is the only provenance value open source ctfkit
// emits. The manifest was read from the local module directory and no party
// has attested to it.
const ProvenanceLocalUnverified = "local-unverified"

// Manifest is the typed subset of the compliance manifest, schema 3.x, that
// analyzers read. Fields the schema defines but no analyzer uses are omitted
// deliberately, and unknown fields in the document are ignored, so an additive
// minor bump of the manifest schema needs no change here. A new major is
// refused by the loader.
type Manifest struct {
	// SchemaVersion is the manifest schema version, for example "3.3". The
	// loader gates on its major component.
	SchemaVersion string `json:"schema_version"`
	// ControlsScope is "package", "subtree" or "package-fallback". Only a
	// package-scope manifest carries ManifestSetHash and the build-level
	// not-applicable and superseded sets.
	ControlsScope string `json:"controls_scope"`
	// ScopePath is the package-root-relative POSIX path of the directory this
	// manifest governs. The package root is ".". It is the value that a
	// control's AppliesIn entries refer to.
	ScopePath string `json:"scope_path"`
	// Module identifies the served build this manifest came from.
	Module ManifestModule `json:"module"`
	// Controls are the controls this manifest lists for its own scope.
	Controls []ManifestControl `json:"controls"`
	// Build carries the build-level control classification.
	Build ManifestBuild `json:"build"`
	// OperationalRules are the operational rules applied to the package. They
	// are package scoped at every manifest; they cannot be attributed to a
	// subtree.
	OperationalRules []ManifestOperationalRule `json:"operational_rules"`
	// Posture carries the org posture that was in force for the build.
	Posture ManifestPosture `json:"posture"`
	// Scope carries what this document explicitly does not prove.
	Scope ManifestScope `json:"scope"`
	// ChildManifests name each immediately governed child manifest.
	ChildManifests []ManifestChild `json:"child_manifests"`
	// ManifestSetHash is the SHA-256 over every manifest in the artifact,
	// present on package-scope manifests only. It detects staleness and
	// partial replacement. It is unsigned and is not an attestation.
	ManifestSetHash string `json:"manifest_set_hash"`
}

// ManifestModule identifies the served build a manifest describes.
type ManifestModule struct {
	// RegistrySource is the compliance.tf source the module was served from.
	RegistrySource string `json:"registry_source"`
	// Version is the served version of the module.
	Version string `json:"version"`
	// UpstreamSource is the terraform-aws-modules source it was built from.
	UpstreamSource string `json:"upstream_source"`
	// UpstreamVersion is the upstream version it was built from.
	UpstreamVersion string `json:"upstream_version"`
	// Frameworks are the framework ids the build enforced controls for.
	Frameworks []string `json:"frameworks"`
	// FrameworkNames maps a framework id in Frameworks to its display name
	// (manifest schema 3.x records an object, e.g. {"soc_2": "SOC 2"}).
	FrameworkNames map[string]string `json:"framework_names"`
}

// ManifestControl is one control entry of a manifest.
type ManifestControl struct {
	// ControlID is the catalog control id, the join key across prevent,
	// detect and evidence.
	ControlID string `json:"control_id"`
	// Name is the human readable control name.
	Name string `json:"name"`
	// Status is "enforced" when this manifest's own files hold the control's
	// evidence, or "delegated" when every file the control changed is governed
	// by another scope named in AppliesIn.
	Status string `json:"status"`
	// AppliesIn lists every scope path where this control has files. "." is
	// the package root; an empty slice means the control changed no files
	// anywhere.
	AppliesIn []string `json:"applies_in"`
	// FilesModified are the paths this manifest governs for this control. It
	// may be empty at package scope when all the files live in children.
	FilesModified []string `json:"files_modified"`
	// ClausesByFramework maps a framework id to the clauses this control
	// satisfies in it.
	ClausesByFramework map[string][]string `json:"clauses_by_framework"`
	// SupportingClausesByFramework (manifest schema 3.4) is, per framework,
	// the subset of ClausesByFramework the catalog curation marked as
	// supporting: partial or indirect evidence, never full enforcement. It is
	// tri-state: nil means the producer did not classify (a manifest before
	// 3.4), which is unknown and never "nothing hedged"; an empty list for a
	// framework means it classified and hedged nothing there.
	SupportingClausesByFramework map[string][]string `json:"supporting_clauses_by_framework"`
}

// ManifestControlStatus values used by ManifestControl.Status.
const (
	// ManifestControlEnforced means this manifest's files hold the evidence.
	ManifestControlEnforced = "enforced"
	// ManifestControlDelegated means another scope holds the evidence.
	ManifestControlDelegated = "delegated"
)

// ManifestBuild carries the build-level control classification. Both fields
// are tri-state: nil means the producer never classified, an empty value means
// it classified and found none.
type ManifestBuild struct {
	// ControlsNotApplicable are control ids the build evaluated and found no
	// resource of their target type for.
	ControlsNotApplicable []string `json:"controls_not_applicable"`
	// ControlsSuperseded maps a weaker control id to the stricter control id
	// that replaced it.
	ControlsSuperseded map[string]string `json:"controls_superseded"`
}

// ManifestOperationalRule is one operational rule applied to the package.
type ManifestOperationalRule struct {
	// Rule is the rule id, for example "example/prevent_destroy_data".
	Rule string `json:"rule"`
	// Outcome is what the rule did on this build.
	Outcome string `json:"outcome"`
	// Ruleset names the org ruleset that selected this rule, nil for a
	// baseline rule.
	Ruleset *ManifestRuleset `json:"ruleset"`
}

// ManifestRuleset binds an operational rule to the content-hashed org bundle
// that selected it.
type ManifestRuleset struct {
	// Name is the ruleset name as requested on the module call.
	Name string `json:"name"`
	// ContentHash is the hash of the ruleset content the producer used.
	ContentHash string `json:"content_hash"`
}

// ManifestPosture carries the org posture in force for the build.
type ManifestPosture struct {
	// Degraded lists the reasons the full org posture could not be applied.
	// It is tri-state: nil means the producer never reported, an empty slice
	// means it reported nothing dropped.
	Degraded []string `json:"degraded"`
}

// ManifestScope carries what a manifest explicitly does not prove.
type ManifestScope struct {
	// DoesNotProve are the machine-readable obligation tokens. A token this
	// build of ctfkit does not know is reported to the reader, never fatal.
	DoesNotProve []ManifestObligation `json:"does_not_prove"`
}

// ManifestObligation is one does-not-prove token and the prose that goes with
// it.
type ManifestObligation struct {
	// Token is the machine-readable token, for example
	// "evaluation_record_partial".
	Token string `json:"token"`
	// Statement is what the manifest does not assert.
	Statement string `json:"statement"`
	// ConsumerObligation is what the consumer must do instead.
	ConsumerObligation string `json:"consumer_obligation"`
}

// ManifestChild names one immediately governed child manifest.
type ManifestChild struct {
	// ScopePath is the child's scope path.
	ScopePath string `json:"scope_path"`
	// SHA256 is the lowercase hex digest of the child manifest bytes.
	SHA256 string `json:"sha256"`
}
