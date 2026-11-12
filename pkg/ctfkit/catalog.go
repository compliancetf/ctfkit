package ctfkit

// ControlID is a control id from the compliance.tf control catalog, for
// example "s3_bucket_versioning_enabled". It is the join key across served
// modules, findings and evidence, so it is stable across catalog versions.
type ControlID string

// CatalogVersion identifies the catalog a run was analyzed against. It is
// recorded in the run object and in evidence so a later reader can tell which
// requirements were in force.
type CatalogVersion struct {
	// Version is the semantic version of the catalog, for example "2026.09.0".
	Version string
	// Provenance says where the catalog came from: the release catalog
	// embedded in the binary, the file at the home path, or the file named on
	// the command line. It is descriptive, not a trust claim.
	Provenance string
}

// ControlRef is one controls entry of the catalog: the control, the resource
// types it applies to, and the framework clauses it satisfies.
type ControlRef struct {
	// ID is the control id.
	ID ControlID
	// Name is the human readable control name.
	Name string
	// ResourceTypes are the Terraform resource types this control applies to.
	ResourceTypes []string
	// ClausesByFramework maps a framework id in the catalog spelling, for
	// example "pci_dss_v40", to the clauses this control satisfies in it.
	ClausesByFramework map[string][]string
	// Enforcement names the layer that owns this control and why, nil when
	// the catalog records none.
	//
	// Additive field, v0.x: added after ControlRef shipped, and a reader
	// written against the earlier shape keeps compiling.
	Enforcement *ControlEnforcement
	// NotApplicable maps a framework id to the reason this control has no
	// applicable clause in it. Nil when the catalog records none.
	//
	// Additive field, v0.x.
	NotApplicable map[string]string
}

// Enforcement layers a catalog may record for a control, in the catalog
// spelling.
const (
	LayerProviderLocal  = "provider-local"
	LayerCompanionLocal = "companion-local"
	LayerGraph          = "graph"
	LayerRuntime        = "runtime"
)

// ControlEnforcement is the enforcement record of a catalog control.
//
// Additive type, v0.x: reachable only through ControlRef.Enforcement.
type ControlEnforcement struct {
	// Layer is one of the Layer constants.
	Layer string
	// Reason says why the control sits at that layer, empty when unrecorded.
	Reason string
}

// ModuleRef is one modules entry of the control catalog: the compliance.tf
// module that covers a resource type, and the controls it enforces. It is what
// lets a finding name a replacement module without a registry token.
type ModuleRef struct {
	// ResourceTypes are the Terraform resource types this module covers. A
	// resource type appears in at most one module entry across the catalog.
	ResourceTypes []string
	// Source is the module source template. It contains the placeholder {host}
	// at most once and is returned as written; the renderer substitutes the
	// host label, which comes from the catalog's hosts map and is a registry
	// endpoint label such as "pcidss", never the framework id "pci_dss_v40". A
	// source with no placeholder is used as it stands.
	Source string
	// Version is the version constraint to write alongside the source, for
	// example "~> 4.6".
	Version string
	// Controls are the control ids this module enforces. A remediation is
	// attached to a finding only when this list holds every control id the
	// finding carries; a coverage finding, which carries none, matches on
	// resource type alone.
	Controls []ControlID
}

// ControlCatalog tells an analyzer which controls apply to a resource type,
// which module covers that type, and how each control maps to framework
// clauses.
//
// An implementation is a preloaded, immutable snapshot: it is read-only, safe
// for concurrent use, and every read it needs has already happened by the time
// an analyzer sees it. Nothing here fetches anything, so an analyzer stays
// pure and a run stays reproducible.
//
// The catalog is the only source of control ids and remediation, and it is
// never discovered from the repository under analysis. The file backend reads
// a ctf.catalog/1 file: the release catalog embedded in the binary, the file
// at the home path, or the file named on the command line. A hosted backend
// reads the same shape over HTTP. An analyzer never learns which backend is
// live, and two backends answering the same catalog version return the same
// control ids.
//
// The interface is sealed until 1.0: an implementation embeds CatalogSeal to
// declare that it accepts a contract which may still gain methods.
type ControlCatalog interface {
	// ControlsFor returns the controls that apply to a Terraform resource
	// type, for example "aws_s3_bucket". It returns an empty slice when the
	// catalog has nothing for that type.
	ControlsFor(resourceType string) []ControlID

	// Control returns the full catalog entry for a control id. The second
	// result is false when the catalog does not hold that control.
	Control(id ControlID) (ControlRef, bool)

	// Frameworks returns the framework ids that control maps to, sorted, in
	// the catalog spelling. It returns an empty slice for a control that maps
	// to none, which is what makes a finding framework agnostic.
	Frameworks(id ControlID) []string

	// Framework returns the clauses that control satisfies in the named
	// framework. It returns an empty slice when the control does not map to
	// that framework.
	Framework(id ControlID, framework string) []string

	// ModuleFor returns the module that covers a resource type. The second
	// result is false when no module covers it. A resource type appears in at
	// most one module entry, so the answer is single-valued, and the returned
	// value owns its own Controls slice, so a caller cannot reach back into
	// the catalog through it.
	ModuleFor(resourceType string) (ModuleRef, bool)

	// Modules returns every module entry in the catalog, in catalog order,
	// each owning its own Controls slice. It is what a coverage inventory
	// walks to report which parts of an estate a module already covers.
	Modules() []ModuleRef

	// Hosts maps a framework id in the catalog spelling to the label of its
	// registry endpoint, for example "pci_dss_v40" to "pcidss". It is what a
	// renderer substitutes for the {host} placeholder of a module source. The
	// returned map is the caller's to keep; an implementation hands back a
	// copy rather than its own state.
	Hosts() map[string]string

	// DefaultHost returns the framework id whose host label is substituted
	// when the operator named none, for example "soc_2". It is always a key of
	// Hosts.
	DefaultHost() string

	// Version returns the version and provenance of the loaded catalog.
	Version() CatalogVersion

	sealedCatalog()
}

// CatalogSeal is embedded by a ControlCatalog implementation to satisfy the
// seal. Embedding it is the implementer's acknowledgment that the interface
// may gain methods before 1.0, which would break the implementation. The
// backends this project ships embed it; so may a backend in another repository
// that accepts the same terms.
type CatalogSeal struct{}

// sealedCatalog is the seal itself. Implementations outside this package embed
// CatalogSeal to satisfy ControlCatalog, which no analysis of this package
// alone can observe, so it reads as unused here. See doc.go, "Sealed
// interfaces".
//
//nolint:unused // seal marker, see doc.go
func (CatalogSeal) sealedCatalog() {}
