// Package ctfkit is the analyzer SDK contract for ctfkit by compliance.tf.
//
// It holds interfaces and data types only. There are no loaders, no analyzer
// implementations and no renderers here; those live in the internal packages
// and in the platform adapters.
//
// # Purity
//
// Purity is the rule that makes the contract portable. An Analyzer receives an
// AnalyzerInput and returns Findings, and in between it does none of the
// following:
//
//	no I/O of any kind
//	no network access
//	no filesystem access, reading included
//	no clock: the time is RunMetadata.Now, never time.Now
//	no mutation of the input
//
// So the same analyzer runs unchanged in a CLI process, a Lambda, a container
// and a WASM module, and the same recorded input gives the same findings on
// any machine on any day. Everything that touches the outside world belongs to
// a loader or an adapter, which hands the result to the analyzer as input.
//
// The input is shared and read only. One AnalyzerInput is handed to every
// analyzer of a stage, and they may run concurrently, so an analyzer that
// writes to any part of it has a defect: it corrupts what its peers see and it
// makes the run depend on order. Nothing in the input is defensively copied
// for you.
//
// Exceptions are not an analyzer's business either. ExceptionRegistry is
// deliberately absent from AnalyzerInput: an analyzer reports what it found,
// and the runner decides afterwards. That decision is Decide, which lives here
// rather than in each adapter so that every platform reaches the same verdict
// from the same registry; the runner then records it with WithException and
// writes the SARIF suppression.
//
// The runner's own sequence, for the same reason, is ValidateFor on every
// finding an analyzer returns, then Decide, then WithException, then
// SortFindings before anything is rendered.
//
// # What each stage supplies
//
// A run executes one stage, named by AnalyzerInput.Stage. Which fields of the
// input carry a value follows from it:
//
//	pre_plan    Config. No Modules, no PlanJSON, no State.
//	post_init   Config and Modules. No PlanJSON, no State.
//	post_plan   PlanJSON and Modules; Config optional.
//	pre_apply   PlanJSON and Modules; Config optional. Same shape as post_plan.
//	post_apply  State, plus PlanJSON and Modules; Config optional.
//
// Catalog, Settings and Metadata are supplied at every stage, and the catalog
// is a preloaded immutable snapshot: nothing is fetched inside Analyze.
// Stage.Rank orders the stages when an analyzer needs to compare them; the
// Stage strings are names, and comparing them directly compares them
// alphabetically, which is not the workflow order.
//
// # Keyed struct literals
//
// Build every struct in this package with keyed fields:
//
//	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, Config: cfg}
//
// An unkeyed literal compiles only while the field list stays exactly as it
// is, and the stability policy allows a field to be added in any release. Such
// a literal is not supported and a release that breaks one is not a breaking
// change.
//
// # Sealed interfaces
//
// Registry, ControlCatalog and ExceptionRegistry each carry an unexported
// method, so an implementation must embed the matching seal type: RegistrySeal,
// CatalogSeal or ExceptionRegistrySeal. Embedding one is an acknowledgment
// that the interface may still gain methods before 1.0, which would break the
// implementation. The point is that no one depends on these shapes by accident
// while they are still moving.
//
// Analyzer is deliberately not sealed. It is the extension point, it is frozen
// as it stands, and anything that can produce Findings is welcome to implement
// it.
//
// # Optional capabilities
//
// Where an analyzer needs to tell the runner something beyond the Analyzer
// contract, the mechanism is an optional capability interface: a small
// interface declared here that the runner type-asserts on the analyzer value,
// falling back to a default when the assertion fails. It extends the contract
// without widening Analyzer, so an analyzer that does not implement it keeps
// compiling and keeps working.
//
// There are none in v0.1. The mechanism is documented so that the first one is
// added this way rather than as a sixth method on Analyzer.
//
// # Versioning
//
// The contract is versioned at v0.x. What may still change before 1.0, and
// what is already frozen, is stated in the stability policy for this package.
package ctfkit
