package ctfkit

import (
	"fmt"
	"reflect"
	"regexp"
)

// RuleIDPattern is the frozen rule id format: ctf, a family segment of lower
// case letters and digits, then one or more segments that may also carry
// underscores. A registry rejects anything else, so an id that cannot appear
// in the findings taxonomy cannot reach a run.
//
// This is the pattern the published schemas carry, verbatim. cff-1 and
// spacelift-1 are the authority for wire shapes, so the SDK follows them
// rather than the other way round, and TestRuleIDPatternMatchesPublishedSchemas
// reads both files to keep the three in step. Note that the family segment
// takes no underscore: ctf.s3_bucket.enabled is not a valid id.
//
// It is exported so that a renderer validating its own emit boundary uses this
// value instead of copying the source text into its own package, which is how
// the SDK and the schemas drifted apart to begin with.
var RuleIDPattern = regexp.MustCompile(`^ctf\.[a-z0-9]+(\.[a-z0-9_]+)+$`)

// Registry holds the analyzers a run may execute. It is in-process; an adapter
// filters by stage and runs the result, and may run them concurrently, which
// is safe because analyzers are pure.
//
// Registration is keyed by the pair (id, stage), not by id alone. One rule id
// may run at two stages, for example ctf.coverage.module_source at pre_plan
// over module blocks and at post_plan over planned resources: that is two
// registered values sharing one rule id and one implementation. Only one stage
// runs per invocation, so no finding is produced twice.
//
// Plugin discovery, whether Go plugins or WASM, is out of scope for v0.x.
//
// The interface is sealed until 1.0: an implementation embeds RegistrySeal to
// declare that it accepts a contract which may still gain methods.
type Registry interface {
	// Register adds a to the registry. It returns an error for a nil
	// analyzer, a rule id outside the frozen format, a stage that is not one
	// of the five, or a second analyzer with the same (id, stage) pair, which
	// would otherwise shadow a check. It never panics; MustRegister is the
	// wrapper for wiring that has nowhere to return an error to.
	Register(a Analyzer) error

	// All returns every registered analyzer in registration order. The same
	// rule id may appear more than once, once per stage it registered at.
	All() []Analyzer

	// ByStage returns the analyzers whose Stage is s, in registration order.
	ByStage(s Stage) []Analyzer

	// ByID returns the analyzer registered for the pair (id, s), or nil when
	// none is. The stage argument is required because a rule id alone does not
	// identify an analyzer.
	ByID(id string, s Stage) Analyzer

	sealedRegistry()
}

// RegistrySeal is embedded by a Registry implementation to satisfy the seal.
// Embedding it is the implementer's acknowledgment that the interface may
// gain methods before 1.0.
type RegistrySeal struct{}

func (RegistrySeal) sealedRegistry() {}

// NewRegistry returns an empty in-process Registry.
//
// The returned value is not safe for concurrent registration. Register every
// analyzer during start-up from a single goroutine, then read it concurrently
// for the rest of the run.
func NewRegistry() Registry {
	return &registry{byKey: make(map[registryKey]int)}
}

// MustRegister registers every analyzer and panics on the first error. It is
// for wiring executed at start-up, where a rejected analyzer is a mistake in
// the binary rather than a condition that depends on input. Anything that can
// report an error calls Register instead.
func MustRegister(r Registry, analyzers ...Analyzer) {
	for _, a := range analyzers {
		if err := r.Register(a); err != nil {
			panic(err.Error())
		}
	}
}

// registryKey is the (id, stage) pair an analyzer registers under.
type registryKey struct {
	id    string
	stage Stage
}

type registry struct {
	RegistrySeal
	order []Analyzer
	byKey map[registryKey]int
}

func (r *registry) Register(a Analyzer) error {
	if isNil(a) {
		return fmt.Errorf("ctfkit: cannot register a nil analyzer")
	}
	id, stage := a.ID(), a.Stage()
	if !RuleIDPattern.MatchString(id) {
		return fmt.Errorf("ctfkit: rule id %q does not match %s", id, RuleIDPattern)
	}
	if stage.Rank() < 0 {
		return fmt.Errorf("ctfkit: analyzer %s declares unknown stage %q", id, stage)
	}
	k := registryKey{id: id, stage: stage}
	if _, ok := r.byKey[k]; ok {
		return fmt.Errorf("ctfkit: analyzer %s is already registered at stage %s", id, stage)
	}
	r.byKey[k] = len(r.order)
	r.order = append(r.order, a)
	return nil
}

func (r *registry) All() []Analyzer {
	out := make([]Analyzer, len(r.order))
	copy(out, r.order)
	return out
}

func (r *registry) ByStage(s Stage) []Analyzer {
	out := make([]Analyzer, 0, len(r.order))
	for _, a := range r.order {
		if a.Stage() == s {
			out = append(out, a)
		}
	}
	return out
}

func (r *registry) ByID(id string, s Stage) Analyzer {
	i, ok := r.byKey[registryKey{id: id, stage: s}]
	if !ok {
		return nil
	}
	return r.order[i]
}

// isNil reports whether a is nil, including a typed nil: an interface holding
// a nil pointer is not equal to nil, and calling ID on it panics, so the check
// that matters is the one on the value inside the interface.
func isNil(a Analyzer) bool {
	if a == nil {
		return true
	}
	v := reflect.ValueOf(a)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}
