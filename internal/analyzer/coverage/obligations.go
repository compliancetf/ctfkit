package coverage

// shippedObligationTokens is the does_not_prove vocabulary this release of
// ctfkit knows. It is regenerated per release from the compliance manifest
// schema, and it is shipped in the binary rather than read from the
// repository under analysis: a document that could extend the list of tokens
// a consumer accepts could also silence the one token it did not want
// reported.
//
// A token outside this list is not an error and never blocks. It is reported
// verbatim as a note, because a producer stating a new obligation must reach
// the reader through an older consumer rather than be dropped by it.
var shippedObligationTokens = map[string]bool{
	"child_not_self_validating":             true,
	"delegated_controls_enforced_elsewhere": true,
	"evaluation_record_partial":             true,
	"no_evaluation_record":                  true,
	"no_per_rule_attribution":               true,
	"ongoing_operation":                     true,
	"organizational_controls":               true,
	"rules_are_package_scoped":              true,
	"runtime_state":                         true,
}
