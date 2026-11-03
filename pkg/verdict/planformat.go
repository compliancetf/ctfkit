package verdict

// planFormats is the plan JSON format_version allowlist: the versions whose
// resource_changes layout the gate and the instance key adapters are built
// against. Terraform 1.5 to 1.16 and OpenTofu up to 1.13 write 1.2.
var planFormats = map[string]bool{"1.2": true}

// PlanFormatAllowed reports whether a plan JSON format_version is in the
// allowlist. Anything else fails closed: a newer layout may move a field the
// gate reads.
func PlanFormatAllowed(v string) bool { return planFormats[v] }
