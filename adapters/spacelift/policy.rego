# Spacelift plan policy for ctfkit by compliance.tf.
#
# Attach this as a Plan policy to every stack that runs the ctfkit hooks. A consuming stack gets its
# hooks from its stack settings (see config.stack.yml), not from a committed file; a
# .spacelift/config.yml applies only to a module repository's test cases (see config.yml). The
# policy renders the verdict the hooks already computed and never re-derives one from counts.
package spacelift

# Rego v1 syntax. The import keeps the file loading on OPA 0.59 or later evaluating in v0 mode
# (0.59 added `import rego.v1`; an older OPA rejects it); on OPA 1.x it changes nothing.
import rego.v1

# Global switch. Set enforce := true to enforce every stack this policy is attached to. While it
# stays false, the verdict rules below are warnings and do not block, except on a stack carrying
# the ctfkit:enforce label (next rule). The label rules and the ctfkit:gate rules deny whatever
# enforce says. No hook can turn a run red on its own. Module repositories do
# not use this switch: their test cases switch by changing --fail-on in their .spacelift/config.yml.
#
# Enforce a stack once it has had several shadow runs whose warnings you have reviewed, every run
# carries both metadata keys, and no run reports an unexpected manifest_missing finding.
enforce := false

# Per-stack switch: a stack carrying the label ctfkit:enforce is enforced while enforce stays false,
# so a platform admin can move one stack at a time. Labels live in stack settings, so a stack cannot
# add or remove its own label from its own repository, unless its settings are managed from that
# same repository (an administrative stack or the Spacelift terraform provider). No label means
# shadow mode. Labels are compared in lower case, so CTFKIT:Enforce enforces too.
enforce_stack if has_label("ctfkit:enforce")

has_label(want) if {
	some label in input.spacelift.stack.labels
	lower(label) == want
}

# Only the known labels count: ctfkit:enforce above and ctfkit:gate below, in any case. Any other
# label starting with ctfkit:, in any case, is denied even in shadow mode, so a typo such as
# ctfkit:enforced or ctfkit:gate2 cannot leave a stack ungoverned unnoticed.
known_labels := {"ctfkit:enforce", "ctfkit:gate"}

unrecognized_labels contains label if {
	some label in input.spacelift.stack.labels
	startswith(lower(label), "ctfkit:")
	not known_labels[lower(label)]
}

deny contains msg if {
	some label in unrecognized_labels
	msg := sprintf("unrecognized ctfkit label %v; the known labels are ctfkit:enforce and ctfkit:gate", [label])
}

enforcing if enforce

enforcing if enforce_stack

# Each hook writes its own metadata key, so after_init and after_plan never overwrite each other:
# `ctfkit report` writes ctfkit.custom.spacelift.json, `ctfkit scan` writes
# ctfkit-scan.custom.spacelift.json. A stack run is expected to carry both.
keys := {"ctfkit", "ctfkit-scan"}

schema := "ctfkit.spacelift/1"

report[key] := r if {
	key := keys[_]
	r := input.third_party_metadata.custom[key]
}

missing contains key if {
	key := keys[_]
	not input.third_party_metadata.custom[key]
}

# ctfkit computes the verdict when it writes the file: fail when any unsuppressed error-level
# finding exists. It does not depend on --fail-on, so a hook's threshold cannot make a failing run
# look clean. The policy reads that field rather than counting findings, which is also why a rule
# that runs at both stages cannot be double counted. The totals are quoted for the reader, never
# summed across the two files.
#
# Anything that is not exactly "pass" fails closed, including an absent verdict: a file this policy
# cannot read as a pass is not a pass.
verdict(r) := v if {
	v := r.verdict
}

verdict(r) := "absent" if {
	not r.verdict
}

complete_summary(r) if {
	r.summary.error
	r.summary.warning
}

counts(r) := c if {
	complete_summary(r)
	c := sprintf("%d error, %d warning", [r.summary.error, r.summary.warning])
}

counts(r) := "totals unavailable" if {
	not complete_summary(r)
}

failed[key] := msg if {
	r := report[key]
	v := verdict(r)
	v != "pass"
	msg := sprintf("%v: verdict %v (%v)", [key, v, counts(r)])
}

# Shadow mode: surface everything, block nothing.
warn contains msg if {
	missing[key]
	msg := sprintf("ctfkit metadata is missing from this run under key %v", [key])
}

warn contains msg if {
	msg := failed[_]
}

# Once enforcing, through enforce or the stack label, the policy fails closed. Metadata absent
# under either key, and metadata carrying a schema this policy does not know, both deny: a run
# where a hook silently did not execute cannot pass as a clean run.
deny contains msg if {
	enforcing
	missing[key]
	msg := sprintf("ctfkit metadata is missing from this run under key %v", [key])
}

deny contains msg if {
	enforcing
	r := report[key]
	r.schema != schema
	msg := sprintf("ctfkit metadata under key %v is in unknown schema %v", [key, r.schema])
}

deny contains msg if {
	enforcing
	msg := failed[_]
}

# Governed apply (preview). A stack whose plan command is ctfkit gate plan (workflow.yml) carries
# the label ctfkit:gate, and its run carries the metadata that command writes once the candidate
# exists, under key ctfkit-gate. On such a stack the policy requires that metadata whether or not
# the stack is enforced: the label is the admin's statement that the stack applies only through
# ctfkit apply. A missing file means planning did not run through ctfkit gate plan.
#
# The metadata is a marker, not evidence: any command that runs during planning, including a
# workflow file committed to the repository or code terraform runs at plan time, can write it.
# A ctfkit:gate stack therefore needs an org profile that sets verdict_required, so the provider
# refuses an apply that carries no verdict whatever this policy saw.
#
# A stack without the label gets no verdict, so the provider checks its applies one resource at a
# time and no graph control decides (single-resource-only). That is allowed unless the org profile
# sets verdict_required: then every mutating apply needs a verdict, and the provider refuses one
# without it. Set verdict_required := true here when the profile does, so such a stack is refused
# at plan rather than at apply.
verdict_required := false

gate_stack if has_label("ctfkit:gate")

gate_required if gate_stack

gate_required if verdict_required

gate_schema := "ctfkit.spacelift-gate/1"

deny contains msg if {
	gate_required
	not input.third_party_metadata.custom["ctfkit-gate"]
	msg := "ctfkit metadata is missing from this run under key ctfkit-gate; the stack's plan command must be ctfkit gate plan"
}

# A schema that is absent or unknown fails closed, on any stack.
gate_ok if input.third_party_metadata.custom["ctfkit-gate"].schema == gate_schema

gate_schema_of(r) := r.schema if r.schema

gate_schema_of(r) := "absent" if not r.schema

deny contains msg if {
	r := input.third_party_metadata.custom["ctfkit-gate"]
	not gate_ok
	msg := sprintf("ctfkit metadata under key ctfkit-gate is in unknown schema %v", [gate_schema_of(r)])
}
