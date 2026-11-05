# Spacelift approval policy for ctfkit by compliance.tf (sample): no tasks on a
# ctfkit:gate stack.
#
# A task runs an arbitrary command in the stack's workspace with the stack's credentials, outside
# the custom workflow, so it can change infrastructure without gate plan, gate sign or ctfkit
# apply. Attach this as an Approval policy to every ctfkit:gate stack. Spacelift evaluates
# approval policies for task runs and replaced its task policies with them [verify on a live
# account]. Every other run is approved here; any other approval policy attached still decides.
package spacelift

# Rego v1 syntax; see policy.rego for why the import is there.
import rego.v1

# Same comparison as policy.rego: the label in any case.
gate_stack if {
	some label in input.stack.labels
	lower(label) == "ctfkit:gate"
}

reject if {
	input.run.type == "TASK"
	gate_stack
}

approve if not reject
