# ctfkit produces findings; this policy decides. Input: ctfkit scan --format json.
# Denies every error-level finding that no accepted exception suppresses.
package ctfkit

deny contains msg if {
	some f in input.findings
	f.level == "error"
	count(object.get(f, "suppressions", [])) == 0
	addr := object.get(f, ["locations", 0, "logicalLocations", 0, "fullyQualifiedName"], "configuration")
	msg := sprintf("%s at %s: %s", [f.ruleId, addr, f.message.text])
}
