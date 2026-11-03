package fixturepin

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// ManifestName is the file the registry writes into every served module
// directory.
const ManifestName = "compliancetf-manifest.json"

// Files is a case's input tree: slash-separated paths relative to input/,
// mapped to their bytes.
type Files map[string][]byte

// Transform derives a synthesized case's input tree from its base case's.
// A synthesized case is a condition the registry cannot be asked to produce
// (testdata/fixtures/README.md "The synthesized inputs, and why"), so it is
// never recorded: it is this function of a recorded tree, and the check test
// holds the committed bytes to it.
type Transform func(base Files) (Files, error)

// Transforms are the transforms a PIN.json may name.
var Transforms = map[string]Transform{
	"degraded-posture":   degradedPosture,
	"schema-major-4":     schemaMajor4,
	"supporting-clauses": supportingClauses,
}

// cc73 is the SOC 2 clause the supporting-clauses case marks supporting, as
// the release catalog words it.
const cc73 = "CC7.3 The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures"

// supportingControls are the controls the supporting-clauses case marks CC7.3
// supporting on.
var supportingControls = []string{"s3_bucket_logging_enabled", "s3_bucket_event_notifications_enabled"}

func schemaMajor4(base Files) (Files, error) {
	return editManifest(base, "", func(m *node) error {
		v, _ := m.get("schema_version").text()
		if !strings.HasPrefix(v, "3.") {
			return fmt.Errorf("base schema_version is %q, want 3.x", v)
		}
		m.set("schema_version", strNode("4.0"), "")
		return nil
	})
}

func degradedPosture(base Files) (Files, error) {
	return editManifest(base, "bobthecorp-degraded-data", func(m *node) error {
		posture := m.get("posture")
		degraded := posture.get("degraded")
		if degraded == nil || degraded.kind != '[' || len(degraded.values) != 0 {
			return fmt.Errorf("base posture.degraded is not an empty list")
		}
		posture.set("degraded", strArray("org-rules-unavailable", "baseline-not-authored"), "")

		dnp := m.get("scope").get("does_not_prove")
		if dnp == nil || dnp.kind != '[' {
			return fmt.Errorf("base scope.does_not_prove is not a list")
		}
		const token = "org_baseline_not_evidenced"
		for _, e := range dnp.values {
			if t, _ := e.get("token").text(); t == token {
				return fmt.Errorf("base already carries does_not_prove token %s", token)
			}
		}
		entry := &node{kind: '{'}
		entry.set("token", strNode(token), "")
		entry.set("statement", strNode("this build could not read the org rule set, so no statement is made about org baseline rules for this package"), "")
		entry.set("consumer_obligation", strNode("must not read the absence of operational rules as evidence that the org baseline was applied"), "")
		dnp.values = append(dnp.values, entry)
		return nil
	})
}

func supportingClauses(base Files) (Files, error) {
	return editManifest(base, "bobthecorp-supporting-data", func(m *node) error {
		v, _ := m.get("schema_version").text()
		minor, ok := strings.CutPrefix(v, "3.")
		if n, err := strconv.Atoi(minor); !ok || err != nil || n > 4 {
			return fmt.Errorf("base schema_version is %q, want 3.0 to 3.4", v)
		}
		m.set("schema_version", strNode("3.4"), "")

		controls := m.get("controls")
		if controls == nil || controls.kind != '[' {
			return fmt.Errorf("base carries no controls list")
		}
		marked := map[string]bool{}
		for _, c := range controls.values {
			id, _ := c.get("control_id").text()
			byFramework := c.get("clauses_by_framework")
			if byFramework == nil || byFramework.kind != '{' {
				return fmt.Errorf("control %s carries no clauses_by_framework", id)
			}
			supporting := &node{kind: '{'}
			for _, k := range byFramework.keys {
				fw := strings.Trim(string(k), `"`)
				items := strArray()
				if fw == "soc_2" && slices.Contains(supportingControls, id) {
					items = strArray(cc73)
					marked[id] = true
				}
				supporting.set(fw, items, "")
			}
			c.set("supporting_clauses_by_framework", supporting, "clauses_by_framework")
		}
		for _, id := range supportingControls {
			if !marked[id] {
				return fmt.Errorf("base has no soc_2 control %s to mark supporting", id)
			}
		}
		return nil
	})
}

// bucketLine is the one bucket argument a base case's main.tf carries.
var bucketLine = regexp.MustCompile(`(?m)^(\s*bucket\s*=\s*)"[^"]*"`)

// editManifest copies base, applies edit to its one manifest and, when bucket
// is not empty, renames the bucket in main.tf. Every post-condition failure is
// an error, so a re-recorded base that no longer fits the transform stops the
// recorder instead of producing a case that asserts something else.
func editManifest(base Files, bucket string, edit func(*node) error) (Files, error) {
	var manifests []string
	for p := range base {
		if path.Base(p) == ManifestName {
			manifests = append(manifests, p)
		}
	}
	if len(manifests) != 1 {
		sort.Strings(manifests)
		return nil, fmt.Errorf("base carries %d manifests %v, want exactly 1", len(manifests), manifests)
	}

	out := make(Files, len(base))
	for p, b := range base {
		out[p] = b
	}

	doc, tail, err := parseJSON(base[manifests[0]])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", manifests[0], err)
	}
	if err = edit(doc); err != nil {
		return nil, fmt.Errorf("%s: %w", manifests[0], err)
	}
	out[manifests[0]] = append(doc.encode(), tail...)

	if bucket != "" {
		mainTF, ok := base["main.tf"]
		if !ok {
			return nil, fmt.Errorf("base carries no main.tf")
		}
		if n := len(bucketLine.FindAllIndex(mainTF, -1)); n != 1 {
			return nil, fmt.Errorf("base main.tf carries %d bucket arguments, want exactly 1", n)
		}
		out["main.tf"] = bucketLine.ReplaceAll(mainTF, []byte(`${1}"`+bucket+`"`))
	}
	return out, nil
}
