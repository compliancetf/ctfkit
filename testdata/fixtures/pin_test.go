package fixtures

import (
	"testing"

	"github.com/compliancetf/ctfkit/internal/fixturepin"
)

// TestReportPackMatchesItsPin is the offline check of the pinned report pack
// (README "Pinning and re-recording"): PIN.json is canonical and names every
// case and every registry module, each manifest hashes to its pin and declares
// the pinned schema version, every Dir stays under .terraform/modules, the
// synthesized cases are exactly their transforms, and nothing in the pack looks
// like a token, a signed URL or an absolute path. It never touches the network.
func TestReportPackMatchesItsPin(t *testing.T) {
	for _, err := range fixturepin.Check("report") {
		t.Error(err)
	}
}
