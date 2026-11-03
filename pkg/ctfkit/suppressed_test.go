package ctfkit_test

import (
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Suppressed is the one definition of a waived finding that every renderer,
// the verdict and the exit code share. Five copies of this predicate existed
// before it, and one of them - the Evidence Receipt's verdict - was missing,
// so a fully waived run recorded fail in its receipt and pass everywhere else.
func TestSuppressed(t *testing.T) {
	tests := []struct {
		name string
		exc  *ctfkit.ExceptionProperty
		want bool
	}{
		{"no exception", nil, false},
		{"an allowed exception waives the finding", &ctfkit.ExceptionProperty{Allowed: true, EntryID: "bobthecorp-1"}, true},
		// An exception found but out of its review window is recorded with
		// Allowed false. It is kept on the finding so a reader sees the lapse,
		// and it waives nothing.
		{"an expired exception does not", &ctfkit.ExceptionProperty{Allowed: false, EntryID: "bobthecorp-1"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ctfkit.Finding{RuleID: "ctf.coverage.manifest_missing", Level: ctfkit.LevelError}
			f.Props.Exception = tt.exc
			if got := f.Suppressed(); got != tt.want {
				t.Errorf("Suppressed() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The level plays no part: a waiver covers a finding whatever its level, and it
// is the verdict, not this predicate, that asks only about error.
func TestSuppressedIgnoresTheLevel(t *testing.T) {
	for _, level := range []string{ctfkit.LevelError, ctfkit.LevelWarning, ctfkit.LevelNote} {
		f := ctfkit.Finding{RuleID: "ctf.coverage.manifest_missing", Level: level}
		f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: true, EntryID: "bobthecorp-1"}
		if !f.Suppressed() {
			t.Errorf("a waived %s finding reported Suppressed() = false", level)
		}
	}
}
