package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/exceptions"
	"github.com/compliancetf/ctfkit/internal/loader"
)

// Exit codes of every ctfkit command. They are the contract adapters gate on,
// so they are stated once here and nowhere else.
const (
	// ExitOK is a completed run with nothing at or above the threshold.
	ExitOK = 0
	// ExitFindings is a completed run that produced findings at or above
	// --fail-on. The analysis succeeded; the configuration did not pass.
	ExitFindings = 1
	// ExitEnvironment is a run that could not complete: a missing or
	// unreadable input, an unsupported schema major, a malformed policy file,
	// an unusable flag combination, or an analyzer malfunction. It is never a
	// statement about the configuration.
	ExitEnvironment = 2
)

// Diagnostic categories of an exit-2 error. A caller tells misconfiguration
// from an analyzer defect by reading the category off the error rather than by
// parsing the prose, which is why it is a field and not a message prefix: the
// recorded fixture stderr froze the wire format as `ctfkit: <message>`.
const (
	categoryInput      = "input"
	categoryCatalog    = "catalog"
	categoryExceptions = "exceptions"
	categorySettings   = "settings"
	categoryAnalyzer   = "analyzer"
	categoryFinding    = "finding"
)

// ExitError is an error that carries the process exit code it asks for.
// Commands return one instead of calling os.Exit, so that a test can run a
// command in process and main stays the only place that ends the process.
type ExitError struct {
	// Code is the exit code, one of ExitOK, ExitFindings, ExitEnvironment.
	Code int
	// Category is the exit-2 diagnostic category, empty on other codes.
	Category string
	// Message is what the operator is told, already stripped of the internal
	// sentinel prefix. An empty message prints nothing.
	Message string
}

// Error implements error.
func (e *ExitError) Error() string { return e.Message }

// ExitCode reports the code the process should end with.
func (e *ExitError) ExitCode() int { return e.Code }

// ExitCode maps any error onto a process exit code. A nil error is 0, an error
// that names its own code takes it, and anything else is an environment error:
// a command that returns a bare error failed before it could judge a
// configuration, and reporting that as "findings" would be a false accusation.
//
// This is the fix for the defect where every error, including a missing file
// and an unparseable flag, ended the process with 1.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}

	var coder interface{ ExitCode() int }
	if errors.As(err, &coder) {
		return coder.ExitCode()
	}

	return ExitEnvironment
}

// sentinel pairs a package's error marker with the diagnostic category it
// belongs to. The marker is also the prefix its messages carry, so the same
// entry both classifies the error and says what to strip from the text.
type sentinel struct {
	err      error
	category string
}

var sentinels = []sentinel{
	{loader.ErrInput, categoryInput},
	{catalog.ErrCatalog, categoryCatalog},
	{exceptions.ErrExceptions, categoryExceptions},
}

// environmentError turns a package error into an exit-2 diagnostic. The
// category comes from the sentinel the error wraps; an error that wraps none is
// an input error, because everything a command reads before an analyzer runs is
// input. The sentinel text is stripped from the message: it is how Go code
// classifies the error, not something an operator can act on.
func environmentError(err error) *ExitError {
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return &ExitError{
				Code:     ExitEnvironment,
				Category: s.category,
				Message:  strings.TrimPrefix(err.Error(), s.err.Error()+": "),
			}
		}
	}

	return &ExitError{Code: ExitEnvironment, Category: categoryInput, Message: err.Error()}
}

// inputError is an exit-2 diagnostic the command raises itself: a flag
// combination that has no defined output, a format name outside the list, a
// path that is not there.
func inputError(format string, args ...any) *ExitError {
	return &ExitError{Code: ExitEnvironment, Category: categoryInput, Message: fmt.Sprintf(format, args...)}
}

// categorized is an exit-2 diagnostic in a category the sentinels cannot
// reach: a settings file, an analyzer that returned an error, a finding that
// failed validation at the emit boundary.
func categorized(category string, format string, args ...any) *ExitError {
	return &ExitError{Code: ExitEnvironment, Category: category, Message: fmt.Sprintf(format, args...)}
}

// findingsError ends a run that completed and produced findings at or above
// the threshold. It is not an environment failure and says so in one line: the
// projections carry the detail.
func findingsError(count int, level string) *ExitError {
	return &ExitError{
		Code:    ExitFindings,
		Message: fmt.Sprintf("%d finding(s) at or above %s", count, level),
	}
}
