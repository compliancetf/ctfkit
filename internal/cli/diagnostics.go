package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/compliancetf/ctfkit/internal/config"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/sink"
)

// The wording of the common usage diagnostics, one place for every command:
// what failed, then "; " and the next step.

// errGivenTwice and errEmptyValue are what onceString and onceBool refuse;
// flagError words them.
var (
	errGivenTwice = errors.New("flag given more than once")
	errEmptyValue = errors.New("flag value is empty")
)

// seeHelp is the next step that points at a command's help.
func seeHelp(cmd *cobra.Command) string {
	return fmt.Sprintf("see %q", cmd.CommandPath()+" --help")
}

// flagError is the root FlagErrorFunc, which every command inherits: any flag
// that does not parse is exit 2 with the flag, the command and the next step.
func flagError(cmd *cobra.Command, err error) error {
	var notExist *pflag.NotExistError
	var noValue *pflag.ValueRequiredError
	var invalid *pflag.InvalidValueError
	switch {
	case errors.As(err, &notExist):
		name := "--" + notExist.GetSpecifiedName()
		if group := notExist.GetSpecifiedShortnames(); group != "" {
			name = "-" + notExist.GetSpecifiedName()
			if len(group) > 1 {
				name += " in -" + group
			}
		}
		return inputError("unknown flag %s for %q; %s", name, cmd.CommandPath(), seeHelp(cmd))
	case errors.As(err, &noValue):
		return inputError("--%s needs a value; %s", noValue.GetFlag().Name, seeHelp(cmd))
	case errors.As(err, &invalid):
		name := invalid.GetFlag().Name
		switch {
		case errors.Is(err, errGivenTwice):
			return inputError("--%s is given more than once; give it once", name)
		case errors.Is(err, errEmptyValue):
			return inputError("--%s has an empty value; give it a value", name)
		case invalid.GetFlag().Value.Type() == "bool":
			return inputError("--%s takes true or false, not %q; use --%s or --%s=false", name, invalid.GetValue(), name, name)
		}
	}
	return inputError("%v; %s", err, seeHelp(cmd))
}

// unknownSubcommand is the RunE of a command that only groups others: with no
// argument it prints its help, and any argument is a command it does not have.
// Without it cobra prints the help and exits 0 for a mistyped subcommand.
func unknownSubcommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	if cmd.SuggestionsMinimumDistance <= 0 {
		cmd.SuggestionsMinimumDistance = 2 // cobra's default, which it sets on the root only
	}
	if names := cmd.SuggestionsFor(args[0]); len(names) > 0 {
		return inputError("unknown command %q for %q; did you mean \"%s %s\"?", args[0], cmd.CommandPath(), cmd.CommandPath(), names[0])
	}
	return inputError("unknown command %q for %q; %s", args[0], cmd.CommandPath(), seeHelp(cmd))
}

// noArgs is cobra.NoArgs with the house wording.
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return inputError("unexpected argument %q for %q, which takes none; %s", args[0], cmd.CommandPath(), seeHelp(cmd))
	}
	return nil
}

// atMostOne is cobra.MaximumNArgs(1) with the house wording; name is the
// argument's placeholder in the usage line.
func atMostOne(name string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			return inputError("too many arguments for %q, which takes at most one %s; %s", cmd.CommandPath(), name, seeHelp(cmd))
		}
		return nil
	}
}

// flagValue is one required flag and the value it was given.
type flagValue struct{ name, value string }

// requireFlags refuses a run that lacks required flags, naming every missing
// one at once, in the order given, so the user fixes them in one go.
func requireFlags(cmd *cobra.Command, flags ...flagValue) error {
	var missing []string
	for _, f := range flags {
		if f.value == "" {
			missing = append(missing, "--"+f.name)
		}
	}
	noun := "flags"
	switch len(missing) {
	case 0:
		return nil
	case 1:
		noun = "flag"
	}
	return inputError("missing required %s for %q: %s; %s", noun, cmd.CommandPath(), strings.Join(missing, ", "), seeHelp(cmd))
}

// cannotRead is the exit-2 diagnostic of a path the command could not read:
// what it is, the path as given, the OS reason and the step for its error
// class. notFound is the step for a path that does not exist ("" for the
// default).
func cannotRead(what, path string, err error, notFound string) *ExitError {
	return inputError("cannot read %s%s: %v; %s", what, path, loader.ReadReason(err), loader.ReadStep(err, notFound))
}

// settingsError is the exit-2 diagnostic of a settings file that does not
// load, worded the same on every command that reads one. notFound is the
// step for a file that does not exist ("" for the default).
func settingsError(path string, err error, notFound string) *ExitError {
	var pathErr *fs.PathError
	switch {
	case errors.As(err, &pathErr):
		e := cannotRead("settings file ", path, err, notFound)
		e.Category = categorySettings
		return e
	case errors.Is(err, config.ErrNotYAML):
		return categorized(categorySettings, "settings file %s is %v; fix it and run again", path, err)
	}
	return categorized(categorySettings, "settings file %s: %v", path, err)
}

// fileError is environmentError for a catalog or exceptions file: one that
// cannot be read is worded by cannotRead, in the category of its package.
func fileError(what string, err error, notFound string) *ExitError {
	e := environmentError(err)
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		e.Message = cannotRead(what, pathErr.Path, err, notFound).Message
	}
	return e
}

// catalogNotFound is the step for a --catalog file that does not exist.
const catalogNotFound = "check the path, or pass --catalog embedded"

// signerError words a --signer failure: an AWS KMS call by its operation and
// failure class, never the SDK text; anything else through format, which
// takes the error once.
func signerError(uri string, err error, format string) *ExitError {
	if op, reason, step, ok := awsFailure(err, "check those credentials and the key policy", "check the key --signer names, then run again"); ok {
		return inputError("AWS %s on %s failed%s; %s", op, strings.TrimPrefix(uri, "awskms:"), reason, step)
	}
	return inputError(format, err)
}

// awsAuthCodes are the AWS error codes that refuse the caller's credentials.
var awsAuthCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true, "ExpiredToken": true, "ExpiredTokenException": true,
	"InvalidAccessKeyId": true, "InvalidClientTokenId": true, "InvalidSignatureException": true,
	"SignatureDoesNotMatch": true, "UnrecognizedClientException": true,
}

// noCredentialsStep is the next step of an AWS call that found no credentials.
const noCredentialsStep = "configure AWS credentials for this run, such as AWS_PROFILE or a role" // #nosec G101 -- a next step, no credential

// awsFailure words an AWS SDK error without its text, which can name the
// caller's identity: the operation that failed, a reason and the next step
// for its class. refused is the step for credentials AWS refused, other the
// step for any other AWS error code. ok is false for an error that is not
// from an AWS call.
func awsFailure(err error, refused, other string) (op, reason, step string, ok bool) {
	var call interface {
		Service() string
		Operation() string
	}
	if !errors.As(err, &call) {
		return "", "", "", false
	}
	op = call.Service() + " " + call.Operation()
	var api interface{ ErrorCode() string }
	switch {
	case errors.As(err, &api) && awsAuthCodes[api.ErrorCode()]:
		return op, " with credentials from the default AWS credential chain (" + api.ErrorCode() + ")", refused, true
	// shortcut: the SDK reports a credential chain that found nothing only
	// in its text; "get identity" is the fixed prefix of its auth middleware.
	// Upgrade when the SDK exports a type for it.
	case strings.Contains(err.Error(), "get identity: "):
		return op, " (no credentials in the default AWS credential chain)", noCredentialsStep, true
	case errors.As(err, &api):
		return op, " (" + api.ErrorCode() + ")", other, true
	}
	return op, " (the request did not complete)", "check the network path to AWS and run again", true
}

// Evidence sink failures, printed as warning lines by evidence ship: the run
// goes on and its receipt status sets the exit code.

// sinkFailure words a sink error and its next step: an AWS S3 call by its
// operation and failure class, never the SDK text; any other sink error in
// its own text, which wraps no SDK error, with the bucket step for S3.
func sinkFailure(err error, isS3 bool) string {
	if op, reason, step, ok := awsFailure(err, "check those credentials and the bucket policy",
		"check the bucket, its region and its object lock settings, then run again"); ok {
		return "AWS " + op + " failed" + reason + "; " + step
	}
	if isS3 {
		return err.Error() + "; check the bucket and its object lock settings"
	}
	return err.Error()
}

// objectFailure is the rest of the warning line of an object sink.Ship did not
// put: spooled for the next run, or neither confirmed uploaded nor spooled.
func objectFailure(err error, isS3 bool) string {
	parts := joined(err)
	switch {
	case errors.Is(err, sink.ErrSpooled) && len(parts) == 2:
		return "spooled for the next run: " + sinkFailure(parts[1], isS3)
	case len(parts) == 2: // shortcut: sink.Ship joins the put error, then the spool error
		return fmt.Sprintf("upload not confirmed and not spooled (spool write: %s): %s; also %s, and check whether the object reached the bucket",
			loader.ReadReason(parts[1]), sinkFailure(parts[0], isS3), spoolStep(parts[1]))
	}
	return "not shipped: " + sinkFailure(err, isS3)
}

// spoolFailure is the rest of the warning line of an object a skipped sink
// could not spool: the OS reason and its step.
func spoolFailure(err error) string {
	return fmt.Sprintf("could not be spooled (%v); %s", loader.ReadReason(err), spoolStep(err))
}

// spoolStep is the next step of a spool write that failed, by error class.
func spoolStep(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "check that this user can write " + spoolDir
	}
	return "check " + spoolDir + " and the free disk space"
}

// drainFailure words an earlier run's spooled object that failed again; the
// object stays spooled and the retry does not change this run's status.
func drainFailure(err error) string {
	inner := errors.Unwrap(err)
	key, ok := strings.CutPrefix(err.Error(), "drain ")
	if !ok || inner == nil {
		return spoolEntryFailure(err.Error())
	}
	key = strings.TrimSuffix(key, ": "+inner.Error())
	return "object " + key + " stays spooled: " + sinkFailure(inner, false)
}

// spoolEntryFailure adds a step to a spool error that names no object. An
// entry whose content is unusable (corrupt, malformed, not a regular file) is
// kept and reported on every run, so the step is to move it out; an entry
// with the wrong owner or mode, or one that could not be read, is still the
// retry copy, so the step is to fix the cause and leave it. Any other spool
// error (the directory, a canceled run) keeps its own text.
func spoolEntryFailure(text string) string {
	if !strings.HasPrefix(text, "spool entry ") {
		return text
	}
	for _, unusable := range []string{": corrupt", ": malformed", ": not a regular file"} {
		if strings.HasSuffix(text, unusable) {
			return text + "; check it, then move it out of " + spoolDir + " to stop this warning"
		}
	}
	return text + "; fix the owner, mode or read error and leave the entry in " + spoolDir + ", which the next run retries"
}

// joined is the errors an errors.Join (or a multi-%w error) holds, else err.
func joined(err error) []error {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok { //nolint:errorlint // the list itself, not a match
		return j.Unwrap()
	}
	return []error{err}
}
