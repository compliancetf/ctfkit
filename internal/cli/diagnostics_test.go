package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/sink"
)

// diagnosticsDir is a working directory for the common failures: a
// configuration, an empty directory, a root with no module cache, a settings
// file that is not YAML and a root whose lock check fails.
func diagnosticsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	module := "module \"b\" {\n  source  = \"bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws\"\n  version = \"5.0.0\"\n}\n"
	lock := "terraform {\n  required_providers {\n    aws = { source = \"hashicorp/aws\" }\n  }\n}\nresource \"aws_s3_bucket\" \"b\" {}\n"
	for name, body := range map[string]string{
		"main.tf": module, "ep/main.tf": module, "lockdir/main.tf": lock, "bad.yaml": "fail_on: [\n", "out/.keep": "",
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestCommonErrorWording pins the text of the common failures: each is exit
// 2, one line, what failed and the next step.
func TestCommonErrorWording(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.ctf catalog file
	t.Setenv("CTFKIT_FAIL_ON", "")
	t.Setenv("TF_CLI_ARGS", "")
	_ = os.Unsetenv("TF_CLI_ARGS") // set at all, even empty, is refused
	signed := []string{"--workspace", "w", "--environment", "e", "--tf-bin", "/bin/false", "--org", "bobthecorp",
		"--profile", "p", "--floor", "f", "--bundle-dir", "b"}
	with := func(args ...string) []string { return append(args, signed...) }
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"U1 unknown subcommand", []string{"gate", "bogus"}, `unknown command "bogus" for "ctfkit gate"; see "ctfkit gate --help"`},
		{"U1b near a subcommand", []string{"gate", "pln"}, `unknown command "pln" for "ctfkit gate"; did you mean "ctfkit gate plan"?`},
		{"U2 unknown flag", []string{"scan", "--bogus", "."}, `unknown flag --bogus for "ctfkit scan"; see "ctfkit scan --help"`},
		{"U2 unknown root flag", []string{"--bogus"}, `unknown flag --bogus for "ctfkit"; see "ctfkit --help"`},
		{"U4 -f with no value", []string{"scan", "-f"}, `--format needs a value; see "ctfkit scan --help"`},
		{"U4 --stage with no value", []string{"scan", "--stage"}, `--stage needs a value; see "ctfkit scan --help"`},
		{"U6 empty value", []string{"scan", "--out", "", "."}, "--out has an empty value; give it a value"},
		{"U7 bool flag", []string{"--no-color=x", "version"}, `--no-color takes true or false, not "x"; use --no-color or --no-color=false`},
		{"U8 argument", []string{"version", "extra"}, `unexpected argument "extra" for "ctfkit version", which takes none; see "ctfkit version --help"`},
		{"U9 config validate", []string{"config", "validate", "a", "b"}, `too many arguments for "ctfkit config validate", which takes at most one FILE; see "ctfkit config validate --help"`},
		{"U9 verify-lock", []string{"verify-lock", "a", "b"}, `too many arguments for "ctfkit verify-lock", which takes at most one DIR; see "ctfkit verify-lock --help"`},
		{"F1 missing path", []string{"scan", "nope"}, "cannot read nope: no such file or directory; pass a directory, configuration files or a plan .json file"},
		{"F2 no configuration", []string{"scan", "empty"}, "no configuration files (.tf, .tf.json, .tofu, .tofu.json) in empty; pass the directory that holds them"},
		{"F3 missing plan", []string{"scan", "nope.json"}, "cannot read plan nope.json: no such file or directory; write it with terraform show -json PLANFILE > nope.json (or tofu show -json PLANFILE > nope.json)"},
		{"F4 report --path", []string{"report", "--path", "nope"}, "cannot read configuration directory nope: no such file or directory; check the path"},
		{"F5 verify-lock DIR", []string{"verify-lock", "nope"}, "cannot read configuration directory nope: no such file or directory; check the path"},
		{"F6 catalog", []string{"scan", "--catalog", "nope.yaml", "."}, "cannot read catalog file nope.yaml: no such file or directory; check the path, or pass --catalog embedded"},
		{"F7 exceptions", []string{"scan", "--exceptions", "nope.yaml", "."}, "cannot read exceptions file nope.yaml: no such file or directory; check the path"},
		{"S1 --config", []string{"scan", "--config", "nope.yaml", "."}, "cannot read settings file nope.yaml: no such file or directory; check the path"},
		{"S1 config validate FILE", []string{"config", "validate", "nope.yaml"}, "cannot read settings file nope.yaml: no such file or directory; check the path"},
		{"S2 no .ctfkit.yaml", []string{"config", "validate"}, "cannot read settings file .ctfkit.yaml: no such file or directory; run ctfkit config init to write one, or name the file"},
		{"S3 not YAML", []string{"config", "validate", "bad.yaml"}, "settings file bad.yaml is not valid YAML (line 1: did not find expected node content); fix it and run again"},
		{"S3 on scan", []string{"scan", "--config", "bad.yaml", "."}, "settings file bad.yaml is not valid YAML (line 1: did not find expected node content); fix it and run again"},
		{"S5 two files", []string{"--config", "bad.yaml", "config", "validate", "main.tf"}, "main.tf and --config bad.yaml name two different settings files; give one of them"},
		{"S6 config init --config", []string{"--config", "x.yaml", "config", "init"}, "--config does not apply to config init, which writes .ctfkit.yaml in the working directory; drop --config"},
		{"R1 report --path", []string{"report", "--path", "ep"}, "no module cache at ep/.terraform/modules/modules.json; run terraform init (or tofu init) in ep, then run the same ctfkit report again"},
		{"R1 report", []string{"report"}, "no module cache at .terraform/modules/modules.json; run terraform init (or tofu init) in the working directory, then run the same ctfkit report again"},
		{"M1 gate plan", []string{"gate", "plan"}, `missing required flags for "ctfkit gate plan": --out, --workspace, --environment, --tf-bin, --org, --profile, --floor, --bundle-dir; see "ctfkit gate plan --help"`},
		{"M1 one flag", with("gate", "plan"), `missing required flag for "ctfkit gate plan": --out; see "ctfkit gate plan --help"`},
		{"M2 gate sign", []string{"gate", "sign"}, `missing required flags for "ctfkit gate sign": --candidate, --workspace, --environment, --tf-bin, --org, --profile, --floor, --bundle-dir, --signer; see "ctfkit gate sign --help"`},
		{"M3 verdict verify", []string{"verdict", "verify"}, `missing required flags for "ctfkit verdict verify": --artifacts, --workspace, --environment, --tf-bin, --org, --profile, --floor, --bundle-dir; see "ctfkit verdict verify --help"`},
		{"M4 apply", []string{"apply"}, `missing required flags for "ctfkit apply": --artifacts, --workspace, --environment, --tf-bin, --org, --profile, --floor, --bundle-dir; see "ctfkit apply --help"`},
		{"M5 evidence ship", []string{"evidence", "ship"}, `missing required flags for "ctfkit evidence ship": --chains, --workspace, --org, --profile, --floor, --bundle-dir, --signer, --receipt; see "ctfkit evidence ship --help"`},
		{"M6 runtask serve", []string{"runtask", "serve"}, `missing required flags for "ctfkit runtask serve": --hmac-key-file, --receipt-dir, --org, --profile, --floor, --bundle-dir; see "ctfkit runtask serve --help"`},
		{"K1 signer scheme", with("gate", "sign", "--candidate", "c", "--signer", "foo:bar"), `--signer scheme "foo" is not supported; use awskms:KEY_ARN`},
		{"K2 signer ARN", with("gate", "sign", "--candidate", "c", "--signer", "awskms:notanarn"), "--signer \"awskms:notanarn\" is not a KMS key ARN; use awskms:arn:PARTITION:kms:REGION:ACCOUNT:key/KEY_ID"},
		{"H1 relative --tf-bin", []string{"gate", "plan", "--out", "o", "--workspace", "w", "--environment", "e", "--tf-bin", "terraform",
			"--org", "bobthecorp", "--profile", "p", "--floor", "f", "--bundle-dir", "b"}, "--tf-bin terraform is not an absolute path; give the full path to the terraform binary"},
		{"H4 --out exists", with("gate", "plan", "--out", "out"), "--out out already exists; name a new directory"},
		{"H8 unknown format", []string{"scan", "-f", "bogus", "."}, `unknown --format "bogus"; use one of sarif, json, text, pretty, junit, spacelift`},
		{"H9 two formats", []string{"version", "-f", "text,json"}, `--format names 2 formats, and "ctfkit version" writes one; use one of text, pretty, json`},
		{"H10 unknown --fail-on", []string{"scan", "--fail-on", "bogus", "."}, `unknown --fail-on "bogus"; use one of error, warning, note, never`},
		{"H11 --out with two formats", []string{"scan", "--out", "x", "-f", "json,sarif", "."}, "--out writes one file, and --format names 2 formats; use --out-dir to write one file per format"},
		{"H12 two directories", []string{"scan", "empty", "ep"}, "more than one configuration directory given (empty, ep); scan one per run"},
		{"H13 unknown --provider", []string{"verify-lock", "--provider", "bogus", "."}, `unknown --provider "bogus"; use one of aws, azurerm, google`},
		{"H14 post_init", []string{"scan", "--stage", "post_init", "."}, "--stage post_init is not a scan stage; after terraform init (or tofu init), run ctfkit report"},
		{"H15 post_plan without a plan", []string{"scan", "--stage", "post_plan", "."}, "--stage post_plan needs a plan; pass --plan FILE or a .json file from terraform show -json (or tofu show -json)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runScanIn(t, diagnosticsDir(t), tc.args...)
			if got.code != ExitEnvironment || got.err == nil || got.err.Error() != tc.want {
				t.Errorf("exit %d, error %v\nwant exit 2, %q", got.code, got.err, tc.want)
			}
		})
	}

	t.Run("H3 TF_CLI_ARGS", func(t *testing.T) {
		t.Setenv("TF_CLI_ARGS", "-x")
		got := runScanIn(t, diagnosticsDir(t), with("gate", "plan", "--out", "o")...)
		if want := "TF_CLI_ARGS is set, and ctfkit runs terraform with no extra arguments; unset it and run again"; got.err == nil || got.err.Error() != want {
			t.Errorf("error %v, want %q", got.err, want)
		}
	})
}

// TestGroupCommandHelp: a command that only groups others still prints its
// help and exits 0, with the usage line it had.
func TestGroupCommandHelp(t *testing.T) {
	got := runScanIn(t, t.TempDir(), "gate")
	if got.code != ExitOK || !strings.Contains(got.stdout, "Usage:\n  ctfkit gate [command]\n") || strings.Contains(got.stdout, "ctfkit gate [flags]") {
		t.Errorf("ctfkit gate: exit %d (%v)\n%s", got.code, got.err, got.stdout)
	}
}

// TestVerifyLockFooter: verify-lock reads no catalog, so its text report
// does not name one.
func TestVerifyLockFooter(t *testing.T) {
	got := runScanIn(t, diagnosticsDir(t), "verify-lock", "lockdir", "-f", "text")
	if got.code != ExitFindings || !strings.HasSuffix(got.stdout, "\nstage pre_plan\n") {
		t.Errorf("exit %d (%v), stdout:\n%s", got.code, got.err, got.stdout)
	}
}

// awsOpError and awsAPIError stand in for the smithy operation and API errors
// the AWS SDK returns; the API text names the caller, as the real one does.
type awsOpError struct {
	service, op string
	err         error
}

func (e *awsOpError) Error() string {
	return "operation error " + e.service + ": " + e.op + ", " + e.err.Error()
}
func (e *awsOpError) Service() string   { return e.service }
func (e *awsOpError) Operation() string { return e.op }
func (e *awsOpError) Unwrap() error     { return e.err }

type awsAPIError struct{ code string }

func (e *awsAPIError) Error() string {
	return "api error " + e.code + ": User: arn:aws:sts::111122223333:assumed-role/ci/run is not authorized"
}
func (e *awsAPIError) ErrorCode() string { return e.code }

// errNoIdentity is the text the SDK gives a credential chain that found nothing.
var errNoIdentity = errors.New("get identity: get credentials: failed to refresh cached credentials, no EC2 IMDS role found")

// TestSignerAWSFailure: a KMS failure names the operation, the key and the
// failure class, and never the SDK text or the caller.
func TestSignerAWSFailure(t *testing.T) {
	const arn = "arn:aws:kms:eu-west-1:111122223333:key/abcd"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"no credentials", &awsOpError{"KMS", "GetPublicKey", errNoIdentity},
			"AWS KMS GetPublicKey on " + arn + " failed (no credentials in the default AWS credential chain); configure AWS credentials for this run, such as AWS_PROFILE or a role"},
		{"refused", &awsOpError{"KMS", "Sign", &awsAPIError{"AccessDeniedException"}},
			"AWS KMS Sign on " + arn + " failed with credentials from the default AWS credential chain (AccessDeniedException); check those credentials and the key policy"},
		{"other code", &awsOpError{"KMS", "Sign", &awsAPIError{"DisabledException"}},
			"AWS KMS Sign on " + arn + " failed (DisabledException); check the key --signer names, then run again"},
		{"no answer", &awsOpError{"KMS", "GetPublicKey", context.DeadlineExceeded},
			"AWS KMS GetPublicKey on " + arn + " failed (the request did not complete); check the network path to AWS and run again"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := fmt.Errorf("kms key %s: %s: %w", arn, "Sign", tc.err)
			if got := signerError("awskms:"+arn, wrapped, "%v").Message; got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
	if got := signerError("test:x", errors.New("signer key: kid unknown"), "run manifest: %v").Message; got != "run manifest: signer key: kid unknown" {
		t.Errorf("a non-AWS failure: %q", got)
	}
}

// TestSinkFailureLines: the evidence sink warnings word AWS failures without
// the SDK text, and say what became of the object.
func TestSinkFailureLines(t *testing.T) {
	denied := &awsOpError{"S3", "PutObject", &awsAPIError{"AccessDenied"}}
	const deniedText = "AWS S3 PutObject failed with credentials from the default AWS credential chain (AccessDenied); check those credentials and the bucket policy"
	spoolErr := fmt.Errorf("spool k: %w", &fs.PathError{Op: "open", Path: ".ctfkit/spool/x", Err: fs.ErrPermission})
	for _, tc := range []struct {
		name, got, want string
	}{
		{"spooled", objectFailure(fmt.Errorf("%w: k: %w", sink.ErrSpooled, denied), true), "spooled for the next run: " + deniedText},
		{"not spooled", objectFailure(errors.Join(denied, spoolErr), true),
			"upload not confirmed and not spooled (spool write: permission denied): " + deniedText + "; also check that this user can write " + spoolDir + ", and check whether the object reached the bucket"},
		{"spool write", spoolFailure(errors.New("spool k: disk full")), "could not be spooled (spool k: disk full); check " + spoolDir + " and the free disk space"},
		{"not AWS", sinkFailure(errors.New("evidence object k exists with a different digest"), true),
			"evidence object k exists with a different digest; check the bucket and its object lock settings"},
		{"retry", drainFailure(fmt.Errorf("drain %s: %w", "bobthecorp/default/r/m.json", denied)),
			"object bobthecorp/default/r/m.json stays spooled: " + deniedText},
		{"retry, unreadable entry", drainFailure(errors.New("spool entry x.json: corrupt")), "spool entry x.json: corrupt; check it, then move it out of " + spoolDir + " to stop this warning"},
		{"retry, entry with a wide mode", drainFailure(errors.New("spool entry x.json: mode 0644 is wider than 0600")),
			"spool entry x.json: mode 0644 is wider than 0600; fix the owner, mode or read error and leave the entry in " + spoolDir + ", which the next run retries"},
		{"retry, spool directory", drainFailure(errors.New("spool .ctfkit/spool: permission denied")), "spool .ctfkit/spool: permission denied"},
		{"retry, canceled", drainFailure(context.Canceled), context.Canceled.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got  %q\nwant %q", tc.got, tc.want)
			}
			if strings.Contains(tc.got, "arn:aws:sts") {
				t.Errorf("the line names the caller: %q", tc.got)
			}
		})
	}
}

// TestEvidenceShipSinkWarnings: a refused put and a preflight with no
// credentials, through evidence ship.
func TestEvidenceShipSinkWarnings(t *testing.T) {
	tc := shipCases["enforced"]
	const sinkName = "s3://bobthecorp-evidence/compliancetf/"
	t.Run("put refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		_, stderr, _ := runShip(t, "enforced", tc, &fakeS3{putErr: &awsOpError{"S3", "PutObject", &awsAPIError{"AccessDenied"}}}, &fakeAPI{}, "")
		want := " spooled for the next run: AWS S3 PutObject failed with credentials from the default AWS credential chain (AccessDenied); check those credentials and the bucket policy\n"
		if !strings.Contains(stderr, "ctfkit: warning: evidence sink "+sinkName+": object ") || !strings.Contains(stderr, want) || strings.Contains(stderr, "arn:aws:sts") {
			t.Errorf("stderr:\n%s", stderr)
		}
	})
	t.Run("no credentials", func(t *testing.T) {
		t.Chdir(t.TempDir())
		_, stderr, _ := runShip(t, "enforced", tc, &fakeS3{lockErr: &awsOpError{"S3", "GetObjectLockConfiguration", errNoIdentity}}, &fakeAPI{}, "")
		want := "ctfkit: warning: evidence sink " + sinkName + " skipped, its objects spooled for the next run: " +
			"AWS S3 GetObjectLockConfiguration failed (no credentials in the default AWS credential chain); configure AWS credentials for this run, such as AWS_PROFILE or a role\n"
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr:\n%s", stderr)
		}
	})
}

// TestOpenS3NoRegion: with no region anywhere the sink is skipped with the
// step that fixes it, and no SDK text.
func TestOpenS3NoRegion(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"AWS_CONFIG_FILE": empty, "AWS_SHARED_CREDENTIALS_FILE": empty,
		"AWS_REGION": "", "AWS_DEFAULT_REGION": "", "AWS_PROFILE": ""} {
		t.Setenv(k, v)
	}
	_, err := openS3(context.Background(), "b")
	if want := "no AWS region in the default AWS configuration; set AWS_REGION"; err == nil || err.Error() != want {
		t.Errorf("openS3 = %v, want %q", err, want)
	}
}
