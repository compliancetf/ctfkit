package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/gate"
	"github.com/compliancetf/ctfkit/internal/graph"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/sign"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
	keyjson "github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
)

type gateSignOptions struct {
	gatePlanOptions
	candidate, signer, failOn, breakGlass string
	format                                string
}

// gateSignFormats are the --format values of gate sign: the graph decisions
// as one line per finding, or as SARIF.
var gateSignFormats = []string{formatText, formatSARIF}

func (c *CLI) gateSignCommand() *cobra.Command {
	opts := &gateSignOptions{format: formatText}
	cmd := &cobra.Command{
		Use:   "sign --candidate DIR --dir DIR --workspace NAME --environment NAME --tf-bin PATH --org ID --profile FILE --floor FILE --bundle-dir DIR --signer URI",
		Short: "Decide a candidate and sign its verdict with your KMS key (preview)",
		Long: `Decide a candidate artifact set (preview) and write verdict.json into
--candidate, signed with the key --signer names (your AWS KMS key). gate sign
verifies the set gate plan wrote and the signed inputs, runs terraform version,
init and show -json on a sealed copy of the planfile (no plan, no apply),
recomputes its instance keys and decides every graph control of the verified
bundles. terraform may use the network and your backend credentials, and
signing calls AWS KMS. verdict.json is the only file it writes; the graph
decisions print to stdout, unsigned, as SARIF with --format sarif.

Refuses (exit 2, no verdict.json written) when:
  - a flag is missing, TF_CLI_ARGS is set, or --break-glass is given
  - --candidate already holds a verdict.json
  - the candidate or a signed input does not verify, or names another org,
    workspace or environment
  - --tf-bin is not the terraform binary gate plan ran
  - the --signer key is not one of the profile's verdict keys, is revoked, or
    KMS does not sign

Exit codes:
  0  verdict.json written and signed; the verdict admits the plan
  1  the plan does not pass, or a graph finding is at or above --fail-on
  2  could not run, or refused

On exit 1: verdict.json is written and signed, except when a governed profile's
plan uses the upstream hashicorp/aws provider directly; then no verdict.json is
written: move those resources to the compliance.tf provider and run gate plan
again. ctfkit apply refuses a verdict that does not admit the plan; a
--fail-on finding changes the exit code only, and the verdict still admits the
plan. A candidate that holds a verdict.json makes a rerun exit 2.

On exit 2: no verdict.json is written, and one already in --candidate is left
as it is. Fix the cause and run gate sign again; a candidate that already holds
a verdict.json was signed before: use that verdict, or run gate plan for a new
candidate.

Details: docs/governed-apply.md`,
		Example: "  ctfkit gate sign --candidate .ctfkit-artifacts --signer awskms:KEY_ARN \\\n" + runFlagsLine + signedFlagsLine,
		Args:    noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.gateSign(cmd, opts)
		},
	}
	f := cmd.Flags()
	once := func(p *string, name, usage string) { f.Var(&onceString{target: p}, name, usage) }
	once(&opts.candidate, "candidate", "Candidate artifact set `DIR` gate plan wrote")
	once(&opts.dir, "dir", "Terraform configuration `DIR` of the candidate (default \".\")")
	once(&opts.workspace, "workspace", workspaceUsage)
	once(&opts.environment, "environment", environmentUsage)
	once(&opts.tfBin, "tf-bin", tfBinUsage)
	once(&opts.org, "org", orgUsage)
	once(&opts.profile, "profile", profileUsage)
	once(&opts.floor, "floor", floorUsage)
	once(&opts.bundleDir, "bundle-dir", cisBundleUsage)
	once(&opts.signer, "signer", "Signer `URI` of your verdict key: awskms:KEY_ARN")
	once(&opts.failOn, "fail-on", "Exit 1 when a graph finding is at or above this `LEVEL`: error (default), warning or note")
	once(&opts.breakGlass, "break-glass", "Approved break-glass override `VALUE` (planned: refused in this build)")
	f.VarP(&onceString{target: &opts.format}, "format", "f", "Output `FORMAT` of the graph decisions: "+strings.Join(gateSignFormats, " or "))
	return cmd
}

// gateSign signs a candidate. Every refusal happens before the signer runs,
// and verdict.json is the only file it writes.
func (c *CLI) gateSign(cmd *cobra.Command, opts *gateSignOptions) error {
	if opts.breakGlass != "" {
		return inputError("--break-glass is not supported yet: gate sign cannot consume a break-glass override")
	}
	format, err := oneFormat(cmd, opts.format, gateSignFormats)
	if err != nil {
		return err
	}
	opts.format = format // trimmed: renderFindings compares it
	threshold := opts.failOn
	if threshold == "" {
		threshold = "error"
	}
	if _, ok := failOnRank[threshold]; !ok {
		return inputError("unknown --fail-on %q; use one of error, warning, note", opts.failOn)
	}
	if err = checkGatePlanFlags(cmd, &opts.gatePlanOptions, flagValue{"candidate", opts.candidate}, flagValue{"signer", opts.signer}); err != nil {
		return err
	}
	// Clean drops a trailing slash, after which lstat would follow a symlink.
	opts.candidate = filepath.Clean(opts.candidate)
	signer, err := c.openSigner(opts.signer)
	if err != nil {
		return signerError(opts.signer, err, "%v")
	}
	if err = refuseTFCLIArgs(); err != nil {
		return err
	}
	files, cand, _, err := readArtifactSet(opts.candidate, false)
	if errors.Is(err, errSigned) {
		return inputError("--candidate %s already holds a verdict.json; use that verdict, or run ctfkit gate plan for a new candidate", opts.candidate)
	}
	if err != nil {
		return inputError("--candidate %s: %v", opts.candidate, err)
	}
	if cand.OrgID != opts.org || cand.Workspace != opts.workspace || cand.Provenance.Workspace != opts.workspace || cand.Environment != opts.environment {
		return inputError("the candidate is for org %q, workspace %q, environment %q", cand.OrgID, cand.Workspace, cand.Environment)
	}

	ver, set, controls, err := c.signInputs(cmd, &opts.gatePlanOptions, cand)
	if err != nil {
		return err
	}
	if d, derr := fileDigest(opts.tfBin); derr != nil || d != cand.TerraformDigest {
		return inputError("--tf-bin is not the terraform binary gate plan ran")
	}
	if rawDigest(files[artifactSchema]) != cand.SchemaDigest {
		return inputError("schema.json does not match schema_digest")
	}
	schemas, err := keyjson.ParseSchemas(files[artifactSchema])
	if err != nil {
		return inputError("schema.json: %v", err)
	}
	secret, err := instancekey.ParseSecret(files[artifactRunKey])
	if err != nil {
		return inputError("%s: %v", artifactRunKey, err)
	}

	dir, err := filepath.Abs(opts.dir)
	if err != nil {
		return inputError("--dir: %v", err)
	}
	show, tfVersion, err := c.showCandidate(cmd.ErrOrStderr(), opts.tfBin, dir, opts.workspace, files[artifactPlanfile], cand)
	if err != nil {
		return err
	}
	inst, err := candidateInstances(secret, show, schemas)
	if err != nil {
		return err
	}
	got, _ := json.Marshal(inst)
	want, _ := json.Marshal(cand.Instances)
	if !bytes.Equal(got, want) {
		return inputError("candidate.json instances are not the keys of the sealed plan")
	}
	plan, err := loader.ParsePlan(show)
	if err != nil {
		return inputError("terraform show -json: %v", err)
	}
	if ver.Profile.Governed {
		if addrs := bypassed(plan); len(addrs) > 0 {
			return &ExitError{Code: ExitFindings, Message: "gate sign: governed plan uses the upstream hashicorp/aws directly for " +
				strings.Join(addrs, ", ") + "; use the compliance.tf provider. No verdict written"}
		}
	}
	archive, err := loader.LoadConfig(dir)
	if err != nil {
		return environmentError(err)
	}
	versions, err := providerVersions(archive.Lockfile)
	if err != nil {
		return inputError("%v", err)
	}
	leaf, check, err := instancekey.Keys(secret)
	if err != nil {
		return environmentError(err)
	}
	keys, err := keyjson.Instances(leaf, show, schemas)
	if err != nil {
		return inputError("instance keys: %v", err)
	}
	mode := set.modeTable()
	out, err := gate.Build(gate.Input{Plan: plan, Lock: archive.Lockfile, Keys: keys, Controls: controls, Mode: mode,
		Coverable: set.coverable(controls, ver.Profile.FloorMode)})
	if err != nil {
		return inputError("verdict: %v", err)
	}

	doc, err := c.verdictHeader(cand, ver, set, versions, tfVersion, check)
	if err != nil {
		return environmentError(err)
	}
	doc.Instances, doc.Exceptions = out.Instances, out.Exceptions
	outcome := resolve.Resolve(resolve.Decisions{Instances: out.Instances, Required: out.Required}, mode, nil, nil, nil)
	findings, err := graph.Findings(out.Findings)
	if err != nil {
		return categorized(categoryFinding, "%v", err)
	}
	ctfkit.SortFindings(findings)
	report, err := c.renderFindings(findings, opts.format)
	if err != nil {
		return err
	}

	kid, err := sign.KeyID(signer)
	if err == nil && ver.Revocations.KeyRevoked(kid) {
		err = errors.New("the signer's key is revoked")
	}
	var raw []byte
	if err == nil {
		raw, err = sign.Verdict(cmd.Context(), signer, doc, set.keys, ver.Profile.RevokedKIDs, c.now())
	}
	if err != nil {
		return signerError(opts.signer, err, "%v")
	}
	if err = publishVerdict(cmd.OutOrStdout(), opts.candidate, raw, report); err != nil {
		return environmentError(err)
	}
	return gateSignExit(outcome, findings, threshold)
}

// publishVerdict writes verdict.json, syncs the directory and prints the
// report. Any failure after the file exists removes it again, so an exit 2
// leaves nothing written; a verdict that was already there (another run's)
// is never touched.
func publishVerdict(stdout io.Writer, dir string, raw, report []byte) error {
	path := filepath.Join(dir, artifactVerdict)
	err := writeExclusive(path, raw, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("writing the verdict: %w", err)
	}
	if err == nil {
		err = syncDir(dir)
	}
	if err == nil {
		_, err = stdout.Write(report)
	}
	if err != nil {
		return fmt.Errorf("writing the verdict: %w", errors.Join(err, os.Remove(path), syncDir(dir)))
	}
	return nil
}

func refuseTFCLIArgs() error {
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(strings.ToUpper(name), "TF_CLI_ARGS") {
			return inputError("%s is set, and ctfkit runs terraform with no extra arguments; unset it and run again", name)
		}
	}
	return nil
}

// signInputs verifies the signed inputs again and refuses a candidate bound
// to others: profile, bundle set, content digest and floor epoch.
func (c *CLI) signInputs(cmd *cobra.Command, opts *gatePlanOptions, cand *candidate) (*verdict.Verified, *signSettings, []gate.Control, error) {
	in, err := readGateInputs(c.keyring, opts)
	if err != nil {
		return nil, nil, nil, inputError("reading signed inputs: %v", err)
	}
	ver, err := verdict.VerifyInputs(in, c.now())
	if err != nil {
		return nil, nil, nil, inputError("signed inputs refused: %v", err)
	}
	for _, w := range ver.Warnings {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ctfkit: %s\n", w)
	}
	switch {
	case ver.ProfileDigest != cand.ProfileDigest:
		return nil, nil, nil, inputError("the candidate was planned under profile %s, the inputs give %s: re-run gate plan", cand.ProfileDigest, ver.ProfileDigest)
	case ver.BundleDigest != cand.BundleDigest:
		return nil, nil, nil, inputError("the candidate was planned under bundle set %s, the inputs give %s: re-run gate plan", cand.BundleDigest, ver.BundleDigest)
	case strconv.FormatInt(ver.Floor.Epoch, 10) != cand.FloorEpoch:
		return nil, nil, nil, inputError("the candidate was planned at floor epoch %s, the floor statement is at %d: re-run gate plan", cand.FloorEpoch, ver.Floor.Epoch)
	}
	if err = verdict.CheckContentDigest(ver, cand.ContentDigest); err != nil {
		return nil, nil, nil, inputError("%v", err)
	}
	controls, err := bundleControls(ver)
	if err != nil {
		return nil, nil, nil, inputError("%v", err)
	}
	set, err := parseSignSettings(ver.Profile)
	if err == nil {
		err = set.checkScope(opts.workspace, opts.environment)
	}
	if err != nil {
		return nil, nil, nil, inputError("%v", err)
	}
	return ver, set, controls, nil
}

// showCandidate shows the candidate's planfile through a fresh terraform
// session: version, init, the planfile sealed and shown. It refuses another
// terraform version, plan format version or digest than the candidate's.
func (c *CLI) showCandidate(stderr io.Writer, tf, dir, workspace string, planfile []byte, cand *candidate) ([]byte, string, error) {
	run, err := newTFRun(context.Background(), tf, cand.TerraformDigest, dir, workspace)
	if err != nil {
		return nil, "", inputError("terraform run directory: %v", err)
	}
	defer func() {
		if cerr := run.cleanup(); cerr != nil {
			_, _ = fmt.Fprintf(stderr, "ctfkit: removing the terraform run directory: %v\n", cerr)
		}
	}()
	if rawDigest(planfile) != cand.PlanDigest {
		return nil, "", inputError("planfile does not match plan_digest")
	}
	res, err := run.show(stderr, planfile)
	if err != nil {
		return nil, "", err
	}
	if res.tfVersion != cand.TerraformVersion || res.formatVersion != cand.PlanFormatVersion {
		return nil, "", inputError("terraform %s shows plan format %s; the candidate has terraform %s, format %s",
			res.tfVersion, res.formatVersion, cand.TerraformVersion, cand.PlanFormatVersion)
	}
	return res.show, res.tfVersion, nil
}

// verdictHeader fills every verdict member but the instances and the
// signature.
func (c *CLI) verdictHeader(cand *candidate, ver *verdict.Verified, set *signSettings, versions map[string]string, tfVersion string, check [32]byte) (*verdict.Document, error) {
	var nonce, runID [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(runID[:]); err != nil {
		return nil, err
	}
	prov, err := json.Marshal(cand.Provenance)
	if err != nil {
		return nil, err
	}
	now := c.now().UTC().Truncate(time.Second)
	return &verdict.Document{Format: verdict.Format, OrgID: cand.OrgID, Workspace: cand.Workspace, Environment: cand.Environment,
		RunID: hex.EncodeToString(runID[:]),
		// shortcut: gate plan records no cloud caller yet (scope binding comes
		// later), so the caller is empty, never an unverified value.
		Caller:     json.RawMessage(`{"account_id":"","role_arn":"","region":""}`),
		PlanDigest: cand.PlanDigest, Provenance: prov, PlanFormatVersion: cand.PlanFormatVersion,
		ProfileDigest: ver.ProfileDigest, BundleDigest: ver.BundleDigest, ContentDigest: cand.ContentDigest,
		FloorEpoch: cand.FloorEpoch, ProviderVersions: versions, TerraformVersion: tfVersion,
		Nonce:    base64.RawURLEncoding.EncodeToString(nonce[:]),
		IssuedAt: now.Format("2006-01-02T15:04:05Z"), ExpiresAt: now.Add(set.ttl).Format("2006-01-02T15:04:05Z"),
		InstanceKeyCheck: instancekey.KeyCheck(check), Baselines: []verdict.BaselineRef{}, BreakGlassReceipts: []json.RawMessage{}}, nil
}

// bypassed lists the changes a governed plan routes around the compliance.tf
// provider: any resource of hashicorp/aws from either registry (A29), the
// addresses verify-lock exempts in the lock file (boundUpstream).
func bypassed(plan *tfjson.Plan) []string {
	var out []string
	for _, rc := range plan.ResourceChanges {
		if rc != nil && (strings.EqualFold(rc.ProviderName, "registry.terraform.io/hashicorp/aws") ||
			strings.EqualFold(rc.ProviderName, "registry.opentofu.org/hashicorp/aws")) {
			out = append(out, rc.Address)
		}
	}
	return out
}

// graphRule is the tool.driver.rules entry of the graph findings gate sign
// prints with --format sarif.
var graphRule = sarif.RuleDescriptor{ID: graph.RuleID, Level: ctfkit.LevelError,
	ShortDescription: "A target resource has no linked companion resource its graph control requires"}

// renderFindings renders the graph findings before anything is signed:
// SARIF with --format sarif, else one line per finding that is not a pass.
func (c *CLI) renderFindings(findings ctfkit.Findings, format string) ([]byte, error) {
	if format == formatSARIF {
		doc, err := sarif.Render(sarif.Input{Tool: sarif.Tool{Name: "ctfkit", Version: c.version}, Findings: findings,
			Rules:    []sarif.RuleDescriptor{graphRule},
			Metadata: loader.DetectRunMetadata(os.Getenv, c.now(), loader.RunFlags{})})
		if err != nil {
			return nil, categorized(categoryFinding, "%v", err)
		}
		return doc, nil
	}
	var b bytes.Buffer
	for _, f := range findings {
		if f.Kind != ctfkit.KindPass {
			fmt.Fprintf(&b, "%s: %s\n", f.Level, f.Message.Text)
		}
	}
	return b.Bytes(), nil
}

// gateSignExit: 0 when Resolve admits the plan and no finding reaches the
// threshold, else 1. The threshold changes the exit code only, never what
// the verdict admits at apply.
func gateSignExit(outcome resolve.Outcome, findings ctfkit.Findings, threshold string) error {
	if outcome.Refuse {
		return &ExitError{Code: ExitFindings, Message: "gate sign: the plan does not pass: " + blockingRows(outcome)}
	}
	for _, f := range findings {
		if failOnRank[f.Level] >= failOnRank[threshold] && f.Kind != ctfkit.KindPass {
			return &ExitError{Code: ExitFindings, Message: "gate sign: graph findings at or above --fail-on " + threshold}
		}
	}
	return nil
}
