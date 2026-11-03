package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/evidence"
	"github.com/compliancetf/ctfkit/internal/render/receipt"
	"github.com/compliancetf/ctfkit/internal/sign"
	"github.com/compliancetf/ctfkit/internal/sink"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// spoolDir holds evidence objects whose put failed, retried by the next run.
var spoolDir = filepath.Join(".ctfkit", "spool")

// alertBreakGlassDegraded is raised when a run with a break-glass record has
// degraded evidence.
const alertBreakGlassDegraded = "break_glass_evidence_degraded"

// alertEvidenceTampered is raised when the chains fail verification.
const alertEvidenceTampered = "evidence_tampered"

type evidenceShipOptions struct {
	inputs                             gatePlanOptions // org, profile, floor, bundle dir, workspace
	chains, receipt, signer, artifacts string
	sinks                              []string
	api                                bool
}

// evidenceIngest is the Evidence API run ingest: a POST of the signed run
// manifest, idempotent on its digest, answered by a signed ack the client
// verifies. ctfkit checks what the ack acknowledges.
type evidenceIngest interface {
	IngestRun(ctx context.Context, manifest []byte) (ingestAck, error)
}

// ingestAck is a verified ack.
type ingestAck struct {
	ManifestDigest string // sha256:<hex> of the manifest bytes acknowledged
	NonceReused    bool   // the verdict nonce was seen in another run
}

// noIngest is the Evidence API client of this build: there is none, so a
// run with --api fails its API post (fail closed) and spools the manifest.
type noIngest struct{}

func (noIngest) IngestRun(context.Context, []byte) (ingestAck, error) {
	return ingestAck{}, errors.New("this build has no Evidence API client")
}

// apiSink ships the run manifest to the Evidence API through the sink
// interface, so a failed post spools and retries like an upload.
type apiSink struct {
	api         evidenceIngest
	nonceReused bool
}

func (*apiSink) Name() string                    { return "compliancetf-evidence-api" }
func (*apiSink) Preflight(context.Context) error { return nil }

func (a *apiSink) Put(ctx context.Context, obj sink.Object) (sink.Receipt, error) {
	ack, err := a.api.IngestRun(ctx, obj.Body)
	if err != nil {
		return sink.Receipt{}, fmt.Errorf("evidence api: %w", err)
	}
	want := rawDigest(obj.Body)
	if ack.ManifestDigest != want {
		return sink.Receipt{}, fmt.Errorf("evidence api acknowledged %s, not the manifest %s", ack.ManifestDigest, want)
	}
	a.nonceReused = a.nonceReused || ack.NonceReused
	return sink.Receipt{Sink: a.Name(), Key: obj.Key, SHA256: strings.TrimPrefix(want, "sha256:")}, nil
}

// openS3 is the S3 client of an evidence sink: the default AWS credential
// chain and region. Its errors are worded for the warning line, with their
// next step, and never carry the SDK text, which can quote a
// credential_process command.
func openS3(ctx context.Context, _ string) (sink.S3API, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, errors.New("cannot load the AWS configuration; check AWS_PROFILE and the AWS config and credentials files")
	}
	if cfg.Region == "" {
		return nil, errors.New("no AWS region in the default AWS configuration; set AWS_REGION")
	}
	return s3.NewFromConfig(cfg), nil
}

func (c *CLI) evidenceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Upload a run's evidence chains and write its receipt (preview)",
	}
	cmd.AddCommand(c.evidenceShipCommand())
	return cmd
}

const evidenceShipLong = `Upload the evidence chains of one run and write its provider-run receipt
(preview). It reads the chains in --chains (EVIDENCE_DIR/RUN_ID/) and the
signed inputs, signs a run manifest with the --signer key (your AWS KMS key),
uploads the chains and the manifest to each --sink, then writes the receipt to
--receipt; the receipt is not signed. It uses the network and your AWS
credentials. The sinks use S3 Object Lock, so uploaded objects cannot be
deleted while their retention lasts. A failed upload is kept under
.ctfkit/spool/ in the working directory and retried on the next run. With
--artifacts, the artifact set ctfkit apply consumed, the run counts as a CI run.

Refuses (exit 2, nothing uploaded, no receipt written) when:
  - a flag is missing, or --receipt exists
  - a signed input does not verify, or the workspace is not the profile's
  - a --sink is not an s3_object_lock sink of the profile's evidence.sinks
  - the --signer key is not one of the profile's verdict keys, or is revoked

Exit codes:
  0  receipt written, status enforced
  1  receipt written with any other status: failed, overridden,
     evidence-degraded or single-resource-only; chains that fail verification
     are not uploaded and the receipt records them as failed
  2  could not run, or refused

On exit 2: stderr names the cause. A refusal uploads nothing and writes no
receipt. A failure after the uploads started leaves the uploaded objects in the
sink and failed uploads in .ctfkit/spool/, and a failed receipt write can leave
a partial or complete --receipt file: do not use it. Fix the cause and run again
with a --receipt path that does not exist; every run, exit 0 and 1 included,
needs a new one.

Details: docs/evidence.md`

func (c *CLI) evidenceShipCommand() *cobra.Command {
	opts := &evidenceShipOptions{}
	cmd := &cobra.Command{
		Use:   "ship --chains DIR --workspace NAME --org ID --profile FILE --floor FILE --bundle-dir DIR --signer URI --receipt FILE [--sink URI]... [--api] [--artifacts DIR]",
		Short: "Upload a run's evidence chains and write its receipt (preview)",
		Long:  evidenceShipLong,
		Example: `  ctfkit evidence ship --chains /var/lib/ctfkit/evidence/RUN_ID --artifacts .ctfkit-artifacts \
    --workspace default --signer awskms:KEY_ARN --receipt receipt.json \
    --sink s3://bobthecorp-evidence/ctfkit \
` + signedFlagsLine,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.evidenceShip(cmd, opts)
		},
	}
	f := cmd.Flags()
	once := func(p *string, name, usage string) { f.Var(&onceString{target: p}, name, usage) }
	once(&opts.chains, "chains", "`DIR` of one run's provider evidence chain files")
	once(&opts.inputs.workspace, "workspace", "Terraform workspace `NAME` of the run")
	once(&opts.inputs.org, "org", orgUsage)
	once(&opts.inputs.profile, "profile", profileUsage)
	once(&opts.inputs.floor, "floor", floorUsage)
	once(&opts.inputs.bundleDir, "bundle-dir", bundleDirUsage)
	once(&opts.signer, "signer", "Signer `URI` of the run manifest key, one of the profile's verdict keys: awskms:KEY_ARN")
	once(&opts.receipt, "receipt", "Provider-run receipt `FILE` to write; must not exist")
	once(&opts.artifacts, "artifacts", "Artifact set `DIR` ctfkit apply consumed for this run (runner class ci)")
	f.StringArrayVar(&opts.sinks, "sink", nil, "Evidence sink `URI` s3://bucket/prefix from the profile's evidence.sinks (repeatable)")
	f.Var(&onceBool{target: &opts.api}, "api", "Post the run manifest to the Evidence API (planned: this build has no client and spools the post)")
	f.Lookup("api").NoOptDefVal = "true"
	return cmd
}

// shipRun is what one evidence ship run found.
type shipRun struct {
	conditions []string
	sinks      []receipt.SinkRef
	reason     string
	alerts     []string
}

// reRunID is a run id the receipt may take from the --chains directory name.
var reRunID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// fallbackRunID is the run of chains no authenticated verdict names: the
// base name of the --chains directory when it is a plain id, else unknown.
func fallbackRunID(chains string) string {
	if name := filepath.Base(filepath.Clean(chains)); reRunID.MatchString(name) {
		return name
	}
	return "unknown"
}

// bindChains refuses chains that are not of the authenticated verdict's run:
// every record's run id must be the verdict's, every record the provider
// binds to the verdict (evidence.Chain.Unbound: eval records at apply_pre)
// must name it, and every non-null digests.verdict, on any record kind and
// stage, must be the verdict's digest, so relabeling a record's kind or stage
// does not dodge the binding.
func bindChains(chains []evidence.Chain, auth artifactAuth) error {
	for _, ch := range chains {
		if ch.RunID != auth.runID {
			return fmt.Errorf("chain %s: %w: run %q, the verdict's run is %q", ch.Chain, evidence.ErrTampered, ch.RunID, auth.runID)
		}
		if ch.Unbound > 0 {
			return fmt.Errorf("chain %s: %w: %d record(s) that must name the verdict name none", ch.Chain, evidence.ErrTampered, ch.Unbound)
		}
		for _, d := range ch.VerdictDigests {
			if d != auth.verdictDigest {
				return fmt.Errorf("chain %s: %w: a record names verdict %s, not %s", ch.Chain, evidence.ErrTampered, d, auth.verdictDigest)
			}
		}
	}
	return nil
}

func (r *shipRun) add(cond string) {
	if !slices.Contains(r.conditions, cond) {
		r.conditions = append(r.conditions, cond)
	}
}

func (c *CLI) evidenceShip(cmd *cobra.Command, opts *evidenceShipOptions) error {
	in := opts.inputs
	if err := requireFlags(cmd, flagValue{"chains", opts.chains}, flagValue{"workspace", in.workspace}, flagValue{"org", in.org},
		flagValue{"profile", in.profile}, flagValue{"floor", in.floor}, flagValue{"bundle-dir", in.bundleDir},
		flagValue{"signer", opts.signer}, flagValue{"receipt", opts.receipt}); err != nil {
		return err
	}
	// Checked first so nothing ships for a run whose receipt cannot be written;
	// the write itself is still exclusive.
	if _, err := os.Lstat(opts.receipt); !errors.Is(err, fs.ErrNotExist) {
		return inputError("--receipt %s already exists; name a new file", opts.receipt)
	}
	stderr := cmd.ErrOrStderr()
	ver, set, ev, err := c.shipInputs(stderr, opts)
	if err != nil {
		return err
	}
	chains, err := evidence.ReadChains(opts.chains)
	if err != nil && !evidence.VerifyFailed(err) {
		return inputError("--chains %s: %v", opts.chains, err)
	}
	run := &shipRun{}
	auth := c.classify(stderr, opts, ver, set, run)
	if err == nil && auth.runner == receipt.RunnerCI {
		err = bindChains(chains, auth)
	}
	if err != nil {
		// Chains that fail verification, or that the authenticated verdict
		// does not name, are recorded, not shipped. Their run id is
		// untrusted: the run is the verdict's, else the directory's name.
		runID := auth.runID
		if runID == "" {
			runID = fallbackRunID(opts.chains)
		}
		_, _ = fmt.Fprintf(stderr, "ctfkit: --chains %s: %v; nothing shipped\n", opts.chains, err)
		_, _ = fmt.Fprintf(stderr, "ctfkit: ALERT: the evidence chains of run %s failed verification\n", runID)
		run.reason = "evidence chains failed verification: " + err.Error()
		run.alerts = append(run.alerts, alertEvidenceTampered)
		run.add(receipt.StatusFailed)
		return c.writeRunReceipt(stderr, opts, run, nil, runID, auth.runner, nil)
	}
	runID, runner := chains[0].RunID, auth.runner
	for _, ch := range chains {
		if ch.BreakGlass {
			run.add(receipt.StatusOverridden)
		}
		if len(ch.Missing) > 0 || ch.Breaks > 0 {
			_, _ = fmt.Fprintf(stderr, "ctfkit: chain %s: records missing (terminated %t, breaks %d)\n", ch.Chain, ch.Terminated, ch.Breaks)
			run.add(receipt.StatusEvidenceDegraded)
		}
	}

	signer, err := c.openSigner(opts.signer)
	if err != nil {
		return signerError(opts.signer, err, "%v")
	}
	if kid, kerr := sign.KeyID(signer); kerr == nil && ver.Revocations.KeyRevoked(kid) {
		return inputError("signer key: %v", verdict.ErrKidRevoked)
	}
	prefix := in.org + "/" + in.workspace + "/" + runID + "/"
	for _, p := range []string{in.org, in.workspace, runID} {
		if p == "" || strings.ContainsAny(p, "/\\") || p == "." || p == ".." {
			return inputError("org, workspace and run id must each be one object key segment, not %q", p)
		}
	}
	m := evidence.NewManifest(in.org, in.workspace, runner, c.now().UTC().Format(time.RFC3339), prefix, chains)
	raw, err := sign.Document(cmd.Context(), signer, m, &m.Signature, set.keys, ver.Profile.RevokedKIDs, c.now())
	if err != nil {
		return signerError(opts.signer, err, "run manifest: %v")
	}
	manifestKey := prefix + "manifest-" + strings.TrimPrefix(rawDigest(raw), "sha256:") + ".json"
	objects := []sink.Object{}
	for _, ch := range chains {
		for _, s := range ch.Segments {
			objects = append(objects, sink.Object{Key: prefix + s.Name, Body: s.Body})
		}
	}
	objects = append(objects, sink.Object{Key: manifestKey, Body: raw})

	api, err := c.ship(cmd.Context(), stderr, opts, ev, objects, run)
	if err != nil {
		return err
	}
	if api != nil && api.nonceReused {
		_, _ = fmt.Fprintln(stderr, "ctfkit: the Evidence API flagged the run's nonce as reused by another run")
		run.add(receipt.StatusFailed)
	}
	return c.writeRunReceipt(stderr, opts, run, chains, runID, runner, &receipt.ManifestRef{
		Key: manifestKey, Kid: m.Signature.Kid, SHA256: strings.TrimPrefix(rawDigest(raw), "sha256:")})
}

// evidenceSettings is the profile's evidence object.
type evidenceSettings struct {
	Required bool         `json:"required"`
	Sinks    []sinkConfig `json:"sinks"`
}

type sinkConfig struct {
	Type             string `json:"type"`
	Bucket           string `json:"bucket"`
	Prefix           string `json:"prefix"`
	MinRetentionDays int    `json:"min_retention_days"`
}

// name is the sink identity sink.S3 reports, or type:bucket for a sink type
// this build cannot ship to.
func (s sinkConfig) name() string {
	if s.Type != "s3_object_lock" {
		return s.Type + ":" + s.Bucket
	}
	p := s.Prefix
	if p == "" {
		p = "compliancetf/"
	}
	return "s3://" + s.Bucket + "/" + strings.TrimSuffix(p, "/") + "/"
}

// shipInputs verifies the signed inputs and reads the profile's verdict keys
// and evidence settings.
func (c *CLI) shipInputs(stderr io.Writer, opts *evidenceShipOptions) (*verdict.Verified, *signSettings, *evidenceSettings, error) {
	in, err := readGateInputs(c.keyring, &opts.inputs)
	if err != nil {
		return nil, nil, nil, inputError("reading signed inputs: %v", err)
	}
	ver, err := verdict.VerifyInputs(in, c.now())
	if err != nil {
		return nil, nil, nil, inputError("signed inputs refused: %v", err)
	}
	for _, w := range ver.Warnings {
		_, _ = fmt.Fprintf(stderr, "ctfkit: %s\n", w)
	}
	set, err := parseSignSettings(ver.Profile)
	if err != nil {
		return nil, nil, nil, inputError("%v", err)
	}
	if set.scope.Workspace != "" && set.scope.Workspace != opts.inputs.workspace {
		return nil, nil, nil, inputError("workspace %q is not the profile's workspace %q", opts.inputs.workspace, set.scope.Workspace)
	}
	ev := &evidenceSettings{}
	if len(ver.Profile.Evidence) > 0 {
		if err = json.Unmarshal(ver.Profile.Evidence, ev); err != nil {
			return nil, nil, nil, inputError("profile evidence: %v", err)
		}
	}
	return ver, set, ev, nil
}

// artifactAuth is what an authenticated --artifacts set gives the run: runner
// class ci, the verdict's run id and digest (sha256 over JCS of verdict.json,
// as the provider's digests.verdict names it). Local has none of them.
type artifactAuth struct {
	runner, runID, verdictDigest string
}

// classify sets the runner class and the conditions it implies. ci needs an
// --artifacts set that authenticates (appliedOutcome); anything else is
// local, which fails closed under verdict_required.
func (c *CLI) classify(stderr io.Writer, opts *evidenceShipOptions, ver *verdict.Verified, set *signSettings, run *shipRun) artifactAuth {
	if opts.artifacts != "" {
		outcome, auth, err := c.appliedOutcome(opts, ver, set)
		if err == nil {
			switch outcome {
			case outcomeEnforced:
			case outcomeOverridden:
				run.add(receipt.StatusOverridden)
			default: // failed, or refused: nothing a receipt can call enforced
				run.add(receipt.StatusFailed)
			}
			return auth
		}
		_, _ = fmt.Fprintf(stderr, "ctfkit: --artifacts %s does not authenticate (%v): runner class local\n", opts.artifacts, err)
	}
	if ver.Profile.VerdictRequired {
		run.add(receipt.StatusFailed) // a local run is not preventive: under verdict_required it fails closed
	} else {
		run.add(receipt.StatusSingleResourceOnly)
	}
	return artifactAuth{runner: receipt.RunnerLocal}
}

// appliedOutcome authenticates the --artifacts set and returns the apply
// outcome it records. Its verdict.json must check against the profile's
// verdict keys (kid not revoked) and name this org and workspace; its
// result.json and tombstone must name that verdict's run (and the result its
// plan) and agree on the outcome; ctfkit-run.key must be gone, so the set is
// one ctfkit apply consumed. The chains are bound to the verdict afterwards
// (bindChains).
func (c *CLI) appliedOutcome(opts *evidenceShipOptions, ver *verdict.Verified, set *signSettings) (string, artifactAuth, error) {
	var none artifactAuth
	dir := opts.artifacts
	raw, err := readCapped(filepath.Join(dir, artifactVerdict), maxSchemaBytes)
	if err != nil {
		return "", none, fmt.Errorf("%s: %w", artifactVerdict, err)
	}
	doc, err := verdict.Parse(raw)
	if err != nil {
		return "", none, fmt.Errorf("%s: %w", artifactVerdict, err)
	}
	if ver.Revocations.KeyRevoked(doc.Signature.Kid) {
		return "", none, fmt.Errorf("%s: %w", artifactVerdict, verdict.ErrKidRevoked)
	}
	if err = verdict.Verify(raw, doc.Signature, set.keys, ver.Profile.RevokedKIDs, "verdict", c.now()); err != nil {
		return "", none, fmt.Errorf("%s: %w", artifactVerdict, err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", none, fmt.Errorf("%s: %w", artifactVerdict, err)
	}
	res, err := readJSON[applyResult](filepath.Join(dir, artifactResult))
	if err != nil {
		return "", none, fmt.Errorf("%s: %w", artifactResult, err)
	}
	tomb, err := readJSON[tombstone](filepath.Join(dir, artifactTombstone))
	if err != nil {
		return "", none, fmt.Errorf("not consumed by ctfkit apply: %s: %w", artifactTombstone, err)
	}
	switch {
	case doc.OrgID != opts.inputs.org || doc.Workspace != opts.inputs.workspace:
		return "", none, fmt.Errorf("the verdict is of org %q workspace %q", doc.OrgID, doc.Workspace)
	case res.RunID != doc.RunID || res.PlanDigest != doc.PlanDigest:
		return "", none, fmt.Errorf("%s is not of the verdict's run and plan", artifactResult)
	case tomb.RunID != doc.RunID || tomb.Outcome != res.Outcome:
		return "", none, fmt.Errorf("%s and %s disagree", artifactResult, artifactTombstone)
	case inSet(dir, artifactRunKey):
		return "", none, fmt.Errorf("%s is still there: ctfkit apply did not consume the set", artifactRunKey)
	}
	return res.Outcome, artifactAuth{runner: receipt.RunnerCI, runID: doc.RunID, verdictDigest: rawDigest(canon)}, nil
}

// ship drains the spool, then uploads objects to every --sink and posts the
// manifest (the last object) to the Evidence API with --api. A sink of the
// profile not shipped to, a failed preflight and a spooled put make the run
// evidence-degraded; a profile with no sink shipped to does too.
func (c *CLI) ship(ctx context.Context, stderr io.Writer, opts *evidenceShipOptions, ev *evidenceSettings, objects []sink.Object, run *shipRun) (*apiSink, error) {
	type target struct {
		sk      sink.Sink
		objects []sink.Object
		openErr error
	}
	var targets []target
	named := map[string]bool{}
	for _, uri := range opts.sinks {
		bucket, prefix, err := sink.ParseS3URI(uri)
		if err != nil {
			return nil, inputError("--sink: %v", err)
		}
		want := sinkConfig{Type: "s3_object_lock", Bucket: bucket, Prefix: prefix}.name()
		i := slices.IndexFunc(ev.Sinks, func(s sinkConfig) bool { return s.name() == want })
		if i < 0 {
			return nil, inputError("--sink %s is not an s3_object_lock sink of the profile's evidence.sinks", uri)
		}
		if named[want] {
			return nil, inputError("--sink %s is given twice", uri)
		}
		named[want] = true
		api, openErr := c.openS3(ctx, bucket)
		s3sink, err := sink.NewS3(api, sink.S3Config{Bucket: bucket, Prefix: prefix, MinRetentionDays: ev.Sinks[i].MinRetentionDays, Now: c.now})
		if err != nil {
			return nil, inputError("profile evidence sink: %v", err)
		}
		targets = append(targets, target{sk: s3sink, objects: objects, openErr: openErr})
	}
	for _, s := range ev.Sinks {
		if !named[s.name()] {
			_, _ = fmt.Fprintf(stderr, "ctfkit: evidence sink %s of the profile was not shipped to\n", s.name())
			run.add(receipt.StatusEvidenceDegraded)
		}
	}
	if len(targets) == 0 {
		_, _ = fmt.Fprintln(stderr, "ctfkit: no evidence sink was shipped to")
		run.add(receipt.StatusEvidenceDegraded)
	}
	var api *apiSink
	if opts.api {
		api = &apiSink{api: c.evidenceAPI}
		targets = append(targets, target{sk: api, objects: objects[len(objects)-1:]})
	}

	sp, err := sink.OpenSpool(spoolDir)
	if err != nil {
		return nil, environmentError(err)
	}
	// Earlier runs' objects first; their outcome does not change this run's.
	drain := make([]sink.Sink, 0, len(targets))
	for _, t := range targets {
		if t.openErr != nil {
			continue
		}
		if a, ok := t.sk.(*apiSink); ok {
			drain = append(drain, &apiSink{api: a.api}) // an earlier run's ack does not flag this one
		} else {
			drain = append(drain, t.sk)
		}
	}
	if shipped, derr := sp.Drain(ctx, drain...); len(shipped) > 0 || derr != nil {
		_, _ = fmt.Fprintf(stderr, "ctfkit: spool: %d earlier object(s) shipped\n", len(shipped))
		for _, e := range joined(derr) {
			_, _ = fmt.Fprintf(stderr, "ctfkit: warning: spool: %s\n", drainFailure(e))
		}
	}
	for _, t := range targets {
		ref := receipt.SinkRef{Name: t.sk.Name()}
		_, isS3 := t.sk.(*sink.S3)
		failed, reason := t.openErr, ""
		if failed != nil {
			reason = failed.Error() // worded by openS3, with its step
		} else if failed = t.sk.Preflight(ctx); failed != nil {
			reason = sinkFailure(failed, isS3)
		}
		unspooled := 0
		for _, obj := range t.objects {
			if failed != nil {
				err = sp.Add(t.sk.Name(), obj) // the sink is not usable this run: keep the object for the next
			} else {
				_, err = sink.Ship(ctx, t.sk, sp, obj)
			}
			switch {
			case err == nil && failed == nil:
				ref.Shipped++
			case err == nil || errors.Is(err, sink.ErrSpooled):
				ref.Spooled++
				run.add(receipt.StatusEvidenceDegraded)
			default:
				run.add(receipt.StatusEvidenceDegraded)
			}
			if err == nil {
				continue
			}
			line := objectFailure(err, isS3)
			if failed != nil {
				unspooled++
				line = spoolFailure(err)
			}
			_, _ = fmt.Fprintf(stderr, "ctfkit: warning: evidence sink %s: object %s %s\n", t.sk.Name(), obj.Key, line)
		}
		if failed != nil {
			outcome := "skipped, its objects spooled for the next run"
			if unspooled > 0 {
				outcome = fmt.Sprintf("skipped, and %d of its objects could not be spooled (see above)", unspooled)
			}
			_, _ = fmt.Fprintf(stderr, "ctfkit: warning: evidence sink %s %s: %s\n", t.sk.Name(), outcome, reason)
		}
		run.sinks = append(run.sinks, ref)
	}
	return api, nil
}

// writeRunReceipt raises the break-glass alert, writes the receipt once and
// fsyncs it and its directory, and returns the exit: nil only for enforced.
func (c *CLI) writeRunReceipt(stderr io.Writer, opts *evidenceShipOptions, run *shipRun, chains []evidence.Chain, runID, runner string, m *receipt.ManifestRef) error {
	alerts := slices.Clone(run.alerts)
	if slices.Contains(run.conditions, receipt.StatusOverridden) && slices.Contains(run.conditions, receipt.StatusEvidenceDegraded) {
		alerts = append(alerts, alertBreakGlassDegraded)
		_, _ = fmt.Fprintf(stderr, "ctfkit: ALERT: run %s used break-glass and its evidence is degraded\n", runID)
	}
	refs := make([]receipt.ChainRef, 0, len(chains))
	for _, ch := range chains {
		ref := receipt.ChainRef{Breaks: ch.Breaks, Chain: ch.Chain, FirstSeq: ch.FirstSeq, LastHash: ch.LastHash,
			LastSeq: ch.LastSeq, Records: ch.Records, Terminated: ch.Terminated}
		for _, r := range ch.Missing {
			ref.Missing = append(ref.Missing, receipt.SeqRange{From: r.From, To: r.To})
		}
		refs = append(refs, ref)
	}
	body, err := receipt.RenderProviderRun(receipt.ProviderRun{
		Generator:  receipt.Generator{Name: "ctfkit", Version: c.version},
		Run:        receipt.RunInfo{ID: runID, OrgID: opts.inputs.org, Workspace: opts.inputs.workspace, RunnerClass: runner, Now: c.now()},
		Conditions: run.conditions, Chains: refs, Sinks: run.sinks, Manifest: m, Alerts: alerts, Reason: run.reason,
	})
	if err == nil {
		err = writeExclusive(opts.receipt, body, 0o600)
	}
	if err == nil {
		err = syncDir(filepath.Dir(opts.receipt))
	}
	if err != nil {
		return environmentError(fmt.Errorf("--receipt %s: %w", opts.receipt, err))
	}
	status := receipt.Status(run.conditions)
	if status != receipt.StatusEnforced {
		return &ExitError{Code: ExitFindings, Message: "receipt status " + status + " (conditions: " + strings.Join(run.conditions, ", ") + ")"}
	}
	return nil
}
