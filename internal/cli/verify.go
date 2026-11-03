package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/gate"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
	keyjson "github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
)

type applyOptions struct {
	gatePlanOptions
	artifacts, baselineKeyFile string
}

func (c *CLI) verdictCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "verdict", Short: "Check an artifact set without applying it (preview)"}
	cmd.AddCommand(c.signedSetCommand(false))
	return cmd
}

const verdictVerifyLong = `Run every check of ctfkit apply on an artifact set and apply nothing (preview).
It reads the set in --artifacts, the signed inputs and the --dir lock file, and
runs terraform version, init and show -json on a sealed copy of the planfile
(no plan, no apply); terraform may use the network and your backend
credentials. The artifact set is left as it is.

Refuses (exit 2) when ctfkit apply would:
  - the verdict does not verify, is not bound to this candidate, or blocks a
    change
  - an exception or break-glass receipt in the verdict has expired
  - the --dir lock file fails the verify-lock rules
  - the set was applied before, or ctfkit apply has started on it

Exit codes:
  0  ctfkit apply would run terraform apply on this set
  2  could not run, or refused

On exit 2: nothing is applied or changed; stderr names the check that failed.
Fix it and run verdict verify again, or run gate plan and gate sign for a new
set.

Details: docs/governed-apply.md`

const applyLong = `Apply the sealed plan of a checked artifact set, at most once (preview). apply
first takes the set's owner lock and claims the set, then runs every check of
ctfkit verdict verify on --artifacts and terraform apply on its sealed copy of
the planfile; terraform uses the network and your cloud credentials. The
verdict and its key reach the terraform child only, through COMPLIANCETF_VERDICT
and COMPLIANCETF_VERDICT_KEY_FILE. Once the set is claimed, every exit records
the outcome in result.json, tombstones the set and removes ctfkit-run.key, so a
refused check also consumes the set.

Refuses (exit 2, nothing applied) when:
  - the verdict does not verify, is not bound to this candidate, or blocks a
    change
  - an exception or break-glass receipt in the verdict has expired
  - the --dir lock file fails the verify-lock rules
  - the set was applied before (it is tombstoned)
  - an earlier apply on the set died; apply ends that run, which consumes the
    set

Exit codes:
  0  terraform apply succeeded; outcome enforced
  1  infrastructure may have changed and the set is consumed: terraform apply
     failed or was interrupted (outcome failed), succeeded with a decision
     pending a post-apply check that is not available yet (outcome failed), or
     succeeded under a break-glass receipt (outcome overridden)
  2  could not run, or refused

On exit 2: stderr names the cause. A flag error, or another apply holding the
lock, leaves the set as it is: fix it and run apply again. Any other exit 2
needs a new set: run gate plan and gate sign. Exit 2 can also follow a terraform
apply that already ran, when apply cannot write result.json or the tombstone or
remove ctfkit-run.key: infrastructure may have changed, so read
docs/governed-apply.md before you retry.

Details: docs/governed-apply.md`

// signedSetCommand is ctfkit apply (apply) or ctfkit verdict verify: both
// take the same flags and run the same checks; only apply runs terraform
// apply and consumes the artifact set.
func (c *CLI) signedSetCommand(apply bool) *cobra.Command {
	opts := &applyOptions{}
	use := "verify --artifacts DIR --dir DIR --workspace NAME --environment NAME --tf-bin PATH --org ID --profile FILE --floor FILE --bundle-dir DIR"
	short := "Run every check of apply on an artifact set, apply nothing (preview)"
	long := verdictVerifyLong
	example := "  ctfkit verdict verify --artifacts .ctfkit-artifacts \\\n" + runFlagsLine + signedFlagsLine
	if apply {
		use = "apply" + strings.TrimPrefix(use, "verify")
		short = "Apply the sealed plan of a checked artifact set (preview)"
		long = applyLong
		example = "  ctfkit apply --artifacts .ctfkit-artifacts \\\n" + runFlagsLine + signedFlagsLine
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Long: long, Example: example, Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if apply {
				return c.apply(cmd, opts)
			}
			return c.verdictVerify(cmd, opts)
		},
	}
	f := cmd.Flags()
	once := func(p *string, name, usage string) { f.Var(&onceString{target: p}, name, usage) }
	once(&opts.artifacts, "artifacts", "Artifact set `DIR` gate plan wrote, with the verdict.json of gate sign")
	once(&opts.dir, "dir", "Terraform configuration `DIR` of the candidate (default \".\")")
	once(&opts.workspace, "workspace", workspaceUsage)
	once(&opts.environment, "environment", environmentUsage)
	once(&opts.tfBin, "tf-bin", tfBinUsage)
	once(&opts.org, "org", orgUsage)
	once(&opts.profile, "profile", profileUsage)
	once(&opts.floor, "floor", floorUsage)
	once(&opts.bundleDir, "bundle-dir", cisBundleUsage)
	if apply {
		once(&opts.baselineKeyFile, "baseline-key-file",
			"Org baseline key `FILE` from the runner secret store, passed to the terraform apply child only")
	}
	return cmd
}

// readSigned checks the flags and reads the exact signed artifact set. dir
// is set once --artifacts resolved, also on an error.
func readSigned(cmd *cobra.Command, opts *applyOptions) (dir string, files map[string][]byte, cand *candidate, custody []string, err error) {
	if err = checkGatePlanFlags(cmd, &opts.gatePlanOptions, flagValue{"artifacts", opts.artifacts}); err != nil {
		return "", nil, nil, nil, err
	}
	dir, err = filepath.Abs(opts.artifacts) // Abs cleans: a trailing slash would make lstat follow a symlink
	if err != nil {
		return "", nil, nil, nil, inputError("--artifacts: %v", err)
	}
	if err = refuseTFCLIArgs(); err != nil {
		return "", nil, nil, nil, err
	}
	files, cand, custody, err = readArtifactSet(dir, true)
	if errors.Is(err, errTombstoned) {
		return dir, nil, nil, nil, errTombstonedSet{inputError("--artifacts %s: %v", opts.artifacts, err)}
	}
	if err != nil {
		return dir, nil, nil, nil, inputError("--artifacts %s: %v", opts.artifacts, err)
	}
	if cand.OrgID != opts.org || cand.Workspace != opts.workspace || cand.Provenance.Workspace != opts.workspace || cand.Environment != opts.environment {
		return "", nil, nil, nil, inputError("the candidate is for org %q, workspace %q, environment %q", cand.OrgID, cand.Workspace, cand.Environment)
	}
	return dir, files, cand, custody, nil
}

// signedRun is a checked artifact set: its verdict, the whole-plan outcome
// and the terraform session holding the sealed planfile. Fields fill in as
// the checks pass.
type signedRun struct {
	doc     *verdict.Document
	outcome *resolve.Outcome
	run     *tfRun
}

func (s *signedRun) cleanup(stderr io.Writer) {
	if s.run == nil {
		return
	}
	if err := s.run.cleanup(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ctfkit: removing the terraform run directory: %v\n", err)
	}
}

// checkSigned runs every check before terraform apply. Every check that
// needs no terraform runs first: the verdict, its binding, the signed
// inputs, the decisions and the expiry recheck; then the sealed planfile is
// shown and the verdict must list exactly its managed changes.
func (c *CLI) checkSigned(cmd *cobra.Command, opts *applyOptions, files map[string][]byte, cand *candidate) (*signedRun, error) {
	s := &signedRun{}
	raw := files[artifactVerdict]
	doc, err := verdict.Parse(raw)
	if err != nil {
		return s, inputError("verdict.json: %v", err)
	}
	s.doc = doc
	if err = checkBinding(doc, cand); err != nil {
		return s, inputError("verdict.json is not the verdict of this candidate: %v", err)
	}
	ver, set, controls, err := c.signInputs(cmd, &opts.gatePlanOptions, cand)
	if err != nil {
		return s, err
	}
	if ver.Revocations.KeyRevoked(doc.Signature.Kid) {
		return s, inputError("verdict.json: %v", verdict.ErrKidRevoked)
	}
	now := c.now()
	if err = verdict.Verify(raw, doc.Signature, set.keys, ver.Profile.RevokedKIDs, "verdict", now); err != nil {
		return s, inputError("verdict.json signature: %v", err)
	}
	if exp, perr := time.Parse(time.RFC3339, doc.ExpiresAt); perr != nil || !now.Before(exp) {
		return s, inputError("verdict.json expired at %s: run gate plan and gate sign again", doc.ExpiresAt)
	}
	if d, derr := fileDigest(opts.tfBin); derr != nil || d != cand.TerraformDigest {
		return s, inputError("--tf-bin is not the terraform binary gate plan ran")
	}
	if rawDigest(files[artifactSchema]) != cand.SchemaDigest {
		return s, inputError("schema.json does not match schema_digest")
	}
	secret, err := instancekey.ParseSecret(files[artifactRunKey])
	if err != nil {
		return s, inputError("%s: %v", artifactRunKey, err)
	}
	leaf, check, err := instancekey.Keys(secret)
	if err != nil {
		return s, environmentError(err)
	}
	if instancekey.KeyCheck(check) != doc.InstanceKeyCheck {
		return s, inputError("%s does not belong to verdict.json (instance_key_check)", artifactRunKey)
	}

	in := gate.Input{Controls: controls, Mode: set.modeTable(), Coverable: set.coverable(controls, ver.Profile.FloorMode)}
	required := gate.Required(in, doc.Instances)
	// shortcut: no exception, baseline or receipt is verified yet (gate sign
	// lists none), so a provisional decision blocks, as at gate sign.
	outcome := resolve.Resolve(resolve.Decisions{Instances: doc.Instances, Required: required}, in.Mode, nil, nil, nil)
	s.outcome = &outcome
	if outcome.Refuse {
		return s, inputError("the verdict does not admit the plan: %s; nothing applied", blockingRows(outcome))
	}
	if err = c.recheckExpiry(cmd.Context(), ver, doc); err != nil {
		return s, err
	}

	dir, err := filepath.Abs(opts.dir)
	if err != nil {
		return s, inputError("--dir: %v", err)
	}
	if err = c.verifyRootLock(cmd.Context(), dir); err != nil {
		return s, err
	}
	if s.run, err = newTFRun(cmd.Context(), opts.tfBin, cand.TerraformDigest, dir, opts.workspace); err != nil {
		return s, inputError("terraform run directory: %v", err)
	}
	planfile := files[artifactPlanfile]
	if rawDigest(planfile) != doc.PlanDigest {
		return s, inputError("planfile does not match the verdict's plan_digest; nothing applied")
	}
	res, err := s.run.show(cmd.ErrOrStderr(), planfile)
	if err != nil {
		return s, err
	}
	if res.tfVersion != cand.TerraformVersion || res.formatVersion != cand.PlanFormatVersion {
		return s, inputError("terraform %s shows plan format %s; the candidate has terraform %s, format %s",
			res.tfVersion, res.formatVersion, cand.TerraformVersion, cand.PlanFormatVersion)
	}
	return s, checkComplete(res.show, files, cand, doc, leaf, in, dir)
}

// checkBinding: the verdict names the candidate's scope, plan, inputs,
// versions and provenance.
func checkBinding(doc *verdict.Document, cand *candidate) error {
	prov, err := json.Marshal(cand.Provenance)
	if err == nil {
		prov, err = jcs.Transform(prov)
	}
	if err != nil {
		return err
	}
	docProv, err := jcs.Transform(doc.Provenance)
	if err != nil {
		return err
	}
	for _, f := range []struct{ name, got, want string }{
		{"org_id", doc.OrgID, cand.OrgID}, {"workspace", doc.Workspace, cand.Workspace},
		{"environment", doc.Environment, cand.Environment}, {"plan_digest", doc.PlanDigest, cand.PlanDigest},
		{"plan_format_version", doc.PlanFormatVersion, cand.PlanFormatVersion},
		{"profile_digest", doc.ProfileDigest, cand.ProfileDigest}, {"bundle_digest", doc.BundleDigest, cand.BundleDigest},
		{"content_digest", doc.ContentDigest, cand.ContentDigest}, {"floor_epoch", doc.FloorEpoch, cand.FloorEpoch},
		{"terraform_version", doc.TerraformVersion, cand.TerraformVersion}, {"provenance", string(docProv), string(prov)},
	} {
		if f.got != f.want {
			return fmt.Errorf("%s differs", f.name)
		}
	}
	return nil
}

// checkComplete refuses a verdict that does not list exactly the managed
// changes of the sealed plan, deposed objects included, with the action and
// keys gate plan computed for each, and candidate.json instances that are
// not the keys of the sealed plan.
func checkComplete(show []byte, files map[string][]byte, cand *candidate, doc *verdict.Document, leaf [32]byte, in gate.Input, dir string) error {
	schemas, err := keyjson.ParseSchemas(files[artifactSchema])
	if err != nil {
		return inputError("schema.json: %v", err)
	}
	keys, err := keyjson.Instances(leaf, show, schemas)
	if err != nil {
		return inputError("instance keys: %v", err)
	}
	plan, err := loader.ParsePlan(show)
	if err != nil {
		return inputError("terraform show -json: %v", err)
	}
	archive, err := loader.LoadConfig(dir)
	if err != nil {
		return environmentError(err)
	}
	in.Plan, in.Lock, in.Keys = plan, archive.Lockfile, keys
	built, err := gate.Build(in)
	if err != nil {
		return inputError("the sealed plan: %v", err)
	}
	var s instancekey.Secret
	if s, err = instancekey.ParseSecret(files[artifactRunKey]); err != nil {
		return inputError("%s: %v", artifactRunKey, err)
	}
	inst, err := candidateInstances(s, show, schemas)
	if err != nil {
		return err
	}
	got, _ := json.Marshal(inst)
	want, _ := json.Marshal(cand.Instances)
	if !bytes.Equal(got, want) {
		return inputError("candidate.json instances are not the keys of the sealed plan")
	}
	if ref := firstDifference(built.Instances, doc.Instances); ref != "" {
		return inputError("verdict.json does not list exactly the plan's managed changes: %s; nothing applied", ref)
	}
	return nil
}

// firstDifference names the first change the plan and the verdict do not
// agree on, "" when they list the same changes with the same identity.
func firstDifference(plan, signed []verdict.Instance) string {
	ident := func(list []verdict.Instance) map[string]string {
		m := map[string]string{}
		for _, i := range list {
			i.Decisions, i.DeleteDecisions, i.NotEvaluable = nil, nil, nil
			i.Exceptions, i.Baselines, i.BreakGlass = nil, nil, nil
			b, _ := json.Marshal(i)
			m[gate.Ref(i.Address, i.Deposed)] = string(b)
		}
		return m
	}
	p, s := ident(plan), ident(signed)
	if len(signed) != len(s) {
		return "a change is listed twice"
	}
	for _, ref := range slices.Sorted(maps.Keys(p)) {
		switch v, ok := s[ref]; {
		case !ok:
			return ref + " is missing"
		case v != p[ref]:
			return ref + " differs from the plan"
		}
	}
	for _, ref := range slices.Sorted(maps.Keys(s)) {
		if _, ok := p[ref]; !ok {
			return ref + " is not in the plan"
		}
	}
	return ""
}

// recheckExpiry judges every exception and break-glass receipt the verdict
// lists at the run's time source, never the local clock: Evidence API time
// under floor_mode online (unavailable: no apply), the accepted floor
// statement's issued_at under airgap. The listed approvals are not in the
// artifact set; their expiry was judged at gate sign.
func (c *CLI) recheckExpiry(ctx context.Context, ver *verdict.Verified, doc *verdict.Document) error {
	var at time.Time
	source := "Evidence API time"
	switch ver.Profile.FloorMode {
	case verdict.FloorAirgap:
		// shortcut: one floor statement per run, so the maximum accepted
		// issued_at is its issued_at; a high-water mark kept across runs
		// (never regressing) comes with the run custody task.
		at, source = ver.Floor.IssuedAt, "the floor statement's issued_at (floor_mode airgap)"
		if len(doc.BreakGlassReceipts) > 0 {
			return inputError("verdict.json embeds a break-glass receipt under floor_mode airgap; nothing applied")
		}
	case verdict.FloorOnline:
		t, err := c.evidenceTime(ctx)
		if err == nil && t.IsZero() {
			err = errors.New("no server time in the answer")
		}
		if err != nil {
			return inputError("floor_mode online needs Evidence API time at apply start: %v; nothing applied", err)
		}
		at = t
	default:
		return inputError("floor_mode %q: want online or airgap", ver.Profile.FloorMode)
	}
	expired := func(what, s string) error {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil || !at.Before(t) {
			return inputError("%s expired at %q by %s %s; nothing applied", what, s, source, at.UTC().Format(time.RFC3339))
		}
		return nil
	}
	for _, e := range doc.Exceptions {
		if err := expired("exception "+e.Digest, e.Expires); err != nil {
			return err
		}
	}
	for _, raw := range doc.BreakGlassReceipts {
		r, err := verdict.ParseReceipt(raw)
		if err != nil {
			return inputError("verdict.json break-glass receipt: %v", err)
		}
		if err = expired("break-glass receipt "+r.OverrideID, r.ExpiresAt); err != nil {
			return err
		}
	}
	return nil
}

// noEvidenceAPI is the Evidence API clock of this build: ctfkit has no
// Evidence API client yet, so floor_mode online refuses (fail closed).
func noEvidenceAPI(context.Context) (time.Time, error) {
	return time.Time{}, errors.New("this build has no Evidence API client")
}

// blockingRows lists the rows that block.
func blockingRows(outcome resolve.Outcome) string {
	var rows []string
	for _, r := range outcome.Rows {
		if r.Severity == resolve.SevError {
			rows = append(rows, fmt.Sprintf("%s %s %s %s", gate.Ref(r.Address, r.Deposed), r.Half, r.Control, r.Result))
		}
	}
	return strings.Join(rows, "; ")
}

func printWarnings(w io.Writer, outcome *resolve.Outcome) {
	for _, r := range outcome.Rows {
		if r.Severity == resolve.SevWarning {
			_, _ = fmt.Fprintf(w, "ctfkit: warning: %s %s %s %s\n", gate.Ref(r.Address, r.Deposed), r.Half, r.Control, r.Result)
		}
	}
}

// verdictVerify runs the checks of ctfkit apply and changes nothing.
func (c *CLI) verdictVerify(cmd *cobra.Command, opts *applyOptions) error {
	_, files, cand, custody, err := readSigned(cmd, opts)
	if err != nil {
		return err
	}
	if i := slices.IndexFunc(custody, func(n string) bool { return n != artifactLock }); i >= 0 {
		return inputError("--artifacts %s holds %s: ctfkit apply ran on it", opts.artifacts, custody[i])
	}
	s, err := c.checkSigned(cmd, opts, files, cand)
	defer s.cleanup(cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	printWarnings(cmd.ErrOrStderr(), s.outcome)
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "verdict verified: %d instances; ctfkit apply would apply the plan\n", len(s.doc.Instances))
	return err
}
