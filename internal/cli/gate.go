package cli

import (
	"context"
	"crypto/sha256"
	_ "embed"
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
	"testing/fstest"

	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
	keyjson "github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
)

// releaseKeyring is the trust anchor VerifyInputs checks bundle manifests,
// profiles and floor statements against: a byte copy of the provider's
// internal/trust/keyring.json. No flag or env replaces it.
//
//go:embed release_keyring.json
var releaseKeyring []byte

// Artifact set of a candidate (phase 3, two-stage gate).
const (
	artifactPlanfile  = "planfile"
	artifactRunKey    = "ctfkit-run.key"
	artifactFindings  = "findings.sarif"
	artifactCandidate = "candidate.json"
	artifactSchema    = "schema.json" // terraform providers schema -json output gate sign reads
	candidateFormat   = "compliancetf.candidate/v1"
	maxPlanBytes      = 1 << 30 // planfile and its show -json output
	maxSchemaBytes    = 1 << 28 // terraform providers schema -json output
)

type gatePlanOptions struct {
	dir, out, workspace, environment, tfBin string
	org, profile, floor, bundleDir          string
	reapDir                                 string // gate plan only
}

func (c *CLI) gateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Plan a candidate and decide its verdict",
		Long: `Governed apply in three steps : gate plan runs terraform plan and
writes a candidate artifact set, gate sign decides the candidate and writes
verdict.json, signed with the key --signer names (your AWS KMS key), and ctfkit
apply applies the sealed plan. ctfkit verdict verify runs the checks of apply
and applies nothing. Findings, SARIF, JSON and receipts are not signed;
compliance.tf does not sign, attest or verify anything for you.

Details: docs/governed-apply.md`,
	}
	cmd.AddCommand(c.gatePlanCommand())
	cmd.AddCommand(c.gateSignCommand())
	return cmd
}

// Flag usage the governed apply commands share.
const (
	dirUsage         = "Terraform configuration `DIR` (default \".\")"
	workspaceUsage   = "Terraform workspace `NAME` of the candidate"
	environmentUsage = "Environment `NAME` of the candidate"
	tfBinUsage       = "Absolute `PATH` of the terraform or tofu binary gate plan ran"
	orgUsage         = "Org `ID` the profile and bundles must name"
	profileUsage     = "Signed org profile `FILE` (DSSE envelope)"
	floorUsage       = "Signed floor statement `FILE` (DSSE envelope)"
	bundleDirUsage   = "`DIR` holding one directory per signed bundle"
	cisBundleUsage   = "`DIR` holding one directory per signed bundle, the provider's CIS bundle included"
	signedFlagsLine  = "    --org bobthecorp --profile profile.dsse.json --floor floor.dsse.json --bundle-dir bundles/"
	runFlagsLine     = "    --dir infra --workspace default --environment prod --tf-bin /usr/bin/terraform \\\n"
)

const gatePlanLong = `Run terraform plan and write a candidate artifact set to --out. gate
plan verifies the signed bundles, org profile and floor statement, checks the
--dir lock file with the verify-lock rules, then runs terraform init, providers
schema -json, plan and show -json in a run directory ctfkit owns and removes
afterwards; terraform may use the network and your cloud credentials. It reads
the configuration and .ctfkit.yaml in --dir, and writes planfile, schema.json,
ctfkit-run.key, findings.sarif and candidate.json to --out. Findings do not
change the exit code. With --reap-dir it also tombstones the orphaned artifact
sets of this org and profile under that DIR before terraform runs; they stay
tombstoned whatever the exit code.

Refuses (exit 2, no artifact set written) when:
  - a flag is missing, --tf-bin is not absolute, or --out exists
  - TF_CLI_ARGS is set: no terraform flag passes through, so targeted,
    -replace, -exclude and refresh-off plans cannot be made
  - a signed input does not verify or names another org
  - the --dir lock file fails the verify-lock rules
  - the plan has an instance the key format cannot name

Exit codes:
  0  candidate written (provider warnings included)
  1  terraform plan failed; no artifact set is written
  2  could not run, or refused

On exit 2: no artifact set is left in --out. Fix the cause (an --out that
exists: pick a new one) and run gate plan again.

Details: docs/governed-apply.md`

func (c *CLI) gatePlanCommand() *cobra.Command {
	opts := &gatePlanOptions{}
	cmd := &cobra.Command{
		Use:     "plan --out DIR --workspace NAME --environment NAME --tf-bin PATH --org ID --profile FILE --floor FILE --bundle-dir DIR",
		Short:   "Run terraform plan and write a candidate artifact set",
		Long:    gatePlanLong,
		Example: "  ctfkit gate plan --out .ctfkit-artifacts \\\n" + runFlagsLine + signedFlagsLine,
		Args:    noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.gatePlan(cmd, opts)
		},
	}
	f := cmd.Flags()
	once := func(p *string, name, usage string) { f.Var(&onceString{target: p}, name, usage) }
	once(&opts.dir, "dir", dirUsage)
	once(&opts.out, "out", "Artifact `DIR` to create; must not exist")
	once(&opts.workspace, "workspace", "Terraform workspace `NAME` the plan runs in")
	once(&opts.environment, "environment", "Environment `NAME` the candidate is for")
	once(&opts.tfBin, "tf-bin", "Absolute `PATH` of the terraform or tofu binary")
	once(&opts.org, "org", orgUsage)
	once(&opts.profile, "profile", profileUsage)
	once(&opts.floor, "floor", floorUsage)
	once(&opts.bundleDir, "bundle-dir", bundleDirUsage)
	once(&opts.reapDir, "reap-dir", "First tombstone the orphaned artifact sets of this org and profile under `DIR` (warnings only)")
	return cmd
}

// gatePlan creates the candidate. Every check that needs no terraform runs
// first; --out is created only once terraform produced an allowlisted plan,
// candidate.json is written last, and any error removes --out, so a refused
// run leaves nothing and a set without candidate.json is never complete.
func (c *CLI) gatePlan(cmd *cobra.Command, opts *gatePlanOptions) error {
	if err := checkGatePlanFlags(cmd, opts, flagValue{"out", opts.out}); err != nil {
		return err
	}
	if err := refuseTFCLIArgs(); err != nil {
		return err
	}
	dir, err := filepath.Abs(opts.dir)
	if err != nil {
		return inputError("--dir: %v", err)
	}
	if _, err = os.Lstat(opts.out); !errors.Is(err, fs.ErrNotExist) {
		return inputError("--out %s already exists; name a new directory", opts.out)
	}
	tfDigest, err := fileDigest(opts.tfBin)
	if err != nil {
		return inputError("--tf-bin: %v", err)
	}

	in, err := readGateInputs(c.keyring, opts)
	if err != nil {
		return inputError("reading signed inputs: %v", err)
	}
	ver, err := verdict.VerifyInputs(in, c.now())
	if err != nil {
		return inputError("signed inputs refused: %v", err)
	}
	for _, w := range ver.Warnings {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ctfkit: %s\n", w)
	}
	contentDigest, err := verdict.ContentDigest(ver)
	if err != nil {
		return inputError("content digest: %v", err)
	}
	if opts.reapDir != "" {
		c.reapOrphans(cmd.ErrOrStderr(), opts, ver)
	}

	if err = c.verifyRootLock(cmd.Context(), dir); err != nil {
		return err
	}
	run, err := newTFRun(context.Background(), opts.tfBin, tfDigest, dir, opts.workspace)
	if err != nil {
		return inputError("terraform run directory: %v", err)
	}
	defer func() {
		if cerr := run.cleanup(); cerr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ctfkit: removing the terraform run directory: %v\n", cerr)
		}
	}()
	res, err := run.plan(cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	secret, err := instancekey.NewSecret()
	if err != nil {
		return environmentError(err)
	}
	instances, err := candidateInstances(secret, res.show, res.schemas)
	if err != nil {
		return err
	}

	findings, err := c.gateFindings(cmd, dir, res.show)
	if err != nil {
		return err
	}

	if err = os.Mkdir(opts.out, 0o700); err != nil {
		return inputError("--out: %v", err)
	}
	cand := candidate{
		Format: candidateFormat, Kind: "plan",
		OrgID: opts.org, Workspace: opts.workspace, Environment: opts.environment,
		PlanDigest: res.planDigest, PlanFormatVersion: res.formatVersion,
		TerraformVersion: res.tfVersion, TerraformDigest: tfDigest,
		ProfileDigest: ver.ProfileDigest, BundleDigest: ver.BundleDigest,
		ContentDigest: contentDigest, FloorEpoch: strconv.FormatInt(ver.Floor.Epoch, 10),
		SchemaDigest: rawDigest(res.schema), Instances: instances,
		Provenance: provenance{
			Tool: "ctfkit gate plan", Refresh: "true", Targeted: "false",
			ArgvDigest: res.argvDigest, TerraformVersion: res.tfVersion, Workspace: opts.workspace,
		},
	}
	if err = writeCandidate(opts.out, secret, res, findings, &cand); err != nil {
		return inputError("writing the artifact set: %v", errors.Join(err, os.RemoveAll(opts.out)))
	}
	return nil
}

// reapOrphans runs the reaper over --reap-dir with this profile's
// verdict.max_ttl. Its notes are warnings; it never changes the exit code.
func (c *CLI) reapOrphans(stderr io.Writer, opts *gatePlanOptions, ver *verdict.Verified) {
	settings, err := parseSignSettings(ver.Profile)
	root, aerr := filepath.Abs(opts.reapDir)
	out, oerr := filepath.Abs(opts.out)
	if err = errors.Join(err, aerr, oerr); err != nil {
		_, _ = fmt.Fprintf(stderr, "ctfkit: warning: --reap-dir: %v\n", err)
		return
	}
	for _, n := range reap(root, out, opts.org, ver.ProfileDigest, settings.ttl, c.now()) {
		_, _ = fmt.Fprintf(stderr, "ctfkit: warning: %s\n", n)
	}
}

// checkGatePlanFlags refuses a run that lacks a required flag: lead, the
// command's own first flag, then the flags gate plan, gate sign, verdict
// verify and apply share, then extra.
func checkGatePlanFlags(cmd *cobra.Command, opts *gatePlanOptions, lead flagValue, extra ...flagValue) error {
	if opts.dir == "" {
		opts.dir = "."
	}
	flags := append([]flagValue{lead, {"workspace", opts.workspace}, {"environment", opts.environment},
		{"tf-bin", opts.tfBin}, {"org", opts.org}, {"profile", opts.profile},
		{"floor", opts.floor}, {"bundle-dir", opts.bundleDir}}, extra...)
	if err := requireFlags(cmd, flags...); err != nil {
		return err
	}
	if !filepath.IsAbs(opts.tfBin) {
		return inputError("--tf-bin %s is not an absolute path; give the full path to the terraform binary", opts.tfBin)
	}
	return nil
}

// readGateInputs reads every signed input once through one root fs.
func readGateInputs(keyring []byte, opts *gatePlanOptions) (verdict.Inputs, error) {
	var rel [3]string
	root := ""
	for i, p := range []string{opts.profile, opts.floor, opts.bundleDir} {
		abs, err := filepath.Abs(p)
		if err != nil {
			return verdict.Inputs{}, err
		}
		r := filepath.VolumeName(abs) + string(filepath.Separator)
		if root != "" && r != root {
			return verdict.Inputs{}, errors.New("--profile, --floor and --bundle-dir must be on one volume")
		}
		root, rel[i] = r, filepath.ToSlash(strings.TrimPrefix(abs, r))
	}
	kfs := keyringFS{os.DirFS(root), fstest.MapFS{keyringName: {Data: keyring, Mode: 0o444}}}
	return verdict.ReadInputs(kfs, opts.org, keyringName, rel[0], rel[1], rel[2])
}

// keyringFS serves the embedded keyring under keyringName beside the disk,
// so ReadInputs reads it with the same bounds as every other input and no
// file on disk is a trust anchor.
type keyringFS struct {
	fs.FS
	keyring fstest.MapFS
}

// keyringName would be a file at the filesystem root, which a run never reads.
const keyringName = ":keyring"

func (k keyringFS) Open(name string) (fs.File, error) {
	if name == keyringName {
		return k.keyring.Open(name)
	}
	return k.FS.Open(name)
}

// gateFindings runs the post_plan scan analyzers over the plan terraform
// showed and renders SARIF. Findings never change gate plan's exit code: the
// provider evaluates resource-local controls at plan and gate sign decides
// graph controls. No local exception file applies.
func (c *CLI) gateFindings(cmd *cobra.Command, dir string, show []byte) ([]byte, error) {
	plan, err := loader.ParsePlan(show)
	if err != nil {
		return nil, inputError("terraform show -json: %v", err)
	}
	settings, err := c.loadSettings(dir)
	if err != nil {
		return nil, err
	}
	cat, version, err := catalog.Resolve("")
	if err != nil {
		return nil, environmentError(err)
	}
	archive, err := loader.LoadConfig(dir)
	if err != nil {
		return nil, environmentError(err)
	}
	archive.ClassifyModules = true
	if err = parseConfig(archive); err != nil {
		return nil, err
	}
	metadata := loader.DetectRunMetadata(os.Getenv, c.now(), loader.RunFlags{})
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, Config: archive, PlanJSON: plan,
		Catalog: cat, Settings: settings.Settings(), Metadata: metadata}
	findings, err := runAnalyzers(cmd.Context(), newScanRegistry(), in, nil, cat, metadata.Now)
	if err != nil {
		return nil, err
	}
	ctfkit.SortFindings(findings)
	doc, err := sarif.Render(sarif.Input{Tool: sarif.Tool{Name: "ctfkit", Version: c.version},
		Rules: scanRules(), Findings: findings, Metadata: metadata, Catalog: version})
	if err != nil {
		return nil, categorized(categoryFinding, "%v", err)
	}
	return doc, nil
}

// candidate is candidate.json. Every value is a string, array or object, as
// in verdict-1, so its JCS bytes never meet the number rules.
type candidate struct {
	Format            string            `json:"format"`
	Kind              string            `json:"kind"`
	OrgID             string            `json:"org_id"`
	Workspace         string            `json:"workspace"`
	Environment       string            `json:"environment"`
	PlanDigest        string            `json:"plan_digest"`
	PlanFormatVersion string            `json:"plan_format_version"`
	TerraformVersion  string            `json:"terraform_version"`
	TerraformDigest   string            `json:"terraform_digest"`
	ProfileDigest     string            `json:"profile_digest"`
	BundleDigest      string            `json:"bundle_digest"`
	ContentDigest     string            `json:"content_digest"`
	FloorEpoch        string            `json:"floor_epoch"`
	SchemaDigest      string            `json:"schema_digest"`
	Instances         []candidateEntry  `json:"instances"`
	Provenance        provenance        `json:"provenance"`
	Artifacts         map[string]string `json:"artifacts"`
}

// candidateEntry is one keyed managed change, in the entry shape of the
// instance key goldens (pkg/verdict/testdata/instancekey/FORMAT.md).
type candidateEntry struct {
	Address      string         `json:"address"`
	Deposed      string         `json:"deposed,omitempty"`
	Actions      []string       `json:"actions"`
	ActionReason string         `json:"action_reason,omitempty"`
	Keys         []candidateKey `json:"keys"`
}

type candidateKey struct {
	Field             string     `json:"field"`
	Form              string     `json:"form"`
	Key               string     `json:"key"`
	PriorIdentityKind string     `json:"prior_identity_kind"`
	UnknownPaths      [][]string `json:"unknown_paths"`
}

// candidateInstances keys every managed change of the sealed plan's show
// -json under the run secret. An instance the format refuses is a refusal
// of the run (FORMAT.md: a runtime error, exit 2), so a candidate never
// holds half a replace or a change without its keys.
func candidateInstances(secret instancekey.Secret, show []byte, schemas *keyjson.Schemas) ([]candidateEntry, error) {
	leaf, _, err := instancekey.Keys(secret)
	if err != nil {
		return nil, environmentError(err)
	}
	insts, err := keyjson.Instances(leaf, show, schemas)
	if err != nil {
		return nil, inputError("instance keys: %v", err)
	}
	out := make([]candidateEntry, 0, len(insts))
	var refused []error
	for _, in := range insts {
		if in.Err != nil {
			refused = append(refused, fmt.Errorf("%s%s: %w", in.Address, deposedSuffix(in.Deposed), in.Err))
			continue
		}
		e := candidateEntry{Address: in.Address, Deposed: in.Deposed, Actions: in.Actions, ActionReason: in.ActionReason}
		for _, k := range in.Keys {
			e.Keys = append(e.Keys, candidateKey{Field: k.Field, Form: string(k.Form), Key: k.Key,
				PriorIdentityKind: k.PriorIdentityKind, UnknownPaths: k.UnknownPaths})
		}
		out = append(out, e)
	}
	if refused != nil {
		return nil, inputError("instance keys refused for %d instance(s): %v", len(refused), errors.Join(refused...))
	}
	return out, nil
}

func deposedSuffix(d string) string {
	if d == "" {
		return ""
	}
	return " (deposed " + d + ")"
}

// provenance holds the fields gate plan establishes today; backend, module
// tree, lockfile, caller and state fields come with their binding tasks.
type provenance struct {
	Tool             string `json:"tool"`
	Refresh          string `json:"refresh"`
	Targeted         string `json:"targeted"`
	ArgvDigest       string `json:"argv_digest"`
	TerraformVersion string `json:"terraform_version"`
	Workspace        string `json:"workspace"`
}

// writeCandidate writes the run key, planfile, schema and findings, then
// candidate.json binding their raw digests, then fsyncs the directory.
func writeCandidate(out string, secret instancekey.Secret, res *planResult, findings []byte, cand *candidate) error {
	key, err := secret.Hex()
	if err != nil {
		return err
	}
	cand.Artifacts = map[string]string{}
	for _, a := range []struct {
		name string
		body []byte
	}{{artifactRunKey, []byte(key)}, {artifactPlanfile, res.planfile}, {artifactSchema, res.schema}, {artifactFindings, findings}} {
		if err = writeExclusive(filepath.Join(out, a.name), a.body, 0o600); err != nil {
			return err
		}
		cand.Artifacts[a.name] = rawDigest(a.body)
	}
	doc, err := json.Marshal(cand)
	if err == nil {
		doc, err = jcs.Transform(doc)
	}
	if err != nil {
		return err
	}
	if err = writeExclusive(filepath.Join(out, artifactCandidate), doc, 0o600); err != nil {
		return err
	}
	return syncDir(out)
}

// writeExclusive creates path (never an existing file or symlink), writes
// body and fsyncs it.
func writeExclusive(path string, body []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, mode) // #nosec G304 -- inside a directory this run created
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func rawDigest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// readCapped reads a regular file through one open, refusing more than
// limit bytes.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("larger than %d bytes", limit)
	}
	return b, err
}

// fileDigest is the raw digest of a regular file, streamed from one open.
func fileDigest(path string) (string, error) {
	f, err := openRegular(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
