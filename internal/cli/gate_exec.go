package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"

	"github.com/compliancetf/ctfkit/internal/tfexec"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
	keyjson "github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
)

// tfRun is one gate plan, gate sign or ctfkit apply terraform session under
// the Terraform exec rules (internal/tfexec).
// shortcut: no credential or proxy variable passes (the signed profile has no
// key naming them yet), so a cloud plan fails closed; apply's init is A2
// until the module tree is carried in the artifact set for A15.
type tfRun struct {
	s        *tfexec.Session
	planfile tfexec.Sealed
	applyEnv []string // the apply child's COMPLIANCETF_* only
}

// newTFRun opens a session for tf, pinned to digest. ctx, when set, interrupts
// terraform on cancel (ctfkit apply).
func newTFRun(ctx context.Context, tf, digest, dir, workspace string) (*tfRun, error) {
	s, err := tfexec.Open(tfexec.Config{Terraform: tf, Digest: digest, Dir: dir, Workspace: workspace, Ctx: ctx})
	if err != nil {
		return nil, err
	}
	return &tfRun{s: s}, nil
}

func (r *tfRun) cleanup() error { return r.s.Close() }

// apply runs A6 on the sealed planfile.
func (r *tfRun) apply(stderr io.Writer) error {
	return r.s.Run(tfexec.Apply(r.planfile, r.applyEnv...), nil, stderr)
}

// planResult is what the terraform session produced.
type planResult struct {
	planfile, show, schema               []byte
	schemas                              *keyjson.Schemas
	planDigest, formatVersion, tfVersion string
	argvDigest                           string
}

// plan runs version, init, providers schema and plan, seals the planfile and shows the sealed
// copy. A failing plan is a gate fail (exit 1, no candidate): a blocking
// control the provider reports surfaces only as a plan failure. Every other
// failure is exit 2.
func (r *tfRun) plan(stderr io.Writer) (*planResult, error) {
	res := &planResult{}
	if err := r.versionInit(res, stderr); err != nil {
		return nil, err
	}
	// The schema comes from the same binary, data dir and locked providers
	// that plan runs, never from the caller.
	schema := capped{limit: maxSchemaBytes}
	if err := r.s.Run(tfexec.Schema(), &schema, stderr); err != nil {
		return nil, inputError("terraform providers schema -json: %v", err)
	}
	res.schema = schema.Bytes()
	schemas, err := keyjson.ParseSchemas(res.schema)
	if err != nil {
		return nil, inputError("terraform providers schema -json: %v", err)
	}
	res.schemas = schemas
	if err = r.s.Run(tfexec.Plan(), nil, stderr); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, &ExitError{Code: ExitFindings, Message: "terraform plan failed; no candidate written"}
		}
		return nil, inputError("terraform plan: %v", err)
	}
	// The digest covers the A3 template, not the per-run paths, so a
	// verifier recomputes it from the argv table alone.
	argv, err := json.Marshal(tfexec.Plan().Template())
	if err == nil {
		argv, err = jcs.Transform(argv)
	}
	if err != nil {
		return nil, inputError("argv digest: %v", err)
	}
	res.argvDigest = rawDigest(argv)

	// One read of the owned planfile: the digest, the artifact and the
	// sealed copy show -json reads are the same bytes.
	if r.planfile, res.planfile, err = r.s.SealOwned("planfile", "planfile", maxPlanBytes); err != nil {
		return nil, inputError("sealing the planfile: %v", err)
	}
	res.planDigest = rawDigest(res.planfile)
	return res, r.showSealed(res, stderr)
}

// show is gate sign's session: version and init, then the planfile bytes of
// the candidate sealed and shown.
func (r *tfRun) show(stderr io.Writer, planfile []byte) (*planResult, error) {
	res := &planResult{planfile: planfile, planDigest: rawDigest(planfile)}
	if err := r.versionInit(res, stderr); err != nil {
		return nil, err
	}
	var err error
	if r.planfile, err = r.s.Seal("planfile", planfile); err != nil {
		return nil, inputError("sealing the planfile: %v", err)
	}
	return res, r.showSealed(res, stderr)
}

// versionInit runs version -json, then init.
func (r *tfRun) versionInit(res *planResult, stderr io.Writer) error {
	version := capped{limit: maxPlanBytes}
	if err := r.s.Run(tfexec.Version(), &version, stderr); err != nil {
		return inputError("terraform version -json: %v", err)
	}
	var v struct {
		Version string `json:"terraform_version"`
	}
	if err := json.Unmarshal(version.Bytes(), &v); err != nil || v.Version == "" {
		return inputError("terraform version -json: no terraform_version")
	}
	res.tfVersion = v.Version
	if err := r.s.Run(tfexec.Init(), nil, stderr); err != nil {
		return inputError("terraform init: %v", err)
	}
	return nil
}

// showSealed shows the sealed planfile and checks its format version.
func (r *tfRun) showSealed(res *planResult, stderr io.Writer) error {
	show := capped{limit: maxPlanBytes}
	if err := r.s.Run(tfexec.Show(r.planfile), &show, stderr); err != nil {
		return inputError("terraform show -json: %v", err)
	}
	res.show = show.Bytes()
	var f struct {
		FormatVersion string `json:"format_version"`
	}
	if err := json.Unmarshal(res.show, &f); err != nil {
		return inputError("terraform show -json: %v", err)
	}
	if !verdict.PlanFormatAllowed(f.FormatVersion) {
		return inputError("plan JSON format_version %q is not supported", f.FormatVersion)
	}
	res.formatVersion = f.FormatVersion
	return nil
}

// openRegular opens path without following a final symlink and refuses
// anything but a regular file.
func openRegular(path string) (*os.File, error) { return tfexec.OpenRegular(path) }

// capped is a buffer that fails a write past limit, so a child cannot
// grow ctfkit's memory without bound. The buffer is a named field: an
// embedded bytes.Buffer would promote ReadFrom, which io.Copy prefers over
// Write, and bypass the cap.
type capped struct {
	limit int
	buf   bytes.Buffer
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.limit {
		return 0, errors.New("terraform output too large")
	}
	return c.buf.Write(p)
}

func (c *capped) Bytes() []byte { return c.buf.Bytes() }
