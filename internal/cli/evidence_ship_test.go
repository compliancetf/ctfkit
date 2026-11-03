package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/compliancetf/ctfkit/internal/sign"
	"github.com/compliancetf/ctfkit/internal/sink"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

var updateEvidence = flag.Bool("update-evidence", false, "rewrite testdata/fixtures/evidence/*/expected")

const evidenceCases = "../../testdata/fixtures/evidence"

// detSigner signs deterministically (RFC 6979), so a run over a fixture
// writes the same manifest, and the same receipt, every time.
type detSigner struct{ key *ecdsa.PrivateKey }

func (d detSigner) Public() *ecdsa.PublicKey { return &d.key.PublicKey }

func (d detSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	return d.key.Sign(nil, digest, crypto.SHA256)
}

// fakeS3 is an Object Lock bucket; failPut makes every put fail.
type fakeS3 struct {
	failPut bool
	puts    []string
	// lockErr and putErr, when set, are what the preflight and every put
	// return.
	lockErr, putErr error
}

func (f *fakeS3) GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	if f.lockErr != nil {
		return nil, f.lockErr
	}
	return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: &types.ObjectLockConfiguration{ObjectLockEnabled: types.ObjectLockEnabledEnabled}}, nil
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.failPut {
		return nil, errors.New("service unavailable")
	}
	if f.putErr != nil {
		return nil, f.putErr
	}
	if in.ObjectLockMode != types.ObjectLockModeCompliance || in.ObjectLockRetainUntilDate == nil {
		return nil, errors.New("put without COMPLIANCE retention")
	}
	f.puts = append(f.puts, aws.ToString(in.Key))
	return &s3.PutObjectOutput{VersionId: aws.String("v1")}, nil
}

func (f *fakeS3) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, errors.New("not stored")
}

// fakeAPI acknowledges every manifest it is given.
type fakeAPI struct {
	got         [][]byte
	nonceReused bool
}

func (f *fakeAPI) IngestRun(_ context.Context, manifest []byte) (ingestAck, error) {
	f.got = append(f.got, manifest)
	return ingestAck{ManifestDigest: rawDigest(manifest), NonceReused: f.nonceReused}, nil
}

type shipCase struct {
	inputs       string // pkg/verdict/testdata/inputs case
	artifacts    bool   // the run went through ctfkit apply (runner class ci)
	artifactsDir string // an --artifacts set other than the case's own
	chainsDir    string // a --chains dir other than the case's own
	failPut      bool
	api          bool
}

// shipCases are testdata/fixtures/evidence, one per receipt status, plus a
// break-glass run with degraded evidence, which raises the alert, and chains
// that fail verification.
var shipCases = map[string]shipCase{
	"enforced":             {inputs: "evidence", artifacts: true, api: true},
	"evidence-degraded":    {inputs: "evidence", artifacts: true, api: true}, // the chain's last line is cut
	"overridden":           {inputs: "evidence", artifacts: true, api: true},
	"overridden-degraded":  {inputs: "evidence", artifacts: true, failPut: true, api: true},
	"single-resource-only": {inputs: "evidence-advisory"},
	"failed":               {inputs: "evidence", artifacts: true, api: true},
	"tampered":             {inputs: "evidence", artifacts: true, api: true}, // an edited line: nothing ships
}

// verdictTemplate is a valid verdict the fixture verdicts are made from.
const verdictTemplate = "../../pkg/verdict/testdata/sig/valid/verdict.json"

var verdictTemplateAbs = mustAbs(verdictTemplate)

// writeFixtureVerdicts writes input/artifacts/verdict.json of every ci case:
// the template rebound to the fixtures' org, workspace, run and plan, signed
// deterministically with the evidence profile's verdict key.
func writeFixtureVerdicts(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(verdictTemplateAbs)
	if err != nil {
		t.Fatal(err)
	}
	set, err := parseSignSettings(mustVerified(t, filepath.Join(gateInputsAbs, "evidence")).Profile)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range shipCases {
		if !tc.artifacts {
			continue
		}
		doc, err := verdict.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		doc.Workspace, doc.Environment, doc.RunID = "default", "prod", "bobthecorp-run-1"
		doc.PlanDigest = "sha256:" + strings.Repeat("1", 64)
		signed, err := sign.Verdict(context.Background(), detSigner{newLabelSigner(verdictKeyL).key}, doc, set.keys, nil, gateCLI(t, filepath.Join(gateInputsAbs, "evidence")).now())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(evidenceCasesAbs, name, "input", "artifacts", artifactVerdict), signed, 0o644); err != nil { //nolint:gosec // public test data
			t.Fatal(err)
		}
	}
}

// Absolute at package init, before a test changes its working directory.
var evidenceCasesAbs, gateInputsAbs = mustAbs(evidenceCases), mustAbs(gateInputs)

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		panic(err)
	}
	return a
}

// runShip runs evidence ship over a fixture case from a fresh working
// directory (its spool) and returns the exit code, stderr and receipt path.
func runShip(t *testing.T, name string, tc shipCase, s3fake *fakeS3, api evidenceIngest, rcpt string, extra ...string) (int, string, string) {
	t.Helper()
	dir := filepath.Join(evidenceCasesAbs, name, "input")
	inputs := filepath.Join(gateInputsAbs, tc.inputs)
	c := gateCLI(t, inputs)
	c.openSigner = func(string) (sign.Signer, error) { return detSigner{newLabelSigner(verdictKeyL).key}, nil }
	c.openS3 = func(context.Context, string) (sink.S3API, error) { return s3fake, nil }
	c.evidenceAPI = api
	if rcpt == "" {
		rcpt = filepath.Join(t.TempDir(), "receipt.json")
	}
	chains := filepath.Join(dir, "chains")
	if tc.chainsDir != "" {
		chains = tc.chainsDir
	}
	args := []string{"evidence", "ship", "--chains", chains, "--workspace", "default", "--org", "bobthecorp",
		"--profile", filepath.Join(inputs, "profile.dsse.json"), "--floor", filepath.Join(inputs, "floor.dsse.json"),
		"--bundle-dir", filepath.Join(inputs, "bundles"), "--signer", "awskms:fake", "--receipt", rcpt,
		"--sink", "s3://bobthecorp-evidence/compliancetf"}
	switch {
	case tc.artifactsDir != "":
		args = append(args, "--artifacts", tc.artifactsDir)
	case tc.artifacts:
		args = append(args, "--artifacts", filepath.Join(dir, "artifacts"))
	}
	if tc.api {
		args = append(args, "--api")
	}
	var errBuf bytes.Buffer
	c.rootCmd.SetArgs(append(args, extra...))
	c.rootCmd.SetOut(&bytes.Buffer{})
	c.rootCmd.SetErr(&errBuf)
	err := c.Execute()
	if err != nil {
		errBuf.WriteString(err.Error())
	}
	return ExitCode(err), errBuf.String(), rcpt
}

// TestEvidenceShipFixtures runs each testdata/fixtures/evidence case: the
// receipt equals expected/receipt.json byte for byte, the exit code equals
// expected/exit-code (0 only for enforced), and the degraded break-glass run
// raises its alert. Tampered chains ship nothing and record the reason.
func TestEvidenceShipFixtures(t *testing.T) {
	if *updateEvidence {
		writeFixtureVerdicts(t)
	}
	for name, tc := range shipCases {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			s3fake, api := &fakeS3{failPut: tc.failPut}, &fakeAPI{}
			code, stderr, rcpt := runShip(t, name, tc, s3fake, api, "")
			got, err := os.ReadFile(rcpt)
			if err != nil {
				t.Fatalf("no receipt (exit %d): %v\n%s", code, err, stderr)
			}
			exp := filepath.Join(evidenceCasesAbs, name, "expected")
			if *updateEvidence {
				for f, b := range map[string][]byte{"receipt.json": got, "exit-code": []byte(strconv.Itoa(code) + "\n")} {
					if werr := os.WriteFile(filepath.Join(exp, f), b, 0o644); werr != nil { //nolint:gosec // public test data
						t.Fatal(werr)
					}
				}
			}
			want, err := os.ReadFile(filepath.Join(exp, "receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("receipt differs from expected/receipt.json:\n got %s\nwant %s", got, want)
			}
			wantCode, err := os.ReadFile(filepath.Join(exp, "exit-code"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(wantCode)) != strconv.Itoa(code) {
				t.Errorf("exit %d, want %s: %s", code, wantCode, stderr)
			}
			if (code == ExitOK) != (name == "enforced") {
				t.Errorf("exit %d: only enforced exits 0", code)
			}
			if alert := strings.Contains(stderr, "ALERT"); alert != (name == "overridden-degraded" || name == "tampered") {
				t.Errorf("alert raised %t: %s", alert, stderr)
			}
			if name == "tampered" {
				if len(s3fake.puts) != 0 || len(api.got) != 0 || !bytes.Contains(got, []byte(`"reason":"evidence chains failed verification`)) {
					t.Errorf("tampered chains: puts %v, api %d, receipt %s", s3fake.puts, len(api.got), got)
				}
				return
			}
			if !bytes.Contains(got, []byte(`"runnerClass":"`+map[bool]string{true: "ci", false: "local"}[tc.artifacts]+`"`)) {
				t.Errorf("runner class: %s", got)
			}
			if tc.failPut {
				if n, _ := pendingSpool(t); n == 0 {
					t.Error("a failed put left nothing in the spool")
				}
			} else if len(s3fake.puts) == 0 {
				t.Error("nothing was uploaded")
			}
			if tc.api && len(api.got) != 1 {
				t.Errorf("Evidence API got %d manifests, want 1", len(api.got))
			}
		})
	}
}

// TestEvidenceShipForgedArtifacts: an --artifacts set that does not
// authenticate gives runner class local, which fails closed under the
// profile's verdict_required, whatever outcome its result.json claims.
func TestEvidenceShipForgedArtifacts(t *testing.T) {
	src := filepath.Join(evidenceCasesAbs, "enforced", "input", "artifacts")
	for name, forge := range map[string]func(t *testing.T, dir string){
		"no verdict": func(t *testing.T, dir string) { mustRemove(t, filepath.Join(dir, artifactVerdict)) },
		"foreign verdict": func(t *testing.T, dir string) {
			b, err := os.ReadFile(verdictTemplateAbs) // another org key's signature, another run
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(dir, artifactVerdict), b)
		},
		"edited verdict": func(t *testing.T, dir string) {
			b, err := os.ReadFile(filepath.Join(dir, artifactVerdict))
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(dir, artifactVerdict), bytes.Replace(b, []byte(`"environment":"prod"`), []byte(`"environment":"prox"`), 1))
		},
		"another run id": func(t *testing.T, dir string) {
			for _, f := range []string{artifactResult, artifactTombstone} {
				b, err := os.ReadFile(filepath.Join(dir, f))
				if err != nil {
					t.Fatal(err)
				}
				mustWrite(t, filepath.Join(dir, f), bytes.ReplaceAll(b, []byte("bobthecorp-run-1"), []byte("bobthecorp-run-2")))
			}
		},
		"not consumed": func(t *testing.T, dir string) { mustWrite(t, filepath.Join(dir, artifactRunKey), []byte("00")) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			dir := t.TempDir()
			for _, f := range []string{artifactVerdict, artifactResult, artifactTombstone} {
				b, err := os.ReadFile(filepath.Join(src, f))
				if err != nil {
					t.Fatal(err)
				}
				mustWrite(t, filepath.Join(dir, f), b)
			}
			forge(t, dir)
			tc := shipCases["enforced"]
			tc.artifactsDir = dir
			code, stderr, rcpt := runShip(t, "enforced", tc, &fakeS3{}, &fakeAPI{}, "")
			got, err := os.ReadFile(rcpt)
			if err != nil {
				t.Fatal(err)
			}
			if code != ExitFindings || !strings.Contains(stderr, "does not authenticate") ||
				!bytes.Contains(got, []byte(`"runnerClass":"local"`)) || !bytes.Contains(got, []byte(`"status":"failed"`)) {
				t.Errorf("exit %d, receipt %s\n%s", code, got, stderr)
			}
		})
	}
}

// TestEvidenceShipChainsBoundToVerdict: in a consumed ci set, a chain that
// verifies on its own but is not of the authenticated verdict's run, names
// another verdict, or has an apply_pre eval record (which the provider always
// binds while a verdict is loaded) with a null or missing digests.verdict
// counts as tampered: failed, nothing shipped, the stderr ALERT and the
// evidence_tampered alert, exit 1, and the receipt names the verdict's run.
// An apply_pre record naming the verdict passes.
func TestEvidenceShipChainsBoundToVerdict(t *testing.T) {
	good, err := os.ReadFile(filepath.Join(evidenceCasesAbs, "enforced", "input", "chains", "c_1791201600000_0101010101010101.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(evidenceCasesAbs, "enforced", "input", "artifacts", artifactVerdict))
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	applyPre := func(verdictDigest any) func(seq int, m map[string]any) {
		return func(seq int, m map[string]any) {
			if seq != 3 { // the second eval record
				return
			}
			m["stage"] = "apply_pre"
			if verdictDigest == "absent" {
				delete(m, "digests")
				return
			}
			m["digests"].(map[string]any)["verdict"] = verdictDigest
		}
	}
	t.Run("apply_pre bound", func(t *testing.T) {
		t.Chdir(t.TempDir())
		tc := shipCases["enforced"]
		tc.chainsDir = runDir(t, editChain(t, good, applyPre(rawDigest(canon))))
		if code, stderr, _ := runShip(t, "enforced", tc, &fakeS3{}, &fakeAPI{}, ""); code != ExitOK {
			t.Errorf("exit %d, want 0: %s", code, stderr)
		}
	})
	for name, chain := range map[string][]byte{
		"another run":            relink(t, bytes.ReplaceAll(good, []byte("bobthecorp-run-1"), []byte("bobthecorp-run-2"))),
		"another verdict":        relink(t, bytes.Replace(good, []byte(`"verdict":null`), []byte(`"verdict":"sha256:`+strings.Repeat("9", 64)+`"`), 1)),
		"apply_pre null digest":  editChain(t, good, applyPre(nil)),
		"apply_pre no digests":   editChain(t, good, applyPre("absent")),
		"apply_pre other digest": editChain(t, good, applyPre("sha256:"+strings.Repeat("9", 64))),
		"undecodable record":     editChain(t, good, onSeq(3, func(m map[string]any) { m["results"] = "not-a-list" })),
		"non-string digest":      editChain(t, good, onSeq(3, func(m map[string]any) { setVerdict(m, json.Number("5")) })),
		"foreign digest on plan eval": editChain(t, good, onSeq(2, func(m map[string]any) {
			setVerdict(m, "sha256:"+strings.Repeat("9", 64))
		})),
		"foreign digest on configure": editChain(t, good, onSeq(1, func(m map[string]any) {
			setVerdict(m, "sha256:"+strings.Repeat("9", 64))
		})),
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			s3fake, api := &fakeS3{}, &fakeAPI{}
			tc := shipCases["enforced"]
			tc.chainsDir = runDir(t, chain)
			code, stderr, rcpt := runShip(t, "enforced", tc, s3fake, api, "")
			got, err := os.ReadFile(rcpt)
			if err != nil {
				t.Fatalf("no receipt: %v\n%s", err, stderr)
			}
			if !strings.Contains(stderr, "ctfkit: ALERT: the evidence chains of run bobthecorp-run-1 failed verification") {
				t.Errorf("no stderr ALERT: %s", stderr)
			}
			if !bytes.Contains(got, []byte(`"alerts":["evidence_tampered"]`)) {
				t.Errorf("no evidence_tampered alert: %s", got)
			}
			if strings.HasPrefix(name, "undecodable") || strings.HasPrefix(name, "non-string") {
				// the chain itself verifies: the binding is what refuses it
				if !bytes.Contains(got, []byte("that must name the verdict name none")) {
					t.Errorf("not refused by the binding: %s", got)
				}
			}
			if code != ExitFindings || len(s3fake.puts) != 0 || len(api.got) != 0 || !bytes.Contains(got, []byte(`"status":"failed"`)) ||
				!bytes.Contains(got, []byte(`"id":"bobthecorp-run-1"`)) || !bytes.Contains(got, []byte(`"runnerClass":"ci"`)) {
				t.Errorf("exit %d, puts %v, api %d, receipt %s\n%s", code, s3fake.puts, len(api.got), got, stderr)
			}
		})
	}
}

// onSeq is an editChain edit of the record with that seq only.
func onSeq(seq int, edit func(m map[string]any)) func(int, map[string]any) {
	return func(i int, m map[string]any) {
		if i == seq {
			edit(m)
		}
	}
}

// setVerdict sets a record's digests.verdict; the record must have digests.
func setVerdict(m map[string]any, v any) {
	m["digests"].(map[string]any)["verdict"] = v
}

// runDir writes chain into a fresh run directory and returns it.
func runDir(t *testing.T, chain []byte) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bobthecorp-run-1")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "c_1791201600000_0101010101010101.jsonl"), chain)
	return dir
}

// relink recomputes every prev of an edited chain so it verifies again.
func relink(t *testing.T, b []byte) []byte {
	t.Helper()
	return editChain(t, b, nil)
}

// editChain applies edit to every record (by line index, which is its seq in
// a single file), then recomputes every prev so the chain verifies again.
func editChain(t *testing.T, b []byte, edit func(seq int, m map[string]any)) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	for i := range lines {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(lines[i]))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			edit(i, m)
		}
		if i > 0 {
			m["prev"] = rawDigest(lines[i-1])
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(m); err != nil {
			t.Fatal(err)
		}
		lines[i] = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}
	return append(bytes.Join(lines, []byte("\n")), '\n')
}

// TestFallbackRunID: the run id of chains no verdict names is a plain
// directory name, never '.', '/' or a path.
func TestFallbackRunID(t *testing.T) {
	for in, want := range map[string]string{
		"bobthecorp-run-1":               "bobthecorp-run-1",
		".":                              "unknown",
		"/":                              "unknown",
		"..":                             "unknown",
		"evidence/runs/bobthecorp-run-2": "bobthecorp-run-2",
		"evidence/my run":                "unknown",
		strings.Repeat("a", 129):         "unknown",
	} {
		if got := fallbackRunID(in); got != want {
			t.Errorf("fallbackRunID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEvidenceShipTamperRunIDs: without a verdict, tampered chains in a
// directory that is not a plain id get run id unknown.
func TestEvidenceShipTamperRunIDs(t *testing.T) {
	edited, err := os.ReadFile(filepath.Join(evidenceCasesAbs, "tampered", "input", "chains", "c_1791201600000_0101010101010101.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for name, sub := range map[string]string{"spaces": "my run", "plain": "bobthecorp-run-7"} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			chains := filepath.Join(t.TempDir(), sub)
			if err := os.Mkdir(chains, 0o700); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(chains, "c_1791201600000_0101010101010101.jsonl"), edited)
			tc := shipCases["single-resource-only"]
			tc.chainsDir = chains
			code, stderr, rcpt := runShip(t, "single-resource-only", tc, &fakeS3{}, &fakeAPI{}, "")
			got, _ := os.ReadFile(rcpt)
			want := map[string]string{"spaces": "unknown", "plain": "bobthecorp-run-7"}[name]
			if code != ExitFindings || !bytes.Contains(got, []byte(`"id":"`+want+`"`)) {
				t.Errorf("exit %d, receipt %s\n%s", code, got, stderr)
			}
		})
	}
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func pendingSpool(t *testing.T) (int, error) {
	t.Helper()
	sp, err := sink.OpenSpool(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	return sp.Pending()
}

// TestEvidenceShipSpoolRetry: objects a failed run spooled are shipped by the
// next run from the same directory, and the next receipt is enforced.
func TestEvidenceShipSpoolRetry(t *testing.T) {
	t.Chdir(t.TempDir())
	tc := shipCases["enforced"]
	down := &fakeS3{failPut: true}
	if code, stderr, _ := runShip(t, "enforced", tc, down, &fakeAPI{}, ""); code != ExitFindings {
		t.Fatalf("sink down: exit %d, want 1: %s", code, stderr)
	}
	up := &fakeS3{}
	code, stderr, _ := runShip(t, "enforced", tc, up, &fakeAPI{}, "")
	if code != ExitOK {
		t.Fatalf("sink back: exit %d, want 0: %s", code, stderr)
	}
	if n, _ := pendingSpool(t); n != 0 {
		t.Errorf("%d objects still spooled", n)
	}
	// the earlier run's chain and manifest, then this run's (the chain put
	// again is the same object, which a real bucket accepts as existing)
	if len(up.puts) != 4 {
		t.Errorf("puts %v, want 4", up.puts)
	}
}

// TestEvidenceShipRefusals: what exits 2 or is not enforced outside the
// fixture table.
func TestEvidenceShipRefusals(t *testing.T) {
	tc := shipCases["enforced"]
	for name, check := range map[string]struct {
		extra []string
		api   *fakeAPI
		code  int
		want  string
	}{
		"sink not in profile": {extra: []string{"--sink", "s3://other-bucket/x"}, code: ExitEnvironment, want: "not an s3_object_lock sink"},
		"nonce reused":        {api: &fakeAPI{nonceReused: true}, code: ExitFindings, want: "receipt status failed"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			api := check.api
			if api == nil {
				api = &fakeAPI{}
			}
			code, stderr, _ := runShip(t, "enforced", tc, &fakeS3{}, api, "", check.extra...)
			if code != check.code || !strings.Contains(stderr, check.want) {
				t.Errorf("exit %d, want %d with %q: %s", code, check.code, check.want, stderr)
			}
		})
	}
	t.Run("receipt exists", func(t *testing.T) {
		t.Chdir(t.TempDir())
		rcpt := filepath.Join(t.TempDir(), "receipt.json")
		if err := os.WriteFile(rcpt, []byte("earlier"), 0o600); err != nil {
			t.Fatal(err)
		}
		up := &fakeS3{}
		if code, stderr, _ := runShip(t, "enforced", tc, up, &fakeAPI{}, rcpt); code != ExitEnvironment {
			t.Errorf("exit %d, want 2: %s", code, stderr)
		}
		if len(up.puts) != 0 {
			t.Errorf("shipped %v for a run whose receipt cannot be written", up.puts)
		}
		if b, _ := os.ReadFile(rcpt); string(b) != "earlier" {
			t.Error("an existing receipt was overwritten")
		}
	})
	t.Run("no api client", func(t *testing.T) {
		t.Chdir(t.TempDir())
		code, stderr, _ := runShip(t, "enforced", tc, &fakeS3{}, noIngest{}, "")
		if code != ExitFindings || !strings.Contains(stderr, "no Evidence API client") {
			t.Errorf("exit %d, want 1 (evidence-degraded): %s", code, stderr)
		}
		if n, _ := pendingSpool(t); n != 1 {
			t.Errorf("%d spooled, want the manifest", n)
		}
	})
}
