package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

// ManifestFormat is the run manifest format ctfkit evidence ship signs.
const ManifestFormat = "compliancetf.run-manifest/v1"

// maxSegment bounds one chain segment file ReadChains reads.
const maxSegment = 1 << 30

// reSegment is a chain segment file name: <chain>.jsonl, <chain>.<n>.jsonl.
var reSegment = regexp.MustCompile(`^(c_[0-9]{13}_[0-9a-f]{16})(?:\.([1-9][0-9]{0,5}))?\.jsonl$`)

// Range is a span of seqs a chain is missing; To nil is open-ended.
type Range struct {
	From int64  `json:"from,string"`
	To   *int64 `json:"to,string,omitempty"`
}

// Segment is one chain file as read: its name and bytes.
type Segment struct {
	Name string
	Body []byte
}

// Chain is one process chain of a run: the summary of the segments that
// stitch from its first segment, what is missing after them, whether any
// committed record carries a break_glass_id, the verdict digests its records
// name (digests.verdict: sha256 over JCS of the verdict the apply was gated
// by), and every segment file read.
type Chain struct {
	Summary
	Missing        []Range
	BreakGlass     bool
	VerdictDigests []string
	Unbound        int // records that must name the verdict and do not (scan)
	Segments       []Segment
}

// ReadChains reads every chain segment file in dir (the provider's
// <evidence_dir>/<run_id>/), one Chain per chain id, sorted by id. Files not
// named *.jsonl are ignored; a *.jsonl that is not a segment name, a chain
// without its first segment, a chain that does not verify and chains of more
// than one run are errors. Only the segments contiguous from the first one
// are stitched (VerifySegments); a final line cut by a crash in the last of
// them is left out of the verified range. A chain that does not end in
// chain_end is missing everything after its last committed seq; segments
// after a hole in the numbering are verified on their own and add nothing to
// the range. Every error but an I/O error wraps a Verify error kind
// (VerifyFailed).
func ReadChains(dir string) ([]Chain, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	segs := map[string]map[int][]byte{}
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".jsonl" {
			continue
		}
		m := reSegment.FindStringSubmatch(name)
		if m == nil || !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s: %w: not a chain segment file", name, ErrMalformed)
		}
		n := 0
		if m[2] != "" {
			n, _ = strconv.Atoi(m[2]) // the pattern bounds it
		}
		body, err := readSegment(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if segs[m[1]] == nil {
			segs[m[1]] = map[int][]byte{}
		}
		segs[m[1]][n] = body
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("%w: no chain segment files", ErrEmpty)
	}
	ids := make([]string, 0, len(segs))
	for id := range segs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Chain, 0, len(ids))
	for _, id := range ids {
		c, err := readChain(id, segs[id])
		if err != nil {
			return nil, fmt.Errorf("chain %s: %w", id, err)
		}
		if len(out) > 0 && !bytes.Equal(c.Run, out[0].Run) {
			return nil, fmt.Errorf("chain %s: %w: another run than chain %s", id, ErrTampered, out[0].Chain)
		}
		out = append(out, c)
	}
	return out, nil
}

// VerifyFailed reports whether err is a chain verification failure, one of
// the Verify error kinds, rather than an I/O error.
func VerifyFailed(err error) bool {
	for _, kind := range []error{ErrEmpty, ErrTruncated, ErrTooLong, ErrMalformed, ErrUnsupported, ErrTampered} {
		if errors.Is(err, kind) {
			return true
		}
	}
	return false
}

func readSegment(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a segment file in the chains dir the caller named
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxSegment+1))
	if err == nil && len(b) > maxSegment {
		err = fmt.Errorf("%s: %w: larger than %d bytes", filepath.Base(path), ErrTooLong, maxSegment)
	}
	return b, err
}

func segmentName(id string, n int) string {
	if n == 0 {
		return id + ".jsonl"
	}
	return id + "." + strconv.Itoa(n) + ".jsonl"
}

func readChain(id string, segs map[int][]byte) (Chain, error) {
	var c Chain
	if _, ok := segs[0]; !ok {
		return c, fmt.Errorf("%w: no first segment %s", ErrEmpty, segmentName(id, 0))
	}
	nums := make([]int, 0, len(segs))
	for n := range segs {
		nums = append(nums, n)
	}
	slices.Sort(nums)
	prefix := 0
	for prefix < len(nums) && nums[prefix] == prefix {
		prefix++
	}
	readers := make([]io.Reader, 0, prefix)
	for i := range prefix {
		b := segs[i]
		if i == prefix-1 {
			b = b[:bytes.LastIndexByte(b, '\n')+1] // a line cut by a crash is not committed
			if len(b) == 0 && i > 0 {
				break
			}
		}
		readers = append(readers, bytes.NewReader(b))
	}
	sum, err := VerifySegments(readers...)
	if err != nil {
		return c, err
	}
	if sum.Chain != id {
		return c, fmt.Errorf("%w: file name names chain %s, its records chain %s", ErrTampered, id, sum.Chain)
	}
	c.Summary = sum
	if !sum.Terminated {
		c.Missing = []Range{{From: sum.LastSeq + 1}}
	}
	for _, n := range nums[prefix:] {
		if sum.Terminated {
			return c, fmt.Errorf("%w: segment %s after chain_end", ErrTampered, segmentName(id, n))
		}
		s, err := Verify(bytes.NewReader(segs[n]))
		if err != nil && !errors.Is(err, ErrTruncated) {
			return c, fmt.Errorf("%s: %w", segmentName(id, n), err)
		}
		if s.Chain != id || !bytes.Equal(s.Run, sum.Run) {
			return c, fmt.Errorf("%w: segment %s names another chain or run", ErrTampered, segmentName(id, n))
		}
	}
	for _, n := range nums {
		c.Segments = append(c.Segments, Segment{Name: segmentName(id, n), Body: segs[n]})
		c.scan(segs[n])
	}
	return c, nil
}

// scan notes, over every complete line of b, a result with a break_glass_id
// and each distinct non-null digests.verdict. The lines are verified
// already; one that does not decode carries neither, and counts as Unbound.
//
// It also counts the records that must name the verdict and do not
// (Unbound): every eval record at stage apply_pre without a digests.verdict,
// and every line that does not decode. The provider sets digests.verdict on
// exactly those records while a verdict is loaded (terraform-provider-aws
// internal/lifecycle/evidence.go recordMatched: only for StageApplyPre with
// a loaded verdict; apply.go and verdict.go write every apply_pre eval
// through it). It writes every other record without one, so those keep null:
// chain_start, configure, chain_break and chain_end, and eval records at
// stage plan, apply_post, refresh, import, ephemeral_open, data_source and
// rpc (record, verdict.go rpcGate).
func (c *Chain) scan(b []byte) {
	for line := range bytes.Lines(b) {
		if !bytes.HasSuffix(line, []byte("\n")) {
			continue // a line cut by a crash is not committed
		}
		var rec struct {
			Kind    Kind   `json:"kind"`
			Stage   string `json:"stage"`
			Digests *struct {
				Verdict *string `json:"verdict"`
			} `json:"digests"`
			Results []struct {
				BreakGlassID string `json:"break_glass_id"`
			} `json:"results"`
		}
		if json.Unmarshal(line, &rec) != nil {
			c.Unbound++
			continue
		}
		var v *string
		if rec.Digests != nil {
			v = rec.Digests.Verdict
		}
		if v == nil && rec.Kind == KindEval && rec.Stage == "apply_pre" {
			c.Unbound++
		}
		if v != nil && !slices.Contains(c.VerdictDigests, *v) {
			c.VerdictDigests = append(c.VerdictDigests, *v)
		}
		for _, r := range rec.Results {
			c.BreakGlass = c.BreakGlass || r.BreakGlassID != ""
		}
	}
}

// Manifest is the run manifest: what the run's chains are, by sequence range
// and final hash, and where each segment was shipped, signed with the
// verdict signer (signature over verdict.SignedBytes, ES256). Like a verdict
// it holds strings, arrays and objects only: numbers and booleans are encoded
// as strings, which SignedBytes requires.
type Manifest struct {
	Format      string            `json:"format"`
	OrgID       string            `json:"org_id"`
	Workspace   string            `json:"workspace"`
	RunID       string            `json:"run_id"`
	RunnerClass string            `json:"runner_class"`
	CreatedAt   string            `json:"created_at"`
	Chains      []ManifestChain   `json:"chains"`
	Signature   verdict.Signature `json:"signature"`
}

// ManifestChain is one chain of the manifest.
type ManifestChain struct {
	Chain      string       `json:"chain"`
	FirstSeq   int64        `json:"first_seq,string"`
	LastSeq    int64        `json:"last_seq,string"`
	FinalHash  string       `json:"final_hash"`
	Records    int          `json:"records,string"`
	Breaks     int          `json:"breaks,string"`
	Terminated bool         `json:"terminated,string"`
	Missing    []Range      `json:"missing"`
	Segments   []SegmentRef `json:"segments"`
}

// SegmentRef names a shipped segment by its object key (relative to the
// sink prefix) and the hex sha256 of its bytes.
type SegmentRef struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

// NewManifest is the unsigned manifest of chains; keyPrefix is the object
// key prefix of the run (org/workspace/run_id/).
func NewManifest(orgID, workspace, runnerClass, createdAt, keyPrefix string, chains []Chain) *Manifest {
	m := &Manifest{Format: ManifestFormat, OrgID: orgID, Workspace: workspace, RunnerClass: runnerClass,
		CreatedAt: createdAt, Chains: []ManifestChain{}}
	for _, c := range chains {
		m.RunID = c.RunID
		mc := ManifestChain{Chain: c.Chain, FirstSeq: c.FirstSeq, LastSeq: c.LastSeq, FinalHash: c.LastHash,
			Records: c.Records, Breaks: c.Breaks, Terminated: c.Terminated, Missing: c.Missing}
		if mc.Missing == nil {
			mc.Missing = []Range{}
		}
		for _, s := range c.Segments {
			h := sha256.Sum256(s.Body)
			mc.Segments = append(mc.Segments, SegmentRef{Key: keyPrefix + s.Name, SHA256: hex.EncodeToString(h[:])})
		}
		m.Chains = append(m.Chains, mc)
	}
	return m
}
