package evidence

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// VerifySegments verifies the segment files of one chain in writer order
// (<chain>.jsonl, <chain>.1.jsonl, <chain>.2.jsonl, ...) and stitches them.
//
// After a failed write the provider abandons the file and starts the next
// segment with a chain_break whose last_good names the last committed line,
// so every segment but the last may end in a cut line (ErrTruncated), and a
// segment holding only a cut line carries nothing to stitch and is skipped.
// The first segment must start with chain_start, every later one with a
// chain_break that continues the previous committed line (seq, hash), the
// same chain id and the same run, and no segment may follow chain_end.
//
// The result covers the whole chain: Chain, RunID, Run and FirstSeq of the
// first segment, LastSeq, LastHash and Terminated of the last, Records, Evals
// and Breaks summed, Segment false. Errors wrap the Verify error kinds and
// name the 0-based segment index.
func VerifySegments(segs ...io.Reader) (Summary, error) {
	var (
		out  Summary
		prev *Summary
	)
	if len(segs) == 0 {
		return out, fmt.Errorf("evidence: %w: no segments", ErrEmpty)
	}
	for i, r := range segs {
		last := i == len(segs)-1
		sum, err := Verify(r)
		if err != nil {
			if last || !errors.Is(err, ErrTruncated) {
				return out, fmt.Errorf("segment %d: %w", i, err)
			}
			if sum.Records == 0 {
				continue
			}
		}
		fail := func(why string) (Summary, error) {
			return out, fmt.Errorf("segment %d: evidence: %w: %s", i, ErrTampered, why)
		}
		if prev == nil {
			if sum.Segment {
				return fail("first segment does not start with chain_start")
			}
			out = sum
			prev = &out
			continue
		}
		switch {
		case !sum.Segment:
			return fail("segment does not start with chain_break")
		case prev.Terminated:
			return fail("segment after chain_end")
		case sum.Chain != prev.Chain:
			return fail("chain id changed")
		case !bytes.Equal(sum.Run, prev.Run):
			return fail("run changed")
		case sum.FirstSeq != prev.LastSeq+1 || sum.FirstPrev != prev.LastHash:
			return fail("chain_break does not continue the previous segment")
		}
		out.Records += sum.Records
		out.Evals += sum.Evals
		out.Breaks += sum.Breaks
		out.LastSeq, out.LastHash, out.Terminated = sum.LastSeq, sum.LastHash, sum.Terminated
	}
	if prev == nil {
		return out, fmt.Errorf("evidence: %w: no committed line", ErrEmpty)
	}
	return out, nil
}
