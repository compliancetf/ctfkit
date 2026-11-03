package evidence

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// breakLines are the lines of chain-break.jsonl: chain_start, eval, then the
// chain_break that chain-segment.jsonl opens with, eval, chain_end.
func breakLines(t *testing.T) [][]byte {
	t.Helper()
	b := readFile(t, filepath.Join(goldens, "chain-break.jsonl"))
	return bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
}

func readers(bs ...[]byte) []io.Reader {
	rs := make([]io.Reader, len(bs))
	for i, b := range bs {
		rs[i] = bytes.NewReader(b)
	}
	return rs
}

// The writer's segment case: the first two lines of chain-break.jsonl are the
// abandoned file, chain-segment.jsonl the next one.
func TestVerifySegments(t *testing.T) {
	bl := breakLines(t)
	base := join(bl[:2])
	seg := readFile(t, filepath.Join(goldens, "chain-segment.jsonl"))
	cut := []byte(`{"chain":"c_1791201600000_0101`)
	whole, err := Verify(bytes.NewReader(join(bl)))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		segs [][]byte
		want error
	}{
		{"stitched", [][]byte{base, seg}, nil},
		{"abandoned file ends in a cut line", [][]byte{append(append([]byte{}, base...), cut...), seg}, nil},
		{"segment of only a cut line is skipped", [][]byte{base, cut, seg}, nil},
		{"single file", [][]byte{join(bl)}, nil},
		{"no segments", nil, ErrEmpty},
		{"only cut lines", [][]byte{cut, cut}, ErrTruncated},
		{"last segment cut", [][]byte{base, append(append([]byte{}, seg...), cut...)}, ErrTruncated},
		{"first segment missing", [][]byte{seg}, ErrTampered},
		{"segment without chain_break", [][]byte{base, base}, ErrTampered},
		{"segment after chain_end", [][]byte{join(bl), seg}, ErrTampered},
		{"gap between segments", [][]byte{join(bl[:1]), seg}, ErrTampered},
		{"tampered segment", [][]byte{base, readFile(t, filepath.Join(goldens, "chain-edited.jsonl"))}, ErrTampered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum, err := VerifySegments(readers(tc.segs...)...)
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifySegments = %v, want %v", err, tc.want)
			}
			if err != nil {
				return
			}
			if sum.Records != whole.Records || sum.Breaks != whole.Breaks || sum.Evals != whole.Evals ||
				sum.LastSeq != whole.LastSeq || sum.LastHash != whole.LastHash || !sum.Terminated || sum.Segment ||
				sum.Chain != whole.Chain || sum.RunID != "bobthecorp-run-1" {
				t.Errorf("summary = %+v, want the single-file %+v", sum, whole)
			}
		})
	}
}

// A one-line segment (its chain_break alone) passes Verify, so only the stitch
// checks can refuse a changed run or chain id; the message pins which one.
func TestVerifySegmentsIdentity(t *testing.T) {
	bl := breakLines(t)
	brk := append(append([]byte{}, bl[2]...), '\n')
	for _, tc := range []struct{ name, old, new, why string }{
		{"other run", "bobthecorp-run-1", "bobthecorp-run-2", "run changed"},
		{"other chain", "c_1791201600000_0101010101010101", "c_1791201600000_0202020202020202", "chain id changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edited := bytes.ReplaceAll(brk, []byte(tc.old), []byte(tc.new))
			if bytes.Equal(edited, brk) {
				t.Fatal("the edit changed nothing, so the case asserts nothing")
			}
			if _, err := Verify(bytes.NewReader(edited)); err != nil {
				t.Fatalf("the edited segment must pass Verify alone: %v", err)
			}
			if _, err := VerifySegments(readers(join(bl[:2]), brk)...); err != nil {
				t.Fatalf("the unedited segment must stitch: %v", err)
			}
			_, err := VerifySegments(readers(join(bl[:2]), edited)...)
			if !errors.Is(err, ErrTampered) || !strings.Contains(err.Error(), tc.why) {
				t.Fatalf("VerifySegments = %v, want %v: %s", err, ErrTampered, tc.why)
			}
		})
	}
}
