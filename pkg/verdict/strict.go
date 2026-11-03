package verdict

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// maxDepth bounds nesting so a deep document cannot exhaust the stack.
const maxDepth = 10000

var errNotStrict = errors.New("verdict: not a strict JSON object of strings, arrays and objects")

// canonical returns the JCS bytes of raw when raw is one I-JSON value
// (jcs.TransformIJSON: valid UTF-8, paired surrogate escapes, no
// noncharacter, no duplicate member name at any depth) that is an object at
// the top and holds no number, bool or null.
func canonical(raw []byte) ([]byte, error) { return checkedJCS(raw, false) }

// checkedJCS is canonical; with scalars any I-JSON value passes, numbers,
// bools and null included, as the provider's bundle.DigestJSON accepts.
func checkedJCS(raw []byte, scalars bool) ([]byte, error) {
	canon, err := jcs.TransformIJSON(raw)
	if err != nil || !scalars && !stringsOnly(canon) {
		return nil, errNotStrict
	}
	return canon, nil
}

// stringsOnly reports whether canon, one JSON value, is an object that holds
// only strings, arrays and objects.
func stringsOnly(canon []byte) bool {
	if !bytes.HasPrefix(canon, []byte("{")) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(canon))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return true
		}
		switch tok.(type) {
		case json.Delim, string:
		default:
			return false // a number, bool, null or a decode error
		}
	}
}
