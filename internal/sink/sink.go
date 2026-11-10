// Package sink writes evidence objects to write-once customer evidence sinks (phase 3
// "Evidence shipping and receipt"). A put that fails is spooled in the directory the caller names and
// retried by the next Drain. Errors never carry object bodies.
package sink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Object is one evidence object. Key is relative to the sink prefix.
type Object struct {
	Key  string
	Body []byte
}

// Receipt records where an object landed.
type Receipt struct {
	Sink        string    // Sink.Name()
	Key         string    // full object key, prefix included
	VersionID   string    // version the store assigned
	SHA256      string    // hex digest of the body
	RetainUntil time.Time // write-once retention end
}

// Sink is a write-once evidence store. Implementations: s3_object_lock (phase 3);
// azure_immutable_blob and gcs_retention_lock plug in here (phase 4).
type Sink interface {
	// Name is the stable sink identity, for example s3://bucket/prefix/. Spool entries
	// are matched to sinks by it.
	Name() string
	// Preflight checks once per run that the store is retention-locked. A failure makes
	// the run evidence-degraded.
	Preflight(ctx context.Context) error
	// Put writes obj once. Writing an object that already exists with the same digest
	// returns its receipt; a different digest is an error.
	Put(ctx context.Context, obj Object) (Receipt, error)
}

// ErrSpooled marks a put that failed and was spooled for a later Drain.
var ErrSpooled = errors.New("evidence object spooled for retry")

// Ship puts obj to s. On a put failure it spools obj and returns an error that wraps
// ErrSpooled and the put error; the caller marks the run evidence-degraded.
func Ship(ctx context.Context, s Sink, sp *Spool, obj Object) (Receipt, error) {
	if err := validKey(obj.Key); err != nil {
		return Receipt{}, err
	}
	r, err := s.Put(ctx, obj)
	if err == nil {
		return r, nil
	}
	if serr := sp.Add(s.Name(), obj); serr != nil {
		return Receipt{}, errors.Join(err, serr)
	}
	return Receipt{}, fmt.Errorf("%w: %s: %w", ErrSpooled, obj.Key, err)
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// validKey refuses keys that could escape the prefix or alias another object.
func validKey(k string) error {
	if k == "" || strings.HasPrefix(k, "/") || strings.HasSuffix(k, "/") || strings.Contains(k, "\\") {
		return fmt.Errorf("invalid evidence object key %q", k)
	}
	for _, seg := range strings.Split(k, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("invalid evidence object key %q", k)
		}
	}
	return nil
}
