package sink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newTestSpool(t *testing.T) *Spool {
	t.Helper()
	sp, err := OpenSpool(filepath.Join(t.TempDir(), ".ctfkit", "spool"))
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// memSink is a Sink whose puts fail while failing is true.
type memSink struct {
	name    string
	failing bool
	got     map[string][]byte
}

func (m *memSink) Name() string                    { return m.name }
func (m *memSink) Preflight(context.Context) error { return nil }
func (m *memSink) Put(_ context.Context, o Object) (Receipt, error) {
	if m.failing {
		return Receipt{}, errors.New("unavailable")
	}
	if m.got == nil {
		m.got = map[string][]byte{}
	}
	m.got[o.Key] = o.Body
	return Receipt{Sink: m.name, Key: o.Key, VersionID: "v", SHA256: digest(o.Body), RetainUntil: time.Unix(0, 0)}, nil
}

func TestSpoolAddIdempotentAndConflict(t *testing.T) {
	sp := newTestSpool(t)
	obj := Object{Key: "a/b.jsonl", Body: []byte("x")}
	for range 2 {
		if err := sp.Add("s3://b/p/", obj); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := sp.Pending(); n != 1 {
		t.Fatalf("pending %d, want 1", n)
	}
	err := sp.Add("s3://b/p/", Object{Key: "a/b.jsonl", Body: []byte("y")})
	if err == nil || !strings.Contains(err.Error(), "different digest") {
		t.Fatalf("conflict: %v", err)
	}
	// Same key for another sink is a separate entry.
	if err := sp.Add("s3://other/p/", obj); err != nil {
		t.Fatal(err)
	}
	if n, _ := sp.Pending(); n != 2 {
		t.Fatalf("pending %d, want 2", n)
	}
	if runtime.GOOS != "windows" {
		names, _ := sp.entries()
		fi, _ := os.Lstat(filepath.Join(sp.dir, names[0]))
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("entry mode %04o, want 0600", fi.Mode().Perm())
		}
	}
}

func TestSpoolDrainKeepsFailuresAndOtherSinks(t *testing.T) {
	sp := newTestSpool(t)
	ok := &memSink{name: "s3://ok/p/"}
	down := &memSink{name: "s3://down/p/", failing: true}
	for _, a := range []struct {
		sink string
		key  string
	}{{ok.name, "k1"}, {ok.name, "k2"}, {down.name, "k3"}, {"s3://absent/p/", "k4"}} {
		if err := sp.Add(a.sink, Object{Key: a.key, Body: []byte(a.key)}); err != nil {
			t.Fatal(err)
		}
	}
	// A temp file left by a crashed Add is cleaned and never shipped.
	stale := filepath.Join(sp.dir, spoolTmpPrefix+"123")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := sp.Drain(context.Background(), ok, down)
	if len(got) != 2 || len(ok.got) != 2 {
		t.Fatalf("shipped %d receipts, sink got %d, want 2", len(got), len(ok.got))
	}
	if err == nil || !strings.Contains(err.Error(), "drain k3") {
		t.Fatalf("drain error %v, want k3 failure", err)
	}
	if n, _ := sp.Pending(); n != 2 {
		t.Fatalf("pending %d, want 2 (k3, k4)", n)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("temp file not cleaned: %v", err)
	}
	down.failing = false
	if got, err := sp.Drain(context.Background(), ok, down); err != nil || len(got) != 1 {
		t.Fatalf("second drain %d %v", len(got), err)
	}
	if n, _ := sp.Pending(); n != 1 {
		t.Fatalf("pending %d, want 1 (k4 for an absent sink)", n)
	}
}

func TestSpoolDrainWaitsForLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the spool lock is unix only")
	}
	// A deep, absent path is created whole.
	sp, err := OpenSpool(filepath.Join(t.TempDir(), "a", "b", "c", "spool"))
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDir(sp.dir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, derr := sp.Drain(context.Background()); done <- derr }()
	select {
	case <-done:
		t.Fatal("Drain ran while another holder had the spool lock")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSpoolCorruptEntryIsKept(t *testing.T) {
	sp := newTestSpool(t)
	s := &memSink{name: "s3://b/p/"}
	if err := sp.Add(s.name, Object{Key: "k", Body: []byte("secret-record-value")}); err != nil {
		t.Fatal(err)
	}
	path := sp.path(s.name, "k")
	b, _ := os.ReadFile(path)
	// Flip the body: base64 of "secret..." starts with "c2Vj".
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), "c2Vj", "c2Vk", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := sp.Drain(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "corrupt") || len(s.got) != 0 {
		t.Fatalf("drain %v, shipped %d", err, len(s.got))
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaks the body: %v", err)
	}
	if n, _ := sp.Pending(); n != 1 {
		t.Fatalf("corrupt entry removed")
	}
}

func TestOpenSpoolRefusesUnsafeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner and mode checks are unix only")
	}
	root := t.TempDir()
	wide := filepath.Join(root, "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSpool(wide); err == nil || !strings.Contains(err.Error(), "wider") {
		t.Errorf("wide dir: %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, link + "/"} {
		if _, err := OpenSpool(p); err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("symlinked dir %q: %v", p, err)
		}
	}
}

func TestShipRefusesBadKey(t *testing.T) {
	sp := newTestSpool(t)
	s := &memSink{name: "s3://b/p/"}
	for _, k := range []string{"", "/abs", "a/../b", "a//b", "dir/", `a\b`, "."} {
		if _, err := Ship(context.Background(), s, sp, Object{Key: k}); err == nil || errors.Is(err, ErrSpooled) {
			t.Errorf("key %q: %v", k, err)
		}
	}
	if n, _ := sp.Pending(); n != 0 {
		t.Errorf("bad keys were spooled")
	}
}
