package sink

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// fakeS3 is an in-process path-style S3 endpoint: object lock configuration, conditional
// PutObject with version ids, and GetObject with retention headers.
type fakeS3 struct {
	mu       sync.Mutex
	lockXML  string // GetObjectLockConfiguration body; "" means 404
	failPuts int    // next n PutObject calls answer 500
	objects  map[string]fakeObj
	puts     []http.Header
	nextVer  int
}

type fakeObj struct {
	body    []byte
	version string
	mode    string
	until   string
}

const lockEnabled = `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`

func newFakeS3(t *testing.T) (*fakeS3, *s3.Client) {
	t.Helper()
	f := &fakeS3{lockXML: lockEnabled, objects: map[string]fakeObj{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := s3.New(s3.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		UsePathStyle:     true,
		RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "test"}, nil
		}),
	})
	return f, c
}

func s3Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/")
	if _, ok := r.URL.Query()["object-lock"]; ok {
		if f.lockXML == "" {
			s3Error(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError")
			return
		}
		fmt.Fprint(w, f.lockXML)
		return
	}
	switch r.Method {
	case http.MethodPut:
		f.puts = append(f.puts, r.Header.Clone())
		if f.failPuts > 0 {
			f.failPuts--
			s3Error(w, http.StatusInternalServerError, "InternalError")
			return
		}
		if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
			s3Error(w, http.StatusNotImplemented, "NotImplemented")
			return
		}
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		if got := r.Header.Get("X-Amz-Checksum-Sha256"); got != base64.StdEncoding.EncodeToString(sum[:]) {
			s3Error(w, http.StatusBadRequest, "BadDigest")
			return
		}
		if _, ok := f.objects[path]; ok && r.Header.Get("If-None-Match") == "*" {
			s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		f.nextVer++
		o := fakeObj{body: body, version: fmt.Sprintf("v%03d", f.nextVer),
			mode: r.Header.Get("X-Amz-Object-Lock-Mode"), until: r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")}
		f.objects[path] = o
		w.Header().Set("X-Amz-Version-Id", o.version)
	case http.MethodGet:
		o, ok := f.objects[path]
		if !ok {
			s3Error(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("X-Amz-Version-Id", o.version)
		w.Header().Set("X-Amz-Object-Lock-Mode", o.mode)
		w.Header().Set("X-Amz-Object-Lock-Retain-Until-Date", o.until)
		_, _ = w.Write(o.body)
	default:
		s3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

var fixedNow = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func newTestS3(t *testing.T, api S3API) *S3 {
	t.Helper()
	s, err := NewS3(api, S3Config{Bucket: "bobthecorp-evidence", MinRetentionDays: 400, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestS3PutSetsRetentionAndReturnsVersion(t *testing.T) {
	f, c := newFakeS3(t)
	s := newTestS3(t, c)
	r, err := s.Put(context.Background(), Object{Key: "bobthecorp/prod/run-1/manifest.json", Body: []byte(`{"a":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	h := f.puts[0]
	wantUntil := fixedNow.Add(400 * 24 * time.Hour)
	for name, want := range map[string]string{
		"X-Amz-Object-Lock-Mode": "COMPLIANCE",
		"If-None-Match":          "*",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	got, err := time.Parse(time.RFC3339, h.Get("X-Amz-Object-Lock-Retain-Until-Date"))
	if err != nil || !got.Equal(wantUntil) {
		t.Errorf("retain-until header %q (%v), want %s", h.Get("X-Amz-Object-Lock-Retain-Until-Date"), err, wantUntil)
	}
	if r.VersionID != "v001" || r.Key != "compliancetf/bobthecorp/prod/run-1/manifest.json" ||
		!r.RetainUntil.Equal(wantUntil) || r.SHA256 != digest([]byte(`{"a":1}`)) || r.Sink != "s3://bobthecorp-evidence/compliancetf/" {
		t.Errorf("receipt %+v", r)
	}
}

func TestS3PutIsWriteOnce(t *testing.T) {
	_, c := newFakeS3(t)
	s := newTestS3(t, c)
	ctx := context.Background()
	obj := Object{Key: "k.jsonl", Body: []byte("secret-record-value")}
	first, err := s.Put(ctx, obj)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Put(ctx, obj)
	if err != nil {
		t.Fatalf("same digest after 412: %v", err)
	}
	if again.VersionID != first.VersionID || !again.RetainUntil.Equal(first.RetainUntil) {
		t.Errorf("retry receipt %+v, want %+v", again, first)
	}
	_, err = s.Put(ctx, Object{Key: "k.jsonl", Body: []byte("other-record-value")})
	if err == nil || !strings.Contains(err.Error(), "different digest") {
		t.Fatalf("different digest: %v", err)
	}
	if strings.Contains(err.Error(), "record-value") {
		t.Errorf("error leaks the body: %v", err)
	}
}

func TestS3PutRefusesExistingWithoutCompliance(t *testing.T) {
	f, c := newFakeS3(t)
	s := newTestS3(t, c)
	f.objects["bobthecorp-evidence/compliancetf/k"] = fakeObj{body: []byte("x"), version: "v9", mode: "GOVERNANCE", until: "2027-01-01T00:00:00Z"}
	if _, err := s.Put(context.Background(), Object{Key: "k", Body: []byte("x")}); err == nil || !strings.Contains(err.Error(), "COMPLIANCE") {
		t.Fatalf("got %v", err)
	}
}

func TestS3PutRefusesExistingWithExpiredRetention(t *testing.T) {
	f, c := newFakeS3(t)
	s := newTestS3(t, c)
	f.objects["bobthecorp-evidence/compliancetf/k"] = fakeObj{body: []byte("x"), version: "v9", mode: "COMPLIANCE", until: "2026-01-01T00:00:00Z"}
	if _, err := s.Put(context.Background(), Object{Key: "k", Body: []byte("x")}); err == nil || !strings.Contains(err.Error(), "COMPLIANCE") {
		t.Fatalf("expired retention accepted: %v", err)
	}
}

func TestS3Preflight(t *testing.T) {
	for _, tc := range []struct {
		name, xml, wantErr string
	}{
		{"enabled", lockEnabled, ""},
		{"compliance default", `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`, ""},
		{"governance default", `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`, "GOVERNANCE"},
		{"not configured", "", "read object lock configuration"},
		{"disabled", `<ObjectLockConfiguration></ObjectLockConfiguration>`, "not retention-locked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, c := newFakeS3(t)
			f.lockXML = tc.xml
			err := newTestS3(t, c).Preflight(context.Background())
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestShipSpoolsThenDrains(t *testing.T) {
	f, c := newFakeS3(t)
	s := newTestS3(t, c)
	sp := newTestSpool(t)
	ctx := context.Background()
	obj := Object{Key: "bobthecorp/prod/run-2/chain-1-5.jsonl", Body: []byte("secret-record-value\n")}

	f.failPuts = 1
	_, err := Ship(ctx, s, sp, obj)
	if !errors.Is(err, ErrSpooled) {
		t.Fatalf("Ship: %v, want ErrSpooled", err)
	}
	if strings.Contains(err.Error(), "secret-record-value") {
		t.Errorf("error leaks the body: %v", err)
	}
	if n, _ := sp.Pending(); n != 1 {
		t.Fatalf("pending %d, want 1", n)
	}

	got, err := sp.Drain(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].VersionID != "v001" || got[0].Key != "compliancetf/"+obj.Key {
		t.Fatalf("drain receipts %+v", got)
	}
	if n, _ := sp.Pending(); n != 0 {
		t.Fatalf("pending %d after drain, want 0", n)
	}
	if o := f.objects["bobthecorp-evidence/compliancetf/"+obj.Key]; string(o.body) != string(obj.Body) || o.mode != "COMPLIANCE" {
		t.Fatalf("stored %+v", o)
	}
}

func TestNewS3AndParseURI(t *testing.T) {
	b, p, err := ParseS3URI("s3://bobthecorp-evidence/ev/")
	if err != nil || b != "bobthecorp-evidence" || p != "ev/" {
		t.Fatalf("ParseS3URI = %q %q %v", b, p, err)
	}
	if _, dp, derr := ParseS3URI("s3://bobthecorp-evidence"); derr != nil || dp != "compliancetf/" {
		t.Fatalf("ParseS3URI default prefix = %q %v", dp, derr)
	}
	for _, bad := range []string{"gs://b/p", "s3:///p", "s3://"} {
		if _, _, perr := ParseS3URI(bad); perr == nil {
			t.Errorf("ParseS3URI(%q) accepted", bad)
		}
	}
	for _, cfg := range []S3Config{
		{Bucket: "", MinRetentionDays: 1},
		{Bucket: "b", MinRetentionDays: 0},
		{Bucket: "b", MinRetentionDays: 36501},
		{Bucket: "b", MinRetentionDays: 1, Prefix: "../x/"},
		{Bucket: "b", MinRetentionDays: 1, Prefix: "/x/"},
	} {
		if _, nerr := NewS3(nil, cfg); nerr == nil {
			t.Errorf("NewS3(%+v) accepted", cfg)
		}
	}
	s, err := NewS3(nil, S3Config{Bucket: "b", MinRetentionDays: 1, Prefix: "ev"})
	if err != nil || s.Name() != "s3://b/ev/" {
		t.Fatalf("NewS3 prefix: %v %v", s, err)
	}
}
