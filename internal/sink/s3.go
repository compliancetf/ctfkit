package sink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	defaultPrefix = "compliancetf/"
	// maxRetentionDays bounds min_retention_days so days*24h cannot overflow time.Duration.
	maxRetentionDays = 36500
)

// S3API is the subset of *s3.Client the sink calls.
type S3API interface {
	GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3Config is one org profile evidence.sinks[] entry of type s3_object_lock.
type S3Config struct {
	Bucket           string
	Prefix           string // default "compliancetf/"; always ends in "/"
	MinRetentionDays int    // required, > 0
	Now              func() time.Time
}

// S3 writes objects once with COMPLIANCE mode Object Lock retention. GOVERNANCE mode is
// never used: it can be bypassed, so it is not immutable evidence.
type S3 struct {
	api S3API
	cfg S3Config
}

// ParseS3URI splits s3://bucket/prefix into bucket and prefix. An empty prefix becomes
// the default "compliancetf/".
func ParseS3URI(uri string) (bucket, prefix string, err error) {
	rest, ok := strings.CutPrefix(uri, "s3://")
	if !ok {
		return "", "", fmt.Errorf("evidence sink %q: want s3://bucket/prefix", uri)
	}
	bucket, prefix, _ = strings.Cut(rest, "/")
	if bucket == "" {
		return "", "", fmt.Errorf("evidence sink %q: empty bucket", uri)
	}
	if prefix == "" {
		prefix = defaultPrefix
	}
	return bucket, prefix, nil
}

// NewS3 returns an Object Lock sink over api.
func NewS3(api S3API, cfg S3Config) (*S3, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3 evidence sink: empty bucket")
	}
	if cfg.MinRetentionDays <= 0 || cfg.MinRetentionDays > maxRetentionDays {
		return nil, fmt.Errorf("s3 evidence sink %s: min_retention_days must be 1..%d", cfg.Bucket, maxRetentionDays)
	}
	if cfg.Prefix == "" {
		cfg.Prefix = defaultPrefix
	}
	if !strings.HasSuffix(cfg.Prefix, "/") {
		cfg.Prefix += "/"
	}
	if strings.HasPrefix(cfg.Prefix, "/") || validKey(strings.TrimSuffix(cfg.Prefix, "/")) != nil {
		return nil, fmt.Errorf("s3 evidence sink %s: invalid prefix %q", cfg.Bucket, cfg.Prefix)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &S3{api: api, cfg: cfg}, nil
}

// Name implements Sink.
func (s *S3) Name() string { return "s3://" + s.cfg.Bucket + "/" + s.cfg.Prefix }

// Preflight implements Sink: Object Lock must be enabled on the bucket. Retention is set
// per object, so a bucket default rule is not required; when one exists it must not be
// GOVERNANCE.
func (s *S3) Preflight(ctx context.Context) error {
	out, err := s.api.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: &s.cfg.Bucket})
	if err != nil {
		return fmt.Errorf("evidence sink s3_object_lock:%s: read object lock configuration: %w", s.cfg.Bucket, err)
	}
	c := out.ObjectLockConfiguration
	if c == nil || c.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		return fmt.Errorf("evidence sink s3_object_lock:%s is not retention-locked (object lock disabled)", s.cfg.Bucket)
	}
	if c.Rule != nil && c.Rule.DefaultRetention != nil && c.Rule.DefaultRetention.Mode == types.ObjectLockRetentionModeGovernance {
		return fmt.Errorf("evidence sink s3_object_lock:%s is not retention-locked (default retention mode GOVERNANCE)", s.cfg.Bucket)
	}
	return nil
}

// Put implements Sink. If-None-Match: * makes the write once; a 412 is success only when
// the stored object has the same SHA-256 and is under unexpired COMPLIANCE retention.
func (s *S3) Put(ctx context.Context, obj Object) (Receipt, error) {
	if err := validKey(obj.Key); err != nil {
		return Receipt{}, err
	}
	key := s.cfg.Prefix + obj.Key
	sum := sha256.Sum256(obj.Body)
	until := s.cfg.Now().UTC().Add(time.Duration(s.cfg.MinRetentionDays) * 24 * time.Hour).Truncate(time.Second)
	out, err := s.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    &s.cfg.Bucket,
		Key:                       &key,
		Body:                      bytes.NewReader(obj.Body),
		ContentLength:             aws.Int64(int64(len(obj.Body))),
		IfNoneMatch:               aws.String("*"),
		ChecksumAlgorithm:         types.ChecksumAlgorithmSha256,
		ChecksumSHA256:            aws.String(base64.StdEncoding.EncodeToString(sum[:])),
		ObjectLockMode:            types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: &until,
	})
	if isPreconditionFailed(err) {
		return s.existing(ctx, key, digest(obj.Body))
	}
	if err != nil {
		return Receipt{}, fmt.Errorf("put evidence object %s: %w", key, err)
	}
	if aws.ToString(out.VersionId) == "" {
		return Receipt{}, fmt.Errorf("put evidence object %s: no version id (bucket not versioned)", key)
	}
	return Receipt{Sink: s.Name(), Key: key, VersionID: *out.VersionId, SHA256: digest(obj.Body), RetainUntil: until}, nil
}

func (s *S3) existing(ctx context.Context, key, want string) (Receipt, error) {
	out, err := s.api.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.cfg.Bucket, Key: &key})
	if err != nil {
		return Receipt{}, fmt.Errorf("read existing evidence object %s: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, out.Body); err != nil {
		return Receipt{}, fmt.Errorf("read existing evidence object %s: %w", key, err)
	}
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		return Receipt{}, fmt.Errorf("evidence object %s exists with a different digest", key)
	}
	// S3 keeps the lock headers after retention ends, so an expired date is not a lock.
	if out.ObjectLockMode != types.ObjectLockModeCompliance || out.ObjectLockRetainUntilDate == nil ||
		!out.ObjectLockRetainUntilDate.After(s.cfg.Now()) || aws.ToString(out.VersionId) == "" {
		return Receipt{}, fmt.Errorf("evidence object %s exists without COMPLIANCE retention", key)
	}
	return Receipt{Sink: s.Name(), Key: key, VersionID: *out.VersionId, SHA256: want, RetainUntil: out.ObjectLockRetainUntilDate.UTC()}, nil
}

func isPreconditionFailed(err error) bool {
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusPreconditionFailed
}
