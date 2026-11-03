//go:build !ctftest

package sign

import "testing"

// TestOpenRelease: a release build opens no test: signer, and awskms: wants
// a KMS key ARN before it reaches AWS.
func TestOpenRelease(t *testing.T) {
	for _, uri := range []string{"", "test:bobthecorp", "awskms:k", "awskms:arn:aws:s3:::bucket", "awskms:arn:aws:kms:eu-west-1:111111111111:alias/x", "awskms:arn:aws:kms::111111111111:key/x", "awskms:arn:aws:kms:eu-west-1::key/x", "file:/tmp/k"} {
		if _, err := Open(uri); err == nil {
			t.Errorf("Open(%q) opened a signer in a release build", uri)
		}
	}
}
