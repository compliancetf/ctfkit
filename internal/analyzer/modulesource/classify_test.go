package modulesource_test

import (
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/modulesource"
)

// EndpointAllowed admits a local path and a served registry address and
// nothing else, under the suffix fallback and under an explicit allowlist
// alike.
func TestEndpointAllowed(t *testing.T) {
	allowlist := []string{"https://bobthecorp.compliance.tf/"}
	tests := []struct {
		name      string
		source    string
		endpoints []string
		want      bool
	}{
		{name: "local child", source: "./modules/x", want: true},
		{name: "local parent", source: "../shared", want: true},
		{name: "served, suffix fallback", source: "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws", want: true},
		{name: "served with a disable query", source: "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable=x", want: true},
		{name: "served submodule", source: "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws//modules/notification", want: true},
		{name: "served, on the allowlist", source: "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws", endpoints: allowlist, want: true},
		{name: "compliance.tf host off the allowlist", source: "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws", endpoints: allowlist},
		{name: "public registry upstream", source: "terraform-aws-modules/vpc/aws"},
		{name: "public registry with host", source: "registry.terraform.io/bobthecorp/app/aws"},
		{name: "unknown registry host", source: "registry.bobthecorp.example/net/vpc/aws"},
		{name: "git getter", source: "git::https://example.com/bobthecorp/app.git?ref=v1"},
		{name: "github shorthand", source: "github.com/bobthecorp/app"},
		{name: "archive url", source: "https://example.com/app.zip"},
		{name: "fragment carrying a served suffix", source: "https://evil.example#.compliance.tf/terraform-aws-modules/s3-bucket/aws"},
		{name: "fragment carrying a served suffix, no scheme", source: "evil.example#.compliance.tf/terraform-aws-modules/s3-bucket/aws"},
		{name: "fragment after a query", source: "https://evil.example?x=1#.compliance.tf/terraform-aws-modules/s3-bucket/aws"},
		{name: "escaped fragment in the host", source: "https://evil.example%23.compliance.tf/terraform-aws-modules/s3-bucket/aws"},
		{name: "escaped slash in the host", source: "evil.example%2F.compliance.tf/terraform-aws-modules/s3-bucket/aws"},
		{name: "backslash in the host", source: `https://evil.example\.compliance.tf/terraform-aws-modules/s3-bucket/aws`},
		{name: "s3 getter", source: "s3::https://s3.amazonaws.com/bobthecorp/app.zip"},
		{name: "absolute path", source: "/opt/modules/app"},
		{name: "empty", source: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := modulesource.EndpointAllowed(tt.source, tt.endpoints); got != tt.want {
				t.Errorf("EndpointAllowed(%q, %q) = %v, want %v", tt.source, tt.endpoints, got, tt.want)
			}
		})
	}
}
