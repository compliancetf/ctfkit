package migrate

import (
	"reflect"
	"strings"
	"testing"
)

// TestResolveWrapperParity: W == U, and the constraints for entries without
// one follow from U.
func TestResolveWrapperParity(t *testing.T) {
	got, blocked, err := ResolveWrapper("live/prod", "aws", "6.68.2", []string{"6.67.0", "6.68.2", "6.68.2-beta.1", "6.69.0-compliancetf.1"})
	if err != nil || blocked != nil {
		t.Fatalf("blocked = %+v, err = %v", blocked, err)
	}
	want := Provider{
		Type: "aws", From: "registry.terraform.io/hashicorp/aws", To: "registry.compliance.tf/compliancetf/aws",
		UpstreamVersion: "6.68.2", WrapperVersion: "6.68.2", RootConstraint: "~> 6.68", ModuleConstraint: ">= 6.0.0",
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestResolveWrapperBlocked(t *testing.T) {
	releases := []string{"6.67.0", "6.67.0-compliancetf.1", "6.68.0", "6.70.0", "6.71.0-beta.1", "v6.66.0", "6.66.0+x", "https://user:secret@example.com"}
	cases := []struct {
		name, u  string
		releases []string
		want     string
	}{
		{
			name: "older than the first release", u: "6.12.0", releases: releases,
			want: "no compliancetf/aws release runs hashicorp/aws 6.12.0 (nearest: 6.67.0, the first release); upgrade hashicorp/aws to >= 6.67.0",
		},
		{
			name: "newer than the latest release", u: "6.71.0", releases: releases,
			want: "no compliancetf/aws release runs hashicorp/aws 6.71.0 (nearest: 6.70.0, the latest release); wait for the release of 6.71.0",
		},
		{
			name: "between two releases", u: "6.69.1", releases: releases,
			want: "no compliancetf/aws release runs hashicorp/aws 6.69.1 (nearest: 6.68.0, 6.70.0); upgrade hashicorp/aws to 6.70.0 or wait for the release of 6.69.1",
		},
		{
			name: "only a prerelease of U", u: "6.71.0", releases: []string{"6.71.0-beta.1", "6.71.0-compliancetf.1"},
			want: "no compliancetf/aws release runs hashicorp/aws 6.71.0 (none published); wait for the release of 6.71.0",
		},
		{
			name: "nothing published", u: "6.67.0", releases: nil,
			want: "no compliancetf/aws release runs hashicorp/aws 6.67.0 (none published); wait for the release of 6.67.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, blocked, err := ResolveWrapper("live/prod", "aws", tc.u, tc.releases)
			if err != nil {
				t.Fatal(err)
			}
			want := &Blocked{Kind: BlockedNoWrapperRelease, Dir: "live/prod", Detail: tc.want}
			if !reflect.DeepEqual(blocked, want) || got != (Provider{}) {
				t.Errorf("got %+v, %+v\nwant %+v", got, blocked, want)
			}
			if strings.Contains(blocked.Detail, "secret") {
				t.Errorf("detail carries registry text: %s", blocked.Detail)
			}
		})
	}
}

// TestResolveWrapperRefusesBadUpstream: U comes from a lockfile and reaches
// blocked[]; anything but X.Y.Z is an error, not a detail.
func TestResolveWrapperRefusesBadUpstream(t *testing.T) {
	for _, u := range []string{"", "6.67", "v6.67.0", "6.67.0-beta.1", "06.67.0", "6.67.0 secret"} {
		if _, b, err := ResolveWrapper(".", "aws", u, []string{u}); err == nil || b != nil {
			t.Errorf("ResolveWrapper(%q): blocked = %+v, err = %v; want an error", u, b, err)
		}
	}
}
