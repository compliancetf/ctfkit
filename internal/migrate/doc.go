// Package migrate will hold ctfkit migrate. Today it holds unit discovery
// (DiscoverUnits: the CLI units and workspaces of a plan file's units[]), the
// config rewrite (Rewrite: the hclwrite edits of a plan file's edits[]), the
// blockers (Blockers and FloorViolations: a plan file's blocked[]), the
// version-parity resolution (ResolveWrapper: a providers[] entry or a
// no_wrapper_release blocked[] entry) and
// the behavior spike, TestBehaviour: the Terraform and OpenTofu behaviors
// B1-B7 the migrate design relies on, recorded as goldens per CLI version
// under testdata/fixtures/migrate.
package migrate
