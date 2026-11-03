//go:build !ctftest

package instancekey

// allowTestSecret: a release build refuses the public test secret (FORMAT.md
// Test secret).
const allowTestSecret = false
