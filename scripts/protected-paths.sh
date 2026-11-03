#!/usr/bin/env bash
# Decide whether a pull request touches a protected path (ported from the terraform-provider-aws protected-paths gate).
#
# Usage:
#   scripts/protected-paths.sh [--rules FILE] [--patch-dir DIR] < changed-paths
#   scripts/protected-paths.sh --compare OWNER/REPO BASE_SHA HEAD_SHA
#   scripts/protected-paths.sh --self-test
#
# --compare: classify the files changed from the merge base of BASE_SHA to
#   HEAD_SHA, from the GitHub compare API (needs gh and GH_TOKEN). Pinned to
#   HEAD_SHA, so the result is for that commit even if the PR head moves; no PR
#   code is fetched, only the changed file list and go.mod/go.sum patches.
# stdin: changed paths, one per line (renames: old and new path).
# --patch-dir: holds <path>.patch for each changed go.mod / go.sum, at the root
#   or in a nested module (tools/x/go.mod.patch). A missing patch
#   file means the patch is unknown and counts as protected.
# Prints each protected hit. Exit 0 = clean, 1 = protected, 2 = error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OWNER='@antonbabenko'
# Crypto modules: a go.mod / go.sum line adding, removing or bumping one is protected.
# Covers every golang.org/x/crypto, filippo.io, sigstore, secure-systems-lab and
# theupdateframework module, and any module whose path contains "crypto" (any case).
CRYPTO_RE='[Cc][Rr][Yy][Pp][Tt][Oo]|filippo\.io/|github\.com/sigstore/|github\.com/cloudflare/circl|github\.com/theupdateframework/|github\.com/secure-systems-lab/|minisign'
# go.mod lines (changed or context) that change module resolution or the toolchain,
# and changed lines with a quote or backslash: a quoted module path can spell
# "crypto" with escapes that CRYPTO_RE cannot see.
GOMOD_RE='^[-+].*["\\]|=>|^.[[:space:]]*(replace|exclude|retract|toolchain|godebug|tool)([[:space:](]|$)|^@@.*@@[[:space:]]*(replace|exclude|retract|godebug|tool)([[:space:](]|$)|^[-+][[:space:]]*(go|module)[[:space:]]'

die() { echo "protected-paths: $*" >&2; exit 2; }

# matches <regex> <file>: grep -Eq, but a grep error (exit 2) aborts instead of
# reading as "no match", so a broken check never fails open.
matches() {
  local rc=0
  grep -Eq "$1" "$2" || rc=$?
  [[ $rc -le 1 ]] || die "grep failed ($rc) on $2"
  return "$rc"
}

check() {
  local rules="$ROOT/.github/protected-paths" pdir=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --rules) rules=$2; shift 2 ;;
      --patch-dir) pdir=$2; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -r $rules ]] || die "cannot read $rules"

  local -a pats=()
  local line pat owner extra
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || $line == \#* ]] && continue
    [[ $line =~ ^/[A-Za-z0-9._/-]+\ @[A-Za-z0-9-]+$ ]] || die "invalid protected-paths rule: $line"
    read -r pat owner extra <<<"$line"
    [[ $owner == "$OWNER" && -z ${extra:-} ]] || die "unexpected owner: $line"
    pat=${pat#/}
    pats+=("${pat%/}")
  done <"$rules"
  [[ ${#pats[@]} -gt 0 ]] || die "no rules in $rules"

  # A rule covers the path itself (file, symlink or submodule) and everything
  # below it. Compare case-insensitively: macOS checkouts fold case, so
  # INTERNAL/Hook/x.go lands in internal/hook there.
  shopt -s nocasematch
  local path hit=0 f
  while IFS= read -r path || [[ -n $path ]]; do
    [[ -z $path ]] && continue
    path=${path#/}
    for pat in "${pats[@]}"; do
      if [[ $path == "$pat" || $path == "$pat"/* ]]; then
        echo "$path"; hit=1; break
      fi
    done
    case $path in
      go.mod | go.sum | */go.mod | */go.sum)
        f="${pdir:-/nonexistent}/$path.patch"
        if [[ ! -r $f ]]; then
          echo "$path (patch unavailable)"; hit=1
        elif matches "^[-+].*($CRYPTO_RE)" "$f"; then
          echo "$path (crypto dependency)"; hit=1
        elif [[ $path == go.mod || $path == */go.mod ]] && matches "$GOMOD_RE" "$f"; then
          echo "$path (replace/exclude/retract/toolchain directive or quoted path)"; hit=1
        fi
        ;;
    esac
  done
  return $hit
}

# --- self-test --------------------------------------------------------------

st_fail=0
expect() { # expect <want-exit> <name> <paths> [patch-dir]
  local want=$1 name=$2 paths=$3 pdir=${4:-} got=0
  local args=(--rules "$ROOT/.github/protected-paths")
  [[ -n $pdir ]] && args+=(--patch-dir "$pdir")
  printf '%s\n' "$paths" | "$0" "${args[@]}" >/dev/null 2>&1 || got=$?
  if [[ $got != "$want" ]]; then
    echo "FAIL $name: exit $got, want $want"
    st_fail=1
  else
    echo "ok   $name"
  fi
}

self_test() {
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/crypto" "$tmp/replace" "$tmp/block" "$tmp/plain" "$tmp/sum" "$tmp/big" "$tmp/none" \
    "$tmp/filippo" "$tmp/sigstore" "$tmp/sslab" "$tmp/tuf" "$tmp/xcryptosub" "$tmp/anycrypto" "$tmp/anycrypto-sum" "$tmp/upper" "$tmp/quoted"
  printf '%s\n' '@@ -5,3 +5,3 @@ require (' '-	golang.org/x/crypto v0.30.0' '+	golang.org/x/crypto v0.31.0' >"$tmp/crypto/go.mod.patch"
  printf '%s\n' '@@ -20,0 +21,1 @@' '+replace github.com/bobthecorp/x => ../x' >"$tmp/replace/go.mod.patch"
  printf '%s\n' '@@ -20,3 +20,3 @@ exclude (' ' 	github.com/bobthecorp/a v1.0.0' '-	github.com/bobthecorp/b v1.0.0' '+	github.com/bobthecorp/b v1.1.0' >"$tmp/block/go.mod.patch"
  printf '%s\n' '@@ -5,3 +5,3 @@ require (' '-	github.com/bobthecorp/lib v1.0.0' '+	github.com/bobthecorp/lib v1.1.0' >"$tmp/plain/go.mod.patch"
  printf '%s\n' '@@ -1,2 +1,2 @@' '-github.com/bobthecorp/lib v1.0.0 h1:aaa=' '+github.com/bobthecorp/lib v1.1.0 h1:bbb=' >"$tmp/plain/go.sum.patch"
  printf '%s\n' '@@ -1,2 +1,2 @@' '-golang.org/x/crypto v0.30.0 h1:aaa=' '+golang.org/x/crypto v0.31.0 h1:bbb=' >"$tmp/sum/go.sum.patch"
  # Every module family named in the crypto rule, plus any path containing "crypto".
  printf '%s\n' '@@ -5,2 +5,3 @@ require (' '+	filippo.io/edwards25519 v1.1.0' >"$tmp/filippo/go.mod.patch"
  printf '%s\n' '@@ -5,2 +5,3 @@ require (' '+	github.com/sigstore/sigstore-go v1.0.0' >"$tmp/sigstore/go.mod.patch"
  printf '%s\n' '@@ -5,2 +5,3 @@ require (' '-	github.com/secure-systems-lab/go-securesystemslib v0.8.0' '+	github.com/secure-systems-lab/go-securesystemslib v0.9.0' >"$tmp/sslab/go.mod.patch"
  printf '%s\n' '@@ -5,2 +5,3 @@ require (' '+	github.com/theupdateframework/go-tuf/v2 v2.0.0' >"$tmp/tuf/go.mod.patch"
  printf '%s\n' '@@ -1,1 +1,1 @@' '+golang.org/x/crypto/x509roots/fallback v0.0.1 h1:ccc=' >"$tmp/xcryptosub/go.sum.patch"
  printf '%s\n' '@@ -5,2 +5,3 @@ require (' '+	github.com/bobthecorp/cryptolib v1.0.0 // indirect' >"$tmp/anycrypto/go.mod.patch"
  printf '%s\n' '@@ -1,1 +1,1 @@' '-github.com/bobthecorp/hashcrypto v1.0.0/go.mod h1:aaa=' >"$tmp/anycrypto-sum/go.sum.patch"
  printf '%s\n' '@@ -5,2 +5,3 @@ require (' '+	github.com/bobthecorp/GoCrypto v1.0.0' >"$tmp/upper/go.mod.patch"
  # go.mod accepts quoted module paths with escapes, which hide the word crypto.
  printf '%s\n' '@@ -5,2 +5,3 @@ require (' '+	"golang.org/x/cr\x79pto" v0.31.0' >"$tmp/quoted/go.mod.patch"
  # Nested modules get the same go.mod / go.sum checks as the root module.
  mkdir -p "$tmp/nested/tools/x" "$tmp/nestedcrypto/tools/x"
  cp "$tmp/plain/go.mod.patch" "$tmp/nested/tools/x/go.mod.patch"
  cp "$tmp/crypto/go.mod.patch" "$tmp/nestedcrypto/tools/x/go.mod.patch"
  # Large patch with the crypto line first: a quiet matcher must not fail open.
  { printf '%s\n' '@@ -1,5000 +1,5000 @@' '+golang.org/x/crypto v0.31.0 h1:bbb='
    for i in $(seq 1 5000); do echo "+github.com/bobthecorp/m$i v1.0.0 h1:x="; done; } >"$tmp/big/go.sum.patch"

  echo "protected (exit 1):"
  expect 1 verdict 'pkg/verdict/resolve/resolve.go'
  expect 1 verdict-jcs 'pkg/verdict/jcs/jcs.go'
  expect 1 verdict-instancekey-golden 'pkg/verdict/testdata/instancekey/FORMAT.md'
  expect 1 release-please-config 'release-please-config.json'
  expect 1 release-please-manifest '.release-please-manifest.json'
  expect 1 pre-commit-config '.pre-commit-config.yaml'
  expect 1 graph 'internal/graph/companion.go'
  expect 1 sign 'internal/sign/awskms.go'
  expect 1 evidence 'internal/evidence/chain.go'
  expect 1 sink 'internal/sink/s3.go'
  expect 1 breakglass 'internal/breakglass/consume.go'
  expect 1 receipt 'internal/render/receipt/canonical.go'
  expect 1 migrate-wal 'internal/migrate/wal.go'
  expect 1 migrate-journal 'internal/migrate/journal.go'
  expect 1 migrate-rebind 'internal/migrate/rebind.go'
  expect 1 migrate-provenance 'internal/migrate/provenance.go'
  expect 1 schema-receipt 'schema/receipt-1.schema.json'
  expect 1 schema-verdict 'schema/verdict-1.schema.json'
  expect 1 golden-provider-evidence 'schema/testdata/provider-evidence/run.jsonl'
  expect 1 golden-evidence 'testdata/fixtures/evidence/enforced/receipt.json'
  expect 1 golden-graph 'testdata/fixtures/graph/same-plan-create/plan.json'
  expect 1 workflow '.github/workflows/test.yml'
  expect 1 rules '.github/protected-paths'
  expect 1 codeowners '.github/CODEOWNERS'
  expect 1 codeowners-root 'CODEOWNERS'
  expect 1 self 'scripts/protected-paths.sh'
  expect 1 pins-test 'workflow_pins_test.go'
  expect 1 makefile 'Makefile'
  expect 1 goreleaser '.goreleaser.yml'
  expect 1 dockerfile 'Dockerfile'
  expect 1 mise 'mise.toml'
  expect 1 golangci '.golangci.yml'
  expect 1 golangci-alt-name '.golangci.yaml'
  expect 1 rename-out-of-protected $'pkg/verdict/digest.go\ndocs/digest.go'
  expect 1 mixed $'README.md\ninternal/sign/keys.go'
  expect 1 gomod-crypto 'go.mod' "$tmp/crypto"
  expect 1 gomod-replace 'go.mod' "$tmp/replace"
  expect 1 gomod-exclude-block 'go.mod' "$tmp/block"
  expect 1 gomod-no-patch 'go.mod' "$tmp/none"
  expect 1 gosum-crypto 'go.sum' "$tmp/sum"
  expect 1 gosum-crypto-large 'go.sum' "$tmp/big"
  expect 1 gomod-filippo 'go.mod' "$tmp/filippo"
  expect 1 gomod-sigstore 'go.mod' "$tmp/sigstore"
  expect 1 gomod-secure-systems-lab 'go.mod' "$tmp/sslab"
  expect 1 gomod-tuf 'go.mod' "$tmp/tuf"
  expect 1 gosum-x-crypto-submodule 'go.sum' "$tmp/xcryptosub"
  expect 1 gomod-any-crypto 'go.mod' "$tmp/anycrypto"
  expect 1 gosum-any-crypto 'go.sum' "$tmp/anycrypto-sum"
  expect 1 gomod-crypto-uppercase 'go.mod' "$tmp/upper"
  expect 1 gomod-quoted-escape 'go.mod' "$tmp/quoted"
  expect 1 nested-gomod-crypto 'tools/x/go.mod' "$tmp/nestedcrypto"
  expect 1 nested-gosum-no-patch 'tools/x/go.sum' "$tmp/nested"
  # A symlink or submodule at the directory path itself (before the package exists).
  expect 1 dir-node 'pkg/verdict'
  expect 1 dir-node-github '.github'
  # Case variants fold onto the protected package on macOS checkouts.
  expect 1 case-variant 'PKG/Verdict/x.go'
  echo "clean (exit 0):"
  expect 0 near-miss-dir 'pkg/verdictx/a.go'
  expect 0 near-miss-prefix 'internal/signer/x.go'
  expect 0 near-miss-receipt 'internal/render/receipts/a.go'
  expect 0 near-miss-golangci '.golangci.yml.bak'
  expect 0 migrate-other 'internal/migrate/rewrite.go'
  expect 0 schema-other 'schema/catalog-1.schema.json'
  expect 0 fixtures-other 'testdata/fixtures/report/missing-manifest/expected.sarif'
  expect 0 pkg-ctfkit 'pkg/ctfkit/finding.go'
  expect 0 docs 'docs/stages.md'
  expect 0 readme 'README.md'
  expect 0 gomod-plain-bump $'go.mod\ngo.sum' "$tmp/plain"
  expect 0 nested-gomod-plain-bump 'tools/x/go.mod' "$tmp/nested"
  expect 0 empty ''
  echo "invalid rules file (exit 2):"
  local got=0
  printf '/internal/*.go @antonbabenko\n' >"$tmp/rules"
  echo README.md | "$0" --rules "$tmp/rules" >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL wildcard-rejected: exit $got, want 2"; st_fail=1; else echo "ok   wildcard-rejected"; fi
  got=0
  "$0" --compare 'bad repo' 1 2 >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL pr-bad-args: exit $got, want 2"; st_fail=1; else echo "ok   pr-bad-args"; fi

  aba_race
  if [[ $st_fail != 0 ]]; then echo "self-test FAILED"; return 1; fi
  echo "self-test passed"
}

# A->B->A force-push: the run for protected head A starts, the PR's live head
# is B (README only), then A again. A fake gh serves B's files for the live PR
# and A's files only for a compare pinned to A; the gate must classify A.
aba_race() {
  local base=1111111111111111111111111111111111111111 a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa got=0
  local c=cccccccccccccccccccccccccccccccccccccccc e=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  local z=0000000000000000000000000000000000000000
  mkdir -p "$tmp/bin" "$tmp/gh"
  echo '[{"filename":"README.md","status":"modified","additions":1,"deletions":0}]' >"$tmp/gh/live-files.json"
  echo '{"total_commits":1,"commits":[],"files":[{"filename":"internal/sign/awskms.go","status":"modified","additions":1,"deletions":0}]}' >"$tmp/gh/compare-a.json"
  # Fake gh: answers only the two calls above, by URL; anything else fails.
  cat >"$tmp/bin/gh" <<STUB
#!/usr/bin/env bash
url="" jqx=""
while [[ \$# -gt 0 ]]; do
  case \$1 in
    --jq) jqx=\$2; shift 2 ;;
    repos/*) url=\$1; shift ;;
    *) shift ;;
  esac
done
case \$url in
  "repos/octo/repo/pulls/7/files?per_page=100") f=$tmp/gh/live-files.json ;;
  "repos/octo/repo/compare/$base...$a") f=$tmp/gh/compare-a.json ;;
  "repos/octo/repo/compare/$base...$c") f=$tmp/gh/compare-cap.json ;;
  "repos/octo/repo/compare/$base...$e") f=$tmp/gh/compare-nofiles.json ;;
  "repos/octo/repo/compare/$base...$z") f=$tmp/gh/compare-empty.json ;;
  *) echo "fake gh: unexpected \$url" >&2; exit 1 ;;
esac
if [[ -n \$jqx ]]; then jq -c "\$jqx" "\$f"; else cat "\$f"; fi
STUB
  chmod +x "$tmp/bin/gh"
  # 300 clean files: the compare API may have cut the list, so protected.
  jq -nc '{total_commits: 1, commits: [], files: [range(300) | {filename: "docs/f\(.).md", additions: 1, deletions: 0}]}' >"$tmp/gh/compare-cap.json"
  echo '{"total_commits":1,"commits":[]}' >"$tmp/gh/compare-nofiles.json"
  echo '{"total_commits":1,"commits":[],"files":[]}' >"$tmp/gh/compare-empty.json"
  PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$a" >/dev/null 2>&1 || got=$?
  if [[ $got != 1 ]]; then echo "FAIL aba-race: exit $got, want 1"; st_fail=1; else echo "ok   aba-race"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$c" >/dev/null 2>&1 || got=$?
  if [[ $got != 1 ]]; then echo "FAIL compare-cap: exit $got, want 1"; st_fail=1; else echo "ok   compare-cap"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$e" >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL compare-no-files: exit $got, want 2"; st_fail=1; else echo "ok   compare-no-files"; fi
  got=0; PATH="$tmp/bin:$PATH" "$0" --compare octo/repo "$base" "$z" >/dev/null 2>&1 || got=$?
  if [[ $got != 1 ]]; then echo "FAIL compare-empty-files: exit $got, want 1"; st_fail=1; else echo "ok   compare-empty-files"; fi
}

# compare_check <owner/repo> <base-sha> <head-sha>: run check on the compare
# API file list of base...head.
compare_check() {
  local repo=$1 base=$2 head=$3 rc=0 count f
  [[ $repo =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ && $base =~ ^[0-9a-f]{40}$ && $head =~ ^[0-9a-f]{40}$ ]] \
    || die "bad --compare arguments"
  work=$(mktemp -d) # global: the EXIT trap reads it after return
  trap 'rm -rf "$work"' EXIT
  mkdir -p "$work/patches"
  gh api "repos/$repo/compare/$base...$head" >"$work/compare.json" || die "cannot compare $base...$head in $repo"
  jq -e '.files | type == "array"' "$work/compare.json" >/dev/null || die "compare response has no file list"
  jq -c '.files[]' "$work/compare.json" >"$work/files.jsonl" || die "jq failed"
  jq -r '.filename, (.previous_filename // empty)' "$work/files.jsonl" >"$work/paths.txt" || die "jq failed"
  # Keep a go.mod/go.sum patch only when it is complete: its +/- line count
  # must equal the API's additions + deletions. Otherwise the patch counts as
  # unavailable, which check treats as protected.
  while IFS= read -r f; do
    [[ $f != *..* ]] || die "unexpected path: $f"
    mkdir -p "$work/patches/$(dirname "$f")"
    jq -r --arg f "$f" 'select(.filename == $f and .patch != null)
      | select(([.patch | split("\n")[] | select(test("^[-+]"))] | length) == (.additions + .deletions))
      | .patch' "$work/files.jsonl" >"$work/patches/$f.patch" || die "jq failed"
    [[ -s $work/patches/$f.patch ]] || rm -f "$work/patches/$f.patch"
  done < <(jq -r 'select(.filename | test("(^|/)go\\.(mod|sum)$"; "i")) | .filename' "$work/files.jsonl")
  "$0" --patch-dir "$work/patches" <"$work/paths.txt" || rc=$?
  [[ $rc -le 1 ]] || die "check failed ($rc)"
  # The compare API returns at most 300 files and does not page them.
  count=$(wc -l <"$work/files.jsonl")
  if [[ $count -ge 300 ]]; then
    echo "changed-file list hit the compare API cap ($count files)"; rc=1
  fi
  # Commits but no files: either they cancel out or the API dropped the list.
  if [[ $count -eq 0 ]] && ! jq -e '.total_commits == 0' "$work/compare.json" >/dev/null; then
    echo "compare lists commits but no changed files"; rc=1
  fi
  return "$rc"
}

if [[ ${1:-} == --compare ]]; then
  [[ $# -eq 4 ]] || die "usage: --compare OWNER/REPO BASE_SHA HEAD_SHA"
  rc=0; compare_check "$2" "$3" "$4" || rc=$?
  exit "$rc"
fi
if [[ ${1:-} == --self-test ]]; then
  self_test
  exit $?
fi
check "$@"
