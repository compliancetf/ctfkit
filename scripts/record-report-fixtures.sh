#!/usr/bin/env bash
# Re-record the report fixture pack (testdata/fixtures/report) against the
# registry named in its PIN.json, or check whether the served modules drifted
# from it. Maintainer-only: it needs a registry credential, which never goes
# into CI. testdata/fixtures/README.md "Pinning and re-recording" is the manual.
#
#   scripts/record-report-fixtures.sh           re-record, then swap the pack in
#   scripts/record-report-fixtures.sh --check   record into scratch and compare
#
# The token is read from TF_TOKEN_<host> (dots as _, hyphens as __), for
# example TF_TOKEN_bobthecorp_compliance_tf.
#
# Exit codes:
#   0  recorded and swapped in (record mode); no drift (--check)
#   1  drift: the served modules differ from the pinned pack (--check only)
#   2  tooling error, a refused source, a failed check, or a pattern hit
#   3  the token or a signed URL is in the recorded tree: rotate the credential
set -Eeuo pipefail
# Any unexpected failure is a tooling error (2), never a command's own status:
# a stray 1 would read as drift. Only the explicit exits below return 1 or 3.
trap 'exit 2' ERR
umask 077

usage() { echo "usage: $0 [--check]" >&2; exit 2; }
die() { echo "record-report-fixtures: $*" >&2; exit 2; }

mode=record
case "${1:-}" in
  "") ;;
  --check) mode=check ;;
  *) usage ;;
esac
[ $# -le 1 ] || usage

[ -z "${CI:-}" ] || die "refusing to run with CI set: the registry credential never goes into CI"
if [ "$mode" = check ] && [ -n "${CTFKIT_UPDATE_GOLDEN:-}" ]; then
  die "refusing --check with CTFKIT_UPDATE_GOLDEN set: a check never writes a golden file"
fi

repo=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repo"
live=$repo/testdata/fixtures/report
work=$repo/testdata/.report-rerecord   # gitignored; same filesystem as the live pack
backup=$work/backup
[ -f "$live/PIN.json" ] || die "no $live/PIN.json"

# --- tools, resolved to absolute paths before anything runs under env -i ---
go_bin=$(command -v go) || die "go is not on PATH"
gomodcache=$("$go_bin" env GOMODCACHE)
gocache=$("$go_bin" env GOCACHE)
go_path_dir=$(dirname "$go_bin")

tofu_pin=$(sed -n '/^\[tools\."http:tofu"\]/,/^\[/s/^version = "\(.*\)"/\1/p' mise.toml | head -1)
[ -n "$tofu_pin" ] || die "mise.toml pins no tofu version"
tofu_bin=$(mise which tofu 2>/dev/null || command -v tofu || true)
case "$tofu_bin" in
  /*) [ -x "$tofu_bin" ] || die "tofu at $tofu_bin is not executable" ;;
  *) die "tofu $tofu_pin is not installed (mise install)" ;;
esac
tofu_version=$("$tofu_bin" version -json | sed -n 's/.*"terraform_version": *"\([^"]*\)".*/\1/p' | head -1)
[ "$tofu_version" = "$tofu_pin" ] || die "tofu at $tofu_bin is $tofu_version, mise.toml pins $tofu_pin"

# --- scratch: one fixed 0700 parent outside the repository, swept every run ---
scratch=${TMPDIR:-/tmp}
scratch=${scratch%/}/ctfkit-report-rerecord
case "$(cd "$(dirname "$scratch")" && pwd -P)/" in
  "$repo"/*) die "the scratch directory $scratch is inside the repository" ;;
esac
rm -rf "$scratch"
mkdir -m 0700 "$scratch"
mkdir -m 0700 "$scratch/home" "$scratch/tmp" "$scratch/data" "$scratch/cases" "$scratch/bin"

if [ -e "$backup" ]; then
  die "$backup exists from an interrupted swap; see testdata/fixtures/README.md \"Recovery\""
fi
rm -rf "$work/fresh"

swapped=0
cleanup() {
  if [ ! -e "$live" ] && [ -e "$backup" ]; then
    mv "$backup" "$live" && echo "record-report-fixtures: restored the live pack from $backup" >&2
  fi
  if [ "$swapped" = 1 ]; then
    rm -rf "$backup"
  fi
  rm -rf "$scratch" "$work/fresh"
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 2' INT TERM HUP

run_go() {
  env -i PATH="$go_path_dir:/usr/bin:/bin" HOME="$scratch/home" TMPDIR="$scratch/tmp" \
    GOMODCACHE="$gomodcache" GOCACHE="$gocache" GOPROXY=off GOFLAGS='-mod=readonly -buildvcs=false' \
    GOTOOLCHAIN=local GOENV=off LC_ALL=C.UTF-8 "$@"
}

run_go "$go_bin" build -o "$scratch/bin/fixturepin" ./cmd/fixturepin || die "building cmd/fixturepin failed"
fp=$scratch/bin/fixturepin

host=$("$fp" host "$live/PIN.json") || die "PIN.json names no usable registry_host"

# --- the credential: read before env -i, written only into a 0600 CLI config ---
token_var=TF_TOKEN_$(printf '%s' "$host" | sed -e 's/-/__/g' -e 's/\./_/g')
token=${!token_var:-}
[ -n "$token" ] || die "set $token_var to a registry token for $host"
case "$token" in
  *[!A-Za-z0-9._~+/=-]*) die "$token_var holds characters a token does not" ;;
esac
cli_config=$scratch/cli.tfrc
# printf is a builtin: the token reaches no argv and no here-document file.
printf 'credentials "%s" {\n  token = "%s"\n}\nprovider_installation {\n  direct {\n    include = ["registry.opentofu.org/hashicorp/*"]\n  }\n}\n' \
  "$host" "$token" >"$cli_config"
chmod 0600 "$cli_config"

# --- the fresh tree: the live layout under its own root ---
if [ "$mode" = check ]; then
  fresh_root=$scratch/fresh
else
  fresh_root=$work/fresh
fi
fresh=$fresh_root/testdata/fixtures/report
mkdir -p "$fresh"

recorded=$("$fp" cases "$live/PIN.json" recorded) || die "PIN.json lists no usable cases"
[ -n "$recorded" ] || die "PIN.json lists no recorded case"
for c in $recorded; do
  echo "record-report-fixtures: $c: tofu init" >&2
  case_dir=$scratch/cases/$c
  "$fp" authored "$live/$c/input" "$case_dir" || die "$c: copying the configuration failed"
  "$fp" validate "$case_dir" "$host" || die "$c: a module source is not allowed; nothing was fetched"
  mkdir -m 0700 "$scratch/data/$c"
  if ! env -i PATH=/usr/bin:/bin HOME="$scratch/home" TMPDIR="$scratch/tmp" \
      TF_DATA_DIR="$scratch/data/$c" TF_CLI_CONFIG_FILE="$cli_config" TF_IN_AUTOMATION=1 \
      "$tofu_bin" -chdir="$case_dir" init -backend=false -input=false -no-color \
      >"$scratch/tmp/init-$c.log" 2>&1; then
    tail -n 20 "$scratch/tmp/init-$c.log" >&2
    die "$c: tofu init failed"
  fi
  "$fp" authored "$live/$c/input" "$fresh/$c/input" || die "$c: copying the configuration failed"
  "$fp" assemble "$case_dir" "$scratch/data/$c" "$fresh/$c/input" "$host" \
    || die "$c: tofu fetched a module the pin does not allow; nothing was copied"
done
"$fp" synthesize "$fresh" "$live/PIN.json" || die "a synthesized case no longer fits its transform"
"$fp" pin "$fresh" "$live/PIN.json" "$host" "$tofu_version" "$(date -u +%F)" || die "writing PIN.json failed"

# --- regenerate every expected file from the fresh inputs, twice ---
golden='^(TestReportProjections|TestReportSARIFParity|TestReportSpaceliftParity|TestReportRecordedExitCodes|TestReportEnvironmentDiagnostic)$'
regenerate() {
  run_go CTFKIT_RERECORD=1 CTFKIT_FIXTURE_ROOT="$fresh_root" \
    "$go_bin" test -count=1 ./internal/cli -run "$golden" >"$scratch/tmp/regen.log" 2>&1 \
    || { tail -n 40 "$scratch/tmp/regen.log" >&2; die "regenerating the expected files failed"; }
}
regenerate
cp -R "$fresh" "$scratch/pass1"
regenerate
if ! "$fp" drift "$scratch/pass1" "$fresh" >&2; then
  die "a second regeneration changed the expected files; the golden tests are not deterministic"
fi

# --- scan before anything is compared, printed or swapped ---
# The status is captured with || so neither a hit nor the ERR trap ends the run
# before it is classified.
scan=0
CTFKIT_SCAN_LITERAL=$token "$fp" scan "$fresh" >"$scratch/tmp/scan.log" 2>&1 || scan=$?
if [ "$scan" -ne 0 ]; then
  cat "$scratch/tmp/scan.log" >&2
  if [ "$scan" -eq 3 ]; then
    echo "record-report-fixtures: the recorded tree carries the token or a signed URL: rotate $token_var's credential, then rerun" >&2
    exit 3
  fi
  die "the recorded tree has a pattern hit; nothing was compared or swapped"
fi

"$fp" check "$fresh" >&2 || die "the fresh pack fails its own pin check"

if [ "$mode" = check ]; then
  drift=0
  "$fp" drift "$live" "$fresh" || drift=$?
  case "$drift" in
    0) echo "record-report-fixtures: no drift from the pinned pack" >&2; exit 0 ;;
    1) echo "record-report-fixtures: drift: re-record in a reviewed PR" >&2; exit 1 ;;
    *) exit 2 ;;
  esac
fi

# --- swap: live -> backup, fresh -> live, delete backup ---
mv "$live" "$backup"
# Test seam, honored only in a copy with no .git (what the recorder test
# builds): a crash between the two renames, which the trap must undo.
if [ "${CTFKIT_RECORDER_TEST_FAIL_SWAP:-}" = 1 ] && [ ! -e "$repo/.git" ]; then
  exit 2
fi
mv "$fresh" "$live"
swapped=1
echo "record-report-fixtures: re-recorded $live; review the diff, run make check and open a PR" >&2
