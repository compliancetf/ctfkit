#!/usr/bin/env bash
# Public-repo hygiene guard: nothing private reaches this repository.
#
# Usage:
#   scripts/check-no-private-content.sh [--root DIR]
#   scripts/check-no-private-content.sh --self-test
#
# Scans tracked and untracked, non-ignored files under DIR (default: the repo
# root), so a planted file fails before it is committed. Prints each hit.
# Exit 0 = clean, 1 = private content found, 2 = error.
#
# Rules:
#   1. Path: local agent and issue-tracker state (.beads/, .claude/, .codex/,
#      .cursor/, .agents/, issues.jsonl) is never part of the tree.
#   2. Text, everywhere but this script: no absolute home-directory paths
#      (placeholder users such as user, dev and bobthecorp are fine) and no
#      issue-tracker ids (ctfkit-xxx, ctf-xxx; the numeric rule ids ctf-001 and
#      up are fine) and no planning task ids (P<n>-T<n>).
#   3. Text: no match of a private pattern list. The list names terms that
#      must not be published, so it is never committed: one extended regex
#      per line (# comments and blank lines skipped) in the file named by
#      COMPLIANCETF_PRIVATE_PATTERNS_FILE, default <git common dir>/info/private-patterns.
#      A missing default file skips this rule; a missing named file is an error.
set -euo pipefail

# A git hook runs with GIT_DIR and friends set; they would point every
# `git -C <dir>` below (the self-test's scratch repos included) at the
# hook's repository.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_PREFIX

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_PATH_RE='(^|/)\.(beads|claude|codex|cursor|agents)/|(^|/)issues\.jsonl$'
HOME_PATH_RE='/(Users|home)/[A-Za-z0-9._-]+'
PLACEHOLDER_HOME_RE='/(Users|home)/(user|dev|runner|bobthecorp|example)'
# The id may end a sentence; a file name such as ctfkit-run.json is not an id.
TRACKER_ID_RE='(^|[^A-Za-z0-9_-])ctf(kit)?-[a-z0-9]{3}(\.[0-9]+)*([^A-Za-z0-9_.-]|\.[^A-Za-z0-9]|\.?$)'
# A match that is only a numeric rule id (ctf-001), with its boundary characters.
RULE_ID_RE=':[^A-Za-z0-9_-]?ctf-[0-9]{3}[^A-Za-z0-9_-]?$'
TASK_ID_RE='(^|[^A-Za-z0-9])P[0-9]+[A-Z]?-T[0-9]+[a-z]?([^A-Za-z0-9]|$)'
SELF='scripts/check-no-private-content.sh'

die() { echo "check-no-private-content: $*" >&2; exit 2; }

check() {
  local root=$ROOT
  while [[ $# -gt 0 ]]; do
    case $1 in
      --root) root=$2; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  list=$(mktemp)
  trap 'rm -f "$list"' EXIT
  git -C "$root" ls-files -z --cached --others --exclude-standard >"$list" 2>/dev/null ||
    die "cannot list files under $root (not a git checkout?)"

  local patterns=${COMPLIANCETF_PRIVATE_PATTERNS_FILE:-}
  if [[ -n $patterns ]]; then
    [[ -f $patterns && -r $patterns ]] || die "cannot read COMPLIANCETF_PRIVATE_PATTERNS_FILE $patterns"
  else
    patterns="$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)/info/private-patterns"
  fi

  # Matched case-insensitively: macOS checkouts fold case.
  shopt -s nocasematch
  local path hit=0 out
  while IFS= read -r -d '' path; do
    if [[ $path =~ $AGENT_PATH_RE ]]; then
      echo "$path: local agent or issue-tracker state"; hit=1
    fi
  done <"$list"
  shopt -u nocasematch

  # Text rules: git grep over the same file set, binary files skipped.
  # -o: each match is filtered alone, so an allowed match cannot hide a real one on its line.
  out=$(textgrep "$root" -o -e "$HOME_PATH_RE" -- . ":!$SELF")
  out=$(printf '%s\n' "$out" | grep -vE ":${PLACEHOLDER_HOME_RE}\$" || true)
  [[ -z $out ]] || { echo "$out" | sed 's/$/  <- home directory path/'; hit=1; }
  out=$(textgrep "$root" -o -e "$TRACKER_ID_RE" -- . ":!$SELF")
  out=$(printf '%s\n' "$out" | grep -vE "$RULE_ID_RE" || true)
  [[ -z $out ]] || { echo "$out" | sed 's/$/  <- issue-tracker id/'; hit=1; }
  out=$(textgrep "$root" -e "$TASK_ID_RE" -- . ":!$SELF")
  [[ -z $out ]] || { echo "$out" | sed 's/$/  <- planning task id/'; hit=1; }
  if [[ -f $patterns && -r $patterns ]]; then
    local list2 rc=0
    list2=$(mktemp)
    grep -vE '^[[:space:]]*(#|$)' "$patterns" >"$list2" || rc=$?
    [[ $rc -le 1 ]] || { rm -f "$list2"; die "cannot read pattern file $patterns"; }
    if [[ -s $list2 ]]; then
      out=$(textgrep "$root" -i -f "$list2")
      [[ -z $out ]] || { echo "$out" | sed 's/$/  <- private pattern/'; hit=1; }
    fi
    rm -f "$list2"
  fi
  return $hit
}

# textgrep ROOT ARGS...: matching lines as path:line:text; exit 2 on a git error.
# The home-path and tracker-id rules exclude this script (its self-test plants
# both); the private-pattern rule covers it too.
textgrep() {
  local root=$1 rc=0
  shift
  git -C "$root" grep --untracked -I -n -E "$@" || rc=$?
  [[ $rc -le 1 ]] || die "git grep failed (exit $rc)"
}

# --- self-test --------------------------------------------------------------

st_fail=0
# expect <want-exit> <name> [path=content]...: plant the files in a fresh git
# repo (untracked, as a developer would before `git add`) and run the check.
expect() {
  local want=$1 name=$2 got=0 dir spec
  shift 2
  dir=$(mktemp -d "$tmp/case.XXXXXX")
  git -C "$dir" init -q
  for spec in "$@"; do
    mkdir -p "$dir/$(dirname "${spec%%=*}")"
    printf '%s\n' "${spec#*=}" >"$dir/${spec%%=*}"
  done
  "$0" --root "$dir" >/dev/null 2>&1 || got=$?
  if [[ $got != "$want" ]]; then
    echo "FAIL $name: exit $got, want $want"
    st_fail=1
  else
    echo "ok   $name"
  fi
}

self_test() {
  # The cases set their own pattern file; an ambient one must not leak in.
  unset COMPLIANCETF_PRIVATE_PATTERNS_FILE
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  local got=0

  echo "private content (exit 1):"
  expect 1 tracker-dir '.beads/issues.jsonl={}'
  expect 1 agent-settings '.claude/settings.json={}'
  expect 1 agent-settings-case '.Codex/hooks.json={}'
  expect 1 tracker-export 'export/issues.jsonl={}'
  expect 1 home-path 'docs/a.md=see /Users/alice/src/x'
  expect 1 linux-home-path 'main.go=// built in /home/alice/go'
  expect 1 bare-home-dir 'docs/a.md=HOME=/home/alice'
  expect 1 home-path-beside-placeholder 'docs/a.md=/home/user/x and /Users/alice/y'
  expect 1 ctfkit-id 'main.go=// see ctfkit-zz1'
  expect 1 ctfkit-child-id 'main.go=// ctfkit-zz1.37: wire the cask'
  expect 1 ctf-id 'main.go=// planned in ctf-zz3.1'
  expect 1 ctfkit-id-in-name 'main_test.go=func TestX(t *testing.T) { t.Run("ctfkit-zz2", nil) }'
  expect 1 ctfkit-id-ends-sentence 'docs/a.md=Tracked in ctfkit-zz1.'
  expect 1 task-id 'main.go=// fixed in P1-T2'
  expect 1 task-id-letter 'main.go=// see P0B-T24'
  expect 1 tracker-id-beside-rule-id 'main.go=// ctf-001 and ctf-zz4'
  printf '# private terms\n\nsecretcodename\n' >"$tmp/patterns"
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/patterns" expect 1 private-pattern 'README.md=the secretcodename plan'
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/patterns" expect 1 private-pattern-case 'README.md=the SecretCodename plan'
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/patterns" expect 1 private-pattern-in-guard "$SELF=# secretcodename"
  expect 1 default-patterns-file '.git/info/private-patterns=secretcodename' 'README.md=the secretcodename plan'
  echo "clean (exit 0):"
  expect 0 empty
  expect 0 guard-own-fixtures "$SELF=# /Users/alice/x ctfkit-zz1 P1-T2"
  expect 0 placeholder-home 'main_test.go=dir := "/home/user/x" + "/Users/dev/y"'
  expect 0 not-a-task-id 'main.go=// P99 latency and EP-T1000X are fine'
  expect 0 rule-ids 'main.go=// ctf-001, ctf-004: rule ids' 'out.golden="ruleId": "ctf-003"'
  expect 0 product-names 'README.md=ctfkit-action, ctfkit_1.0.0_Linux, ctf-rules-check'
  expect 0 file-names 'docs/a.md=writes ctfkit-run.json and ctf-run.sarif'
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/patterns" expect 0 private-pattern-clean 'README.md=nothing here'
  echo "error (exit 2):"
  "$0" --root "$tmp/missing" >/dev/null 2>&1 || got=$?
  if [[ $got != 2 ]]; then echo "FAIL not-a-repo: exit $got, want 2"; st_fail=1; else echo "ok   not-a-repo"; fi
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp/none" expect 2 missing-patterns-file 'README.md=x'
  COMPLIANCETF_PRIVATE_PATTERNS_FILE="$tmp" expect 2 patterns-file-is-dir 'README.md=x'

  if [[ $st_fail != 0 ]]; then echo "self-test FAILED"; return 1; fi
  echo "self-test passed"
}

if [[ ${1:-} == --self-test ]]; then
  self_test
  exit $?
fi
check "$@"
