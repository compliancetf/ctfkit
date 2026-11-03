#!/usr/bin/env bash
# Record the provider side of the instance_key goldens
# (pkg/verdict/testdata/instancekey/<type>/{apply,envelope}/, SOURCE.json)
# with the terraform-provider-aws record build tag. It copies
# pkg/verdict/testdata/instancekey/record/record_goldens_test.go into the
# provider checkout's internal/proxy, runs it against the in-process fake
# upstream (no real provider, no cloud, no Terraform binary) and removes it.
#
#   scripts/record-instancekey-apply.sh <provider-checkout> <type>...
#
# The checkout must be clean: SOURCE.json names its HEAD commit.
set -Eeuo pipefail
umask 022

die() { echo "record-instancekey-apply: $*" >&2; exit 2; }
[ $# -ge 2 ] || die "usage: $0 <provider-checkout> <type>..."

repo=$(cd "$(dirname "$0")/.." && pwd -P)
gold="$repo/pkg/verdict/testdata/instancekey"
prov=$(cd "$1" && pwd -P) || die "no provider checkout at $1"
shift
[ -f "$prov/internal/proxy/record_on.go" ] || die "$prov has no record build tag (internal/proxy/record_on.go)"
status=$(git -C "$prov" status --porcelain) || die "cannot read git status of $prov"
[ -z "$status" ] || die "$prov has uncommitted changes"
commit=$(git -C "$prov" rev-parse HEAD)
for typ in "$@"; do
  [[ "$typ" =~ ^[a-z0-9_]+$ ]] && [ -f "$gold/$typ/plan.json" ] || die "no golden type $typ"
done

out=$(mktemp -d)
driver="$prov/internal/proxy/zz_record_goldens_test.go"
trap 'rm -rf "$out" "$driver"' EXIT
cp "$gold/record/record_goldens_test.go" "$driver"
(cd "$prov" && CTFKIT_GOLDEN_DIR="$gold" CTFKIT_RECORD_OUT="$out" CTFKIT_PROVIDER_COMMIT="$commit" \
  CTFKIT_GOLDEN_TYPES="$*" go test -count=1 -tags record -run '^TestRecordGoldens$' ./internal/proxy/) ||
  die "recording failed"
for typ in "$@"; do
  [ -f "$out/$typ/SOURCE.json" ] || die "$typ: nothing recorded"
  rm -rf "${gold:?}/$typ/apply" "${gold:?}/$typ/envelope" "$gold/$typ/SOURCE.json"
  cp -R "$out/$typ/apply" "$out/$typ/envelope" "$out/$typ/SOURCE.json" "$gold/$typ/"
  chmod -R go+rX "$gold/$typ/apply" "$gold/$typ/envelope"
  echo "recorded $typ at $commit"
done
