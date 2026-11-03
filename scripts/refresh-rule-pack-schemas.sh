#!/usr/bin/env bash
# Regenerates every rule pack's schema.json from its provider's own schema and
# writes draft-rule proposals, one markdown file per pack, to the directory
# named as the first argument (default: a new temporary directory).
#
# A provider whose newest release has a major version no pack covers first
# gets a new pack directory, copied from its newest pack, so the validation
# test can say what the new major broke.
#
# Needs terraform and network access to the provider registry. The weekly
# rule-pack-schemas workflow runs it; run it locally the same way:
#
#   scripts/refresh-rule-pack-schemas.sh /tmp/proposals
#   go test ./internal/analyzer/sensitivechange/ -run Schema
set -euo pipefail

cd "$(dirname "$0")/.."
rules=internal/rulepack/rules
out=${1:-$(mktemp -d)}
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export TF_PLUGIN_CACHE_DIR="$work/plugin-cache" CHECKPOINT_DISABLE=1
mkdir -p "$TF_PLUGIN_CACHE_DIR"

# install <dir> <source> [constraint]: installs one provider in dir and prints
# the version the lock file records.
install() {
  local dir=$1 source=$2 constraint=${3:-} version=""
  [ -n "$constraint" ] && version=", version = \"$constraint\""
  mkdir -p "$dir"
  printf 'terraform {\n  required_providers {\n    p = { source = "%s"%s }\n  }\n}\n' "$source" "$version" > "$dir/main.tf"
  terraform -chdir="$dir" init -backend=false -input=false -no-color > "$dir/init.log"
  sed -n 's/^  version *= *"\([^"]*\)".*/\1/p' "$dir/.terraform.lock.hcl" | head -n 1
}

for provider in "$rules"/*/; do
  provider=${provider%/}
  name=$(basename "$provider")
  newest=$(find "$provider" -mindepth 1 -maxdepth 1 -type d -name 'v*' | sed 's|.*/v||' | sort -n | tail -n 1)
  source=$(sed -n 's/^source: *//p' "$provider/v$newest/provider.yaml")
  latest=$(install "$work/latest-$name" "$source")
  major=${latest%%.*}
  if [ "$major" -gt "$newest" ]; then
    mkdir "$provider/v$major"
    cp "$provider/v$newest"/*.yaml "$provider/v$major/"
    echo "- New major: \`$name/v$major\` copied from \`v$newest\` for $source $latest." >> "$out/new-majors.md"
  fi
done

for dir in "$rules"/*/v*/; do
  dir=${dir%/}
  pack=${dir#"$rules"/}
  slug=${pack//\//-}
  source=$(sed -n 's/^source: *//p' "$dir/provider.yaml")
  version=$(install "$work/$slug" "$source" "~> ${pack##*/v}.0")
  terraform -chdir="$work/$slug" providers schema -json > "$work/$slug/schema.json"
  go run ./cmd/rulepackgen -pack "$pack" -schema "$work/$slug/schema.json" -version "$version" \
    -proposals "$out/$slug.md"
done
echo "proposals in $out"
