#!/usr/bin/env bash
# Maintainer check for the override_twins fixtures: both roots and
# their modules/store must load under OpenTofu and Terraform, with no network.
# CI has neither binary, so this is run by hand after editing a fixture:
#
#   testdata/override_twins/check.sh
#
# `providers` loads and validates the configuration, override files and .tofu
# twins included, without downloading anything. Each directory is copied to a
# scratch location first so no lock file or cache lands in the repository.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/ctfkit-override-twins.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

status=0
for syntax in native json; do
  for tool in tofu terraform; do
    command -v "$tool" >/dev/null || { echo "skip: $tool is not on PATH"; continue; }
    for dir in "" modules/store; do
      copy="$scratch/$tool-$syntax-${dir//\//-}"
      cp -R "$here/$syntax/$dir" "$copy"
      if (cd "$copy" && TF_IN_AUTOMATION=1 "$tool" providers >/dev/null 2>"$copy.err"); then
        echo "ok:   $tool $syntax/${dir:-.}"
      else
        echo "FAIL: $tool $syntax/${dir:-.}"
        sed 's/^/      /' "$copy.err"
        status=1
      fi
    done
  done
done
exit "$status"
