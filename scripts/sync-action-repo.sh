#!/bin/sh
# Copy the GitHub Action (action.yml and defaults/) from adapters/github into a checkout of the
# public compliancetf/ctfkit-action repository. That repository keeps its own README. It only
# copies files: review, commit and tag in that checkout yourself.
#
# Usage: scripts/sync-action-repo.sh <path-to-ctfkit-action-checkout>
set -eu

if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
	echo "usage: $0 <path-to-ctfkit-action-checkout>" >&2
	exit 2
fi

src="$(cd "$(dirname "$0")/../adapters/github" && pwd)"
dest="$1"

cp "$src/action.yml" "$dest/"
rm -rf "$dest/defaults"
cp -R "$src/defaults" "$dest/defaults"

echo "Copied action.yml and defaults/ from $src to $dest"
