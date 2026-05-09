#!/usr/bin/env bash
# fetch-sfx.sh — download CC0 SFX listed in audio/sfx/manifest.json.
# Manifest entries pin a freesound.org sound id and a SHA-256 of the expected file.
# This is a content hash gate — pipeline fails if upstream changes the file.
#
# Usage: fetch-sfx.sh <manifest.json> <out-dir>

set -euo pipefail

MANIFEST="${1:?manifest.json required}"
OUTDIR="${2:?out-dir required}"
mkdir -p "$OUTDIR"

jq -c '.[]' "$MANIFEST" | while read -r row; do
  name=$(echo "$row" | jq -r .name)
  url=$(echo "$row" | jq -r .url)
  sha=$(echo "$row" | jq -r .sha256)
  out="$OUTDIR/$name"

  if [ -f "$out" ] && echo "$sha  $out" | sha256sum -c --status; then
    echo "  [sfx] cached $name"
    continue
  fi

  echo "  [sfx] fetching $name"
  curl -sSL "$url" -o "$out"
  echo "$sha  $out" | sha256sum -c --status \
    || { echo "  [sfx] hash mismatch for $name — refusing to use" >&2; exit 1; }
done

echo "  [sfx] all sfx verified"
