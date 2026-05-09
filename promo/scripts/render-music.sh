#!/usr/bin/env bash
# render-music.sh — generate the 60s music bed via Suno API.
# Submits the brief, polls until complete, downloads, trims to 60s, normalizes.
#
# Usage: render-music.sh <prompt.txt> <output.mp3>

set -euo pipefail

INPUT="${1:?prompt.txt required}"
OUTPUT="${2:?output.mp3 required}"
: "${SUNO_API_KEY:?SUNO_API_KEY missing}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PROMPT="$(cat "$INPUT")"

echo "  [music] submitting Suno generation request..."
JOB=$(curl -sS -X POST "https://studio-api.suno.ai/api/external/generate/v2" \
  -H "Authorization: Bearer ${SUNO_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg p "$PROMPT" \
      '{prompt:$p, make_instrumental:true, model:"chirp-v4", wait_audio:false}')")

JOB_ID=$(echo "$JOB" | jq -r '.id // .[0].id // empty')
[ -n "$JOB_ID" ] || { echo "  [music] no job id in response: $JOB" >&2; exit 1; }

echo "  [music] job $JOB_ID — polling..."
for i in $(seq 1 60); do
  sleep 10
  STATUS=$(curl -sS "https://studio-api.suno.ai/api/external/generate/${JOB_ID}" \
    -H "Authorization: Bearer ${SUNO_API_KEY}")
  AUDIO_URL=$(echo "$STATUS" | jq -r '.audio_url // empty')
  if [ -n "$AUDIO_URL" ] && [ "$AUDIO_URL" != "null" ]; then
    echo "  [music] ready: $AUDIO_URL"
    curl -sSL "$AUDIO_URL" -o "$WORK/raw.mp3"
    break
  fi
done

[ -s "$WORK/raw.mp3" ] || { echo "  [music] timed out waiting for audio" >&2; exit 1; }

# Trim to 60s exactly and normalize bed to -16 LUFS (will be ducked under VO at master).
ffmpeg -y -i "$WORK/raw.mp3" -t 60 \
  -af "loudnorm=I=-16:TP=-1.5:LRA=11" \
  -c:a libmp3lame -b:a 192k "$OUTPUT" -loglevel error

echo "  [music] wrote $OUTPUT"
