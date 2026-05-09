#!/usr/bin/env bash
# render-host.sh — OPTIONAL HeyGen avatar bookend.
#
# If HEYGEN_AVATAR_ID is set in .env, this renders a 5-second talking-head
# clip that swaps in for the CTA beat (0:55–1:00). The Promo60 composition
# checks for `host/cta.webm` at static-file time and includes it when present.
#
# If HEYGEN_AVATAR_ID is unset, this script is a no-op and the existing
# pure-motion-graphic CTA stands. That's the default.
#
# Usage: render-host.sh <output.webm>

set -euo pipefail

OUTPUT="${1:?output path required}"

if [ -z "${HEYGEN_AVATAR_ID:-}" ]; then
  echo "  [host] HEYGEN_AVATAR_ID not set — skipping avatar bookend (motion-graphic CTA stands)"
  exit 0
fi

: "${HEYGEN_API_KEY:?HEYGEN_API_KEY missing}"
VOICE_ID="${HEYGEN_VOICE_ID:?HEYGEN_VOICE_ID missing}"
API="https://api.heygen.com"

# Bookend script. Kept short so the avatar lands cleanly inside the 5s slot.
TEXT="Become AI-first. Safely. Rafter dot s o."

echo "  [host] submitting avatar render (avatar_id=$HEYGEN_AVATAR_ID)"
JOB=$(jq -n \
  --arg t   "$TEXT" \
  --arg v   "$VOICE_ID" \
  --arg av  "$HEYGEN_AVATAR_ID" \
  '{
    caption: false,
    dimension: { width: 1920, height: 1080 },
    video_inputs: [{
      character: { type: "avatar", avatar_id: $av, avatar_style: "normal" },
      voice:     { type: "text",   input_text: $t,  voice_id: $v },
      background:{ type: "color",  value: "#0a0a0a" }
    }]
  }' \
  | curl -sS -X POST "$API/v2/video/generate" \
      -H "X-Api-Key: $HEYGEN_API_KEY" \
      -H "Content-Type: application/json" \
      -d @- \
  | jq -r '.data.video_id // .video_id')

[ -n "$JOB" ] || { echo "  [host] no video_id returned" >&2; exit 1; }
echo "  [host] job $JOB — polling..."

for _ in $(seq 1 60); do
  sleep 8
  STATUS=$(curl -sS "$API/v1/video_status.get?video_id=$JOB" \
    -H "X-Api-Key: $HEYGEN_API_KEY")
  s=$(echo "$STATUS" | jq -r '.data.status // .status // empty')
  if [ "$s" = "completed" ]; then
    URL=$(echo "$STATUS" | jq -r '.data.video_url // .video_url')
    mkdir -p "$(dirname "$OUTPUT")"
    # HeyGen ships MP4; transcode to WebM with alpha-friendly codec for clean
    # compositing in Remotion. Crop to a centered portrait if the avatar's
    # framing leaves dead space on the sides.
    curl -sSL "$URL" -o "${OUTPUT%.webm}.mp4"
    ffmpeg -y -i "${OUTPUT%.webm}.mp4" \
      -c:v libvpx-vp9 -b:v 0 -crf 30 -row-mt 1 \
      -c:a libopus -b:a 128k \
      "$OUTPUT" -loglevel error
    rm -f "${OUTPUT%.webm}.mp4"
    echo "  [host] wrote $OUTPUT"
    exit 0
  fi
  if [ "$s" = "failed" ]; then
    echo "  [host] HeyGen render failed: $STATUS" >&2
    exit 1
  fi
done
echo "  [host] timed out" >&2
exit 1
