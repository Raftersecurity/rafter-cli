#!/usr/bin/env bash
# render-vo.sh — synthesize the voiceover via HeyGen v2 video API,
# then extract audio per line and place each line on a 60s silent canvas
# at the start time declared in audio/prompts/voiceover.json.
#
# HeyGen's TTS is exposed through the video-generate endpoint. We render
# the smallest possible video per line (we discard the pixels), strip audio
# with ffmpeg, then assemble the final 60s mix in one filter graph.
#
# Usage: render-vo.sh <prompts.json> <output.mp3>

set -euo pipefail

INPUT="${1:?prompts.json required}"
OUTPUT="${2:?output.mp3 required}"
: "${HEYGEN_API_KEY:?HEYGEN_API_KEY missing}"
VOICE_ID="${HEYGEN_VOICE_ID:?HEYGEN_VOICE_ID missing}"

API="https://api.heygen.com"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

LINE_COUNT=$(jq '.lines | length' "$INPUT")
RATE=$(jq -r '.settings.rate // 1.0' "$INPUT")
PITCH=$(jq -r '.settings.pitch // 0' "$INPUT")
EMOTION=$(jq -r '.settings.emotion // "Friendly"' "$INPUT")

submit_line() {
  local text="$1"
  jq -n \
    --arg text   "$text" \
    --arg voice  "$VOICE_ID" \
    --arg emo    "$EMOTION" \
    --argjson rate  "$RATE" \
    --argjson pitch "$PITCH" \
    '{
      caption: false,
      dimension: { width: 1280, height: 720 },
      video_inputs: [{
        character: { type: "avatar", avatar_id: "Vanessa-public", avatar_style: "normal" },
        voice:     { type: "text", input_text: $text, voice_id: $voice,
                     emotion: $emo, speed: $rate, pitch: $pitch },
        background:{ type: "color", value: "#000000" }
      }]
    }' \
  | curl -sS -X POST "$API/v2/video/generate" \
      -H "X-Api-Key: $HEYGEN_API_KEY" \
      -H "Content-Type: application/json" \
      -d @- \
  | jq -r '.data.video_id // .video_id // empty'
}

poll_until_done() {
  local id="$1"
  for _ in $(seq 1 60); do
    sleep 8
    local resp status url
    resp=$(curl -sS "$API/v1/video_status.get?video_id=$id" \
      -H "X-Api-Key: $HEYGEN_API_KEY")
    status=$(echo "$resp" | jq -r '.data.status // .status // empty')
    if [ "$status" = "completed" ]; then
      echo "$resp" | jq -r '.data.video_url // .video_url'
      return 0
    fi
    if [ "$status" = "failed" ]; then
      echo "  [vo] HeyGen render failed for $id: $resp" >&2
      return 1
    fi
  done
  echo "  [vo] timed out waiting for $id" >&2
  return 1
}

# ── Render every line, extract audio ─────────────────────────────
for i in $(seq 0 $((LINE_COUNT - 1))); do
  line=$(jq -r ".lines[$i]" "$INPUT")
  id=$(echo "$line" | jq -r .id)
  text=$(echo "$line" | jq -r .text)
  start=$(echo "$line" | jq -r .start)

  echo "  [vo] rendering $id @ ${start}s — \"$text\""

  video_id=$(submit_line "$text")
  [ -n "$video_id" ] || { echo "  [vo] no video_id returned" >&2; exit 1; }

  url=$(poll_until_done "$video_id")
  curl -sSL "$url" -o "$WORK/$id.mp4"
  ffmpeg -y -i "$WORK/$id.mp4" -vn -acodec libmp3lame -q:a 4 "$WORK/$id.mp3" -loglevel error
done

# ── Build a 60s silent canvas, overlay each line at its timestamp ──
ffmpeg -y -f lavfi -i "anullsrc=channel_layout=stereo:sample_rate=48000" \
  -t 60 -q:a 9 -acodec libmp3lame "$WORK/base.mp3" -loglevel error

INPUTS=("$WORK/base.mp3")
FILTERS=("[0:a]aresample=48000[base]")
LAST="base"
for i in $(seq 0 $((LINE_COUNT - 1))); do
  line=$(jq -r ".lines[$i]" "$INPUT")
  id=$(echo "$line" | jq -r .id)
  start_ms=$(echo "$line" | jq -r '.start * 1000 | floor')
  INPUTS+=("$WORK/$id.mp3")
  IDX=$((i + 1))
  FILTERS+=("[${IDX}:a]adelay=${start_ms}|${start_ms},aresample=48000[d${i}]")
  FILTERS+=("[${LAST}][d${i}]amix=inputs=2:duration=longest:dropout_transition=0[mix${i}]")
  LAST="mix${i}"
done

CMD=(ffmpeg -y)
for inp in "${INPUTS[@]}"; do CMD+=(-i "$inp"); done
CMD+=(-filter_complex "$(IFS=';'; echo "${FILTERS[*]}")" -map "[${LAST}]" -ac 2 -ar 48000 -b:a 192k "$OUTPUT" -loglevel error)
"${CMD[@]}"

echo "  [vo] wrote $OUTPUT"
