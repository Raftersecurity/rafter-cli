#!/usr/bin/env bash
# render-vo.sh — synthesize the voiceover from audio/prompts/voiceover.json
# using ElevenLabs API, then concatenate lines with the timing baked into the JSON.
#
# Usage: render-vo.sh <prompts.json> <output.mp3>

set -euo pipefail

INPUT="${1:?prompts.json required}"
OUTPUT="${2:?output.mp3 required}"
: "${ELEVENLABS_API_KEY:?ELEVENLABS_API_KEY missing}"
VOICE_ID="${ELEVENLABS_VOICE_ID:-nPczCjzI2devNBz1zQrb}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Render each line as its own MP3, then place it on a 60s silent canvas at its start time.
LINE_COUNT=$(jq '.lines | length' "$INPUT")
for i in $(seq 0 $((LINE_COUNT - 1))); do
  line=$(jq -r ".lines[$i]" "$INPUT")
  id=$(echo "$line" | jq -r .id)
  text=$(echo "$line" | jq -r .text)
  start=$(echo "$line" | jq -r .start)

  echo "  [vo] rendering $id @ ${start}s — \"$text\""

  curl -sS -X POST "https://api.elevenlabs.io/v1/text-to-speech/${VOICE_ID}" \
    -H "xi-api-key: ${ELEVENLABS_API_KEY}" \
    -H "Content-Type: application/json" \
    -H "Accept: audio/mpeg" \
    -d "$(jq -n --arg t "$text" --argjson s "$(jq .settings "$INPUT")" \
        '{text:$t, model_id:"eleven_v3", voice_settings:$s}')" \
    -o "$WORK/$id.mp3"
done

# Build a 60s silent base and overlay each line at its timestamp.
ffmpeg -y -f lavfi -i "anullsrc=channel_layout=stereo:sample_rate=48000" -t 60 -q:a 9 -acodec libmp3lame "$WORK/base.mp3" -loglevel error

# adelay one line at a time, summing into the canvas.
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
