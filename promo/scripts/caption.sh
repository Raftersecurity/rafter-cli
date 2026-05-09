#!/usr/bin/env bash
# caption.sh — transcribe the VO using whisper.cpp into an SRT.
# Auto-installs whisper.cpp + the large-v3 model into ~/.cache/whisper-cpp on first run.
#
# Usage: caption.sh <vo.mp3> <out.srt>

set -euo pipefail

VO="${1:?vo.mp3 required}"
OUT="${2:?out.srt required}"
CACHE="${WHISPER_CACHE:-$HOME/.cache/whisper-cpp}"
MODEL="$CACHE/ggml-large-v3.bin"
WHISPER="$CACHE/whisper.cpp/main"

if [ ! -x "$WHISPER" ]; then
  echo "  [caption] bootstrapping whisper.cpp..."
  mkdir -p "$CACHE"
  git clone --depth 1 https://github.com/ggerganov/whisper.cpp "$CACHE/whisper.cpp"
  make -C "$CACHE/whisper.cpp" -j
fi
if [ ! -f "$MODEL" ]; then
  echo "  [caption] downloading large-v3 model..."
  curl -sSL "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-large-v3.bin" -o "$MODEL"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ffmpeg -y -i "$VO" -ar 16000 -ac 1 "$WORK/vo.wav" -loglevel error

"$WHISPER" -m "$MODEL" -f "$WORK/vo.wav" -osrt -of "$WORK/vo" -l en
cp "$WORK/vo.srt" "$OUT"
echo "  [caption] wrote $OUT"
