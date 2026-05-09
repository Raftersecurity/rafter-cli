# Rafter Promo Video — Agent-Only Production Pipeline

Builds the 60s promo from `docs/promo-video-60s-storyboard.md` end-to-end with no GUI, no human in the timeline. Everything is a file in git; every output regenerates from `make video`.

## One-shot

```sh
cp .env.example .env       # fill HEYGEN_API_KEY (+ HEYGEN_VOICE_ID), SUNO_API_KEY
make video                 # 60s 16:9 master at build/promo-60s.mp4
make deliver               # also writes 9:16 and 1:1 reframes
```

Optional: set `HEYGEN_AVATAR_ID` and run `make host` to add a talking-head bookend on the CTA beat.

## Stack

| Layer | Tool | Source files | Output |
|-------|------|--------------|--------|
| Terminal capture | `vhs` (charmbracelet) | `tape/*.tape` | `remotion/public/tape/*.mp4` |
| Voiceover | **HeyGen v2 video API** (TTS, audio extracted) | `audio/prompts/voiceover.json` | `remotion/public/vo/full.mp3` |
| Avatar bookend (optional) | **HeyGen v2 video API** (with `HEYGEN_AVATAR_ID`) | `scripts/render-host.sh` | `remotion/public/host/cta.webm` |
| Music bed | Suno API (HeyGen does not compose music) | `audio/prompts/music.txt` | `remotion/public/music/bed.mp3` |
| SFX | freesound.org CC0 manifest | `audio/sfx/manifest.json` | `remotion/public/sfx/*.wav` |
| Motion graphics | Remotion | `remotion/src/**/*.tsx` | render via `npx remotion render` |
| Captions | whisper.cpp large-v3 | derived from VO | `build/captions.srt` |
| Loudness | ffmpeg `loudnorm` | — | -14 LUFS master |
| Reframes | Remotion compositions `Promo60-16x9` / `Promo60-9x16` / `Promo60-1x1` | same JSX | three masters |

**Why HeyGen for VO instead of ElevenLabs:** HeyGen's TTS is exposed through the same v2 video endpoint that drives their avatar product, so the same API key + the same voice IDs cover both audio-only VO *and* the optional talking-head bookend on the CTA beat. Lower surface area, one provider to manage. The trade-off: each VO line round-trips through a video render (we discard the pixels and `ffmpeg -vn` the audio). Slower than a pure-TTS API, but keeps the stack to one upstream.

**Why music still routes through Suno:** HeyGen has no music-bed composition product. The Suno brief (`audio/prompts/music.txt`) is bar-locked to the storyboard's drop at 0:50, which is hard to replace with stock library music.

## Pipeline (DAG)

```
voiceover.json ──▶ make vo ──▶ vo/full.mp3 ──┐
music.txt      ──▶ make music ──▶ bed.mp3 ───┤
tape/*.tape    ──▶ make tape ──▶ tape/*.mp4 ─┼─▶ make render ──▶ build/promo-60s.mp4
sfx/manifest   ──▶ make sfx  ──▶ sfx/*.wav ──┤                          │
remotion/src/  ────────────────────────────────┘                         ▼
                                                              make master ──▶ -14 LUFS, color-graded
                                                                        │
                                                                        ▼
                                                              make caption ──▶ build/captions.srt
                                                                        │
                                                                        ▼
                                                              make deliver ──▶ 9:16, 1:1 reframes
```

Every step is idempotent. Re-running `make` only rebuilds dirty targets.

## Re-rendering one beat

```sh
make tape/03-scan       # rebuilds just that terminal capture
make render             # remotion picks up the new mp4
```

## Captions

```sh
make caption            # whisper.cpp transcribes vo/full.mp3 → SRT
                        # Remotion burns captions into the 9:16 + 1:1 cuts
```

## Deliverables

- `build/promo-60s.mp4` — 16:9 1080p master, -14 LUFS
- `build/promo-60s-9x16.mp4` — vertical (TikTok / Reels / Shorts)
- `build/promo-60s-1x1.mp4` — square (LinkedIn, X feed)
- `build/promo-60s.srt` — captions
- `build/promo-60s-poster.png` — first-frame thumbnail

## Human-action gates

Two beads tagged `human` block public posting:
1. API keys (one-time): `HEYGEN_API_KEY` (+ optional `HEYGEN_AVATAR_ID`), `SUNO_API_KEY` in `.env`
2. Final approval: review `build/promo-60s.mp4` and merge the production PR before publishing

Everything else is owned by the agent pipeline.

## Provenance

Every artifact's source is a tracked file. To audit how a frame was made:
1. Find the beat in `remotion/src/beats/*.tsx`
2. Find the terminal cast in `tape/*.tape` (if applicable)
3. Find the VO line in `audio/prompts/voiceover.json` matched by timestamp
4. Find the music section in `audio/prompts/music.txt` matched by bar number
