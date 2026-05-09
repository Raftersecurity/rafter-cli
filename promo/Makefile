# Rafter promo video — agent-only build
#
# Targets:
#   make video      = full pipeline → build/promo-60s.mp4 (16:9 master)
#   make deliver    = also produce 9:16 and 1:1 reframes + captions + poster
#   make tape       = rebuild all terminal captures
#   make vo         = rebuild voiceover from script
#   make music      = rebuild music bed
#   make caption    = transcribe VO into SRT
#   make clean      = wipe build/ and regenerable assets in remotion/public/

SHELL          := /bin/bash
ROOT           := $(abspath .)
BUILD          := $(ROOT)/build
PUBLIC         := $(ROOT)/remotion/public
TAPE_SRC       := $(wildcard tape/*.tape)
TAPE_MP4       := $(patsubst tape/%.tape,$(PUBLIC)/tape/%.mp4,$(TAPE_SRC))
VO_OUT         := $(PUBLIC)/vo/full.mp3
MUSIC_OUT      := $(PUBLIC)/music/bed.mp3
SFX_MANIFEST   := audio/sfx/manifest.json
SFX_OUT        := $(PUBLIC)/sfx/.fetched
LUT            := scripts/rafter-grade.cube
MASTER_16x9    := $(BUILD)/promo-60s.mp4
MASTER_9x16    := $(BUILD)/promo-60s-9x16.mp4
MASTER_1x1     := $(BUILD)/promo-60s-1x1.mp4
CAPTIONS       := $(BUILD)/promo-60s.srt
POSTER         := $(BUILD)/promo-60s-poster.png

include .env
export

.PHONY: video deliver tape vo music sfx render master caption reframe poster clean check-env

# ── Top-level ────────────────────────────────────────────────────
video: $(MASTER_16x9)

deliver: $(MASTER_16x9) $(MASTER_9x16) $(MASTER_1x1) $(CAPTIONS) $(POSTER)

# ── Asset stages ─────────────────────────────────────────────────
tape: $(TAPE_MP4)

$(PUBLIC)/tape/%.mp4: tape/%.tape
	@mkdir -p $(PUBLIC)/tape
	vhs $< -o $@

vo: $(VO_OUT)

$(VO_OUT): audio/prompts/voiceover.json scripts/render-vo.sh check-env
	@mkdir -p $(PUBLIC)/vo
	bash scripts/render-vo.sh $< $@

music: $(MUSIC_OUT)

$(MUSIC_OUT): audio/prompts/music.txt scripts/render-music.sh check-env
	@mkdir -p $(PUBLIC)/music
	bash scripts/render-music.sh $< $@

sfx: $(SFX_OUT)

$(SFX_OUT): $(SFX_MANIFEST) scripts/fetch-sfx.sh
	@mkdir -p $(PUBLIC)/sfx
	bash scripts/fetch-sfx.sh $< $(PUBLIC)/sfx
	@touch $@

# ── Render (Remotion → 16:9 raw) ─────────────────────────────────
render: $(BUILD)/promo-60s-raw.mp4

$(BUILD)/promo-60s-raw.mp4: $(TAPE_MP4) $(VO_OUT) $(MUSIC_OUT) $(SFX_OUT) $(wildcard remotion/src/**/*.tsx)
	@mkdir -p $(BUILD)
	cd remotion && npx remotion render Promo60-16x9 $@ \
		--codec=h264 --image-format=jpeg --concurrency=4 \
		--props='{"version":"$(shell git rev-parse --short HEAD)"}'

# ── Master (color grade + loudnorm to -14 LUFS) ──────────────────
$(MASTER_16x9): $(BUILD)/promo-60s-raw.mp4 $(LUT)
	ffmpeg -y -i $< \
		-vf "lut3d=$(LUT)" \
		-af "loudnorm=I=-14:TP=-1.5:LRA=11" \
		-c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p \
		-c:a aac -b:a 192k \
		-movflags +faststart \
		$@

# ── Reframes ─────────────────────────────────────────────────────
$(MASTER_9x16): $(TAPE_MP4) $(VO_OUT) $(MUSIC_OUT) $(SFX_OUT)
	cd remotion && npx remotion render Promo60-9x16 $@ --codec=h264

$(MASTER_1x1): $(TAPE_MP4) $(VO_OUT) $(MUSIC_OUT) $(SFX_OUT)
	cd remotion && npx remotion render Promo60-1x1 $@ --codec=h264

# ── Captions (whisper.cpp local) ─────────────────────────────────
caption: $(CAPTIONS)

$(CAPTIONS): $(VO_OUT)
	bash scripts/caption.sh $< $@

# ── Poster ───────────────────────────────────────────────────────
poster: $(POSTER)

$(POSTER): $(MASTER_16x9)
	ffmpeg -y -ss 00:00:13.5 -i $< -frames:v 1 -q:v 2 $@

# ── Misc ─────────────────────────────────────────────────────────
check-env:
	@: $${ELEVENLABS_API_KEY?ELEVENLABS_API_KEY missing — see .env.example}
	@: $${SUNO_API_KEY?SUNO_API_KEY missing — see .env.example}

clean:
	rm -rf $(BUILD) $(PUBLIC)/tape $(PUBLIC)/vo $(PUBLIC)/music $(PUBLIC)/sfx
