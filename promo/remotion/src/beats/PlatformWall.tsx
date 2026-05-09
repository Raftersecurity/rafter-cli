import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import type { Aspect } from "../Promo60";
import { theme } from "./theme";

// Beats 6–8 (0:18–0:30) — agent-velocity commit graph + platform wall.
// Each platform name lands on a 1.5s interval = 8 platforms over 12s.
// In production: replace each <PlatformCard/> with an actual screen-recorded MP4
// in remotion/public/platforms/<id>.mp4 and use OffthreadVideo.

const PLATFORMS = [
  { id: "claude-code", label: "Claude Code", color: "#d97757" },
  { id: "codex",       label: "Codex",       color: "#f5f5f5" },
  { id: "gemini",      label: "Gemini CLI",  color: "#4285f4" },
  { id: "cursor",      label: "Cursor",      color: "#d4d4d4" },
  { id: "windsurf",    label: "Windsurf",    color: "#00c4b4" },
  { id: "continue",    label: "Continue",    color: "#7c3aed" },
  { id: "aider",       label: "Aider",       color: "#10b981" },
  { id: "openclaw",    label: "OpenClaw",    color: "#e8662a" },
];

export const PlatformWall: React.FC<{ aspect: Aspect }> = ({ aspect }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const beatLen = fps * 1.5; // each platform card holds ~1.5s

  const activeIdx = Math.min(PLATFORMS.length - 1, Math.floor(frame / beatLen));
  const local = (frame % beatLen) / beatLen;
  const fadeIn = interpolate(local, [0, 0.2], [0, 1], { extrapolateRight: "clamp" });
  const fadeOut = interpolate(local, [0.8, 1.0], [1, 0], { extrapolateLeft: "clamp" });
  const cardOpacity = Math.min(fadeIn, fadeOut);

  const platform = PLATFORMS[activeIdx]!;
  const isVertical = aspect !== "16x9";

  return (
    <AbsoluteFill style={{
      backgroundColor: theme.bg, color: theme.text,
      alignItems: "center", justifyContent: "center",
      flexDirection: "column", gap: 40, fontFamily: theme.sans,
    }}>
      {/* Active platform card */}
      <div style={{
        opacity: cardOpacity,
        transform: `scale(${0.96 + cardOpacity * 0.04})`,
        backgroundColor: theme.bgPanel,
        border: `2px solid ${platform.color}`,
        borderRadius: 24,
        padding: isVertical ? "40px 60px" : "60px 100px",
        boxShadow: `0 30px 80px ${platform.color}33`,
      }}>
        <div style={{ fontSize: isVertical ? 64 : 96, fontWeight: 700, letterSpacing: -2, color: platform.color }}>
          {platform.label}
        </div>
        <div style={{ fontFamily: theme.mono, fontSize: 24, color: theme.textDim, marginTop: 16 }}>
          rafter agent init --with-{platform.id}
        </div>
      </div>

      {/* Counter */}
      <div style={{ fontFamily: theme.mono, fontSize: 22, color: theme.textDim, letterSpacing: 4 }}>
        {String(activeIdx + 1).padStart(2, "0")} / {PLATFORMS.length} PLATFORMS
      </div>

      {/* Lower line */}
      <div style={{ fontSize: isVertical ? 38 : 44, fontWeight: 600, marginTop: 20 }}>
        Same scan. Same contract.
      </div>
    </AbsoluteFill>
  );
};
