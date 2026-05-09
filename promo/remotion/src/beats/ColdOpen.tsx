import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import type { Aspect } from "../Promo60";
import { theme, easeOutExpo } from "./theme";

// Beat 1+2 (0:00–0:05) — leaked AWS key reveals, then a charge notification slams in.
// Sound-off readable: text is large, the red flash is unmistakable.

export const ColdOpen: React.FC<{ aspect: Aspect }> = ({ aspect }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // 0–1.8s: type the key in
  const typedChars = Math.min(
    Math.max(0, Math.floor(((frame / fps) - 0.4) * 24)),
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".length,
  );
  const keyShown = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".slice(0, typedChars);

  // 1.8–2.4s: red flash on the key line
  const flashOpacity = interpolate(
    frame, [fps * 1.8, fps * 2.0, fps * 2.4],
    [0, 1, 0],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
  );

  // 3.0–3.6s: charge card slams in from the right
  const cardProgress = easeOutExpo(
    Math.max(0, Math.min(1, (frame / fps - 3.0) / 0.6)),
  );
  const cardX = (1 - cardProgress) * 600;
  const cardOpacity = cardProgress;

  const isVertical = aspect !== "16x9";
  const fontSize = isVertical ? 64 : 56;

  return (
    <AbsoluteFill style={{ backgroundColor: theme.bg, color: theme.text, fontFamily: theme.mono }}>
      {/* Editor surface */}
      <div style={{
        position: "absolute",
        inset: isVertical ? "20% 5%" : "20% 15%",
        backgroundColor: theme.bgPanel,
        border: `1px solid ${theme.bgPanel}`,
        borderRadius: 12,
        padding: 48,
        boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
      }}>
        <div style={{ color: theme.textDim, fontSize: 22, marginBottom: 24 }}>
          .env  ·  modified by claude-code
        </div>
        <div style={{ fontSize, lineHeight: 1.4, position: "relative" }}>
          <span style={{ color: theme.textDim }}>+ </span>
          <span>{keyShown}</span>
          <span style={{
            display: "inline-block", width: "0.55ch", height: "1em", marginLeft: 4,
            background: theme.text, verticalAlign: "text-bottom",
            opacity: Math.floor(frame / 20) % 2 === 0 ? 1 : 0,
          }} />
          {/* red flash overlay */}
          <div style={{
            position: "absolute", inset: -8,
            backgroundColor: theme.danger, opacity: flashOpacity * 0.35,
            mixBlendMode: "screen", borderRadius: 4,
          }} />
        </div>
      </div>

      {/* Charge notification */}
      <div style={{
        position: "absolute",
        top: isVertical ? "75%" : "70%",
        right: isVertical ? "5%" : "12%",
        transform: `translateX(${cardX}px)`,
        opacity: cardOpacity,
        backgroundColor: "#1c1c1e",
        border: `1px solid ${theme.danger}`,
        borderRadius: 16,
        padding: "20px 28px",
        minWidth: 420,
        fontFamily: theme.sans,
        boxShadow: "0 20px 60px rgba(255,59,48,0.25)",
      }}>
        <div style={{ color: theme.textDim, fontSize: 18, marginBottom: 6 }}>OpenAI</div>
        <div style={{ color: theme.text, fontSize: 28, fontWeight: 600 }}>
          $1,247.30 charged
        </div>
        <div style={{ color: theme.danger, fontSize: 16, marginTop: 8 }}>
          Unusual usage detected
        </div>
      </div>

      {/* On-screen line, last second */}
      {frame > fps * 4.0 && (
        <div style={{
          position: "absolute", bottom: 80, left: 0, right: 0,
          textAlign: "center", fontFamily: theme.sans, fontSize: 48, fontWeight: 600,
          color: theme.text, letterSpacing: -0.5,
          opacity: interpolate(frame, [fps * 4.0, fps * 4.3], [0, 1], { extrapolateRight: "clamp" }),
        }}>
          Your AI agent just leaked a key.
        </div>
      )}
    </AbsoluteFill>
  );
};
