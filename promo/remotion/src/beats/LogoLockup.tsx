import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import type { Aspect } from "../Promo60";
import { theme, easeOutExpo } from "./theme";

// Beat 5 (0:13–0:18) — brand reveal. Logo + tagline, sustains for 5s.

export const LogoLockup: React.FC<{ aspect: Aspect; subtitle: string }> = ({ aspect, subtitle }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const enter = easeOutExpo(Math.min(1, frame / (fps * 0.8)));
  const subOpacity = interpolate(frame, [fps * 0.6, fps * 1.2], [0, 1], { extrapolateRight: "clamp" });

  return (
    <AbsoluteFill style={{
      backgroundColor: theme.bg,
      alignItems: "center", justifyContent: "center",
      flexDirection: "column", gap: 32,
    }}>
      <div style={{
        fontFamily: theme.sans, fontSize: aspect === "9x16" ? 160 : 200, fontWeight: 700,
        color: theme.text, letterSpacing: -4,
        opacity: enter,
        transform: `translateY(${(1 - enter) * 30}px)`,
      }}>
        Rafter
      </div>
      <div style={{
        width: 180 * enter, height: 4,
        background: theme.rafterGreen,
      }} />
      <div style={{
        fontFamily: theme.sans, fontSize: aspect === "9x16" ? 36 : 32, fontWeight: 400,
        color: theme.textDim, opacity: subOpacity, maxWidth: 900, textAlign: "center",
      }}>
        {subtitle}
      </div>
    </AbsoluteFill>
  );
};
