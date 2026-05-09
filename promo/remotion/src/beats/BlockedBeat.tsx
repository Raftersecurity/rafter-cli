import { AbsoluteFill, OffthreadVideo, interpolate, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import type { Aspect } from "../Promo60";
import { theme } from "./theme";

// Beat 4 (0:09–0:13) — pre-commit hook blocks. Red bar slides across at 0:11.

export const BlockedBeat: React.FC<{ aspect: Aspect }> = ({ aspect }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Red bar enters at 1.5s into this beat (= 0:10.5 absolute).
  const barX = interpolate(
    frame, [fps * 1.5, fps * 2.2],
    [-100, 0],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
  );

  return (
    <AbsoluteFill style={{ backgroundColor: theme.bg }}>
      <OffthreadVideo
        src={staticFile("tape/04-blocked.mp4")}
        style={{ width: "100%", height: "100%", objectFit: aspect === "16x9" ? "contain" : "cover" }}
      />
      <div style={{
        position: "absolute", left: 0, right: 0,
        top: aspect === "9x16" ? "78%" : "72%",
        height: 14,
        background: `linear-gradient(90deg, ${theme.danger} 0%, #c1121f 100%)`,
        transform: `translateX(${barX}%)`,
        boxShadow: "0 0 30px rgba(255,59,48,0.6)",
      }} />
      <div style={{
        position: "absolute", left: 60, bottom: 60,
        fontFamily: theme.sans, fontSize: 32, fontWeight: 600, color: theme.text,
      }}>
        Pre-commit. Zero setup. Zero telemetry.
      </div>
    </AbsoluteFill>
  );
};
