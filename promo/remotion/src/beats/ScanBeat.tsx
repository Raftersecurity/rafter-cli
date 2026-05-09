import { AbsoluteFill, OffthreadVideo, staticFile } from "remotion";
import type { Aspect } from "../Promo60";
import { theme } from "./theme";

// Beat 3 (0:05–0:09) — the rafter agent scan, captured by VHS.
// Pure overlay role: terminal video fills the frame, lower-third names the tool.

export const ScanBeat: React.FC<{ aspect: Aspect }> = ({ aspect }) => {
  const isVertical = aspect !== "16x9";
  return (
    <AbsoluteFill style={{ backgroundColor: theme.bg }}>
      <OffthreadVideo
        src={staticFile("tape/03-scan.mp4")}
        style={{
          width: "100%", height: "100%",
          objectFit: isVertical ? "cover" : "contain",
        }}
      />
      <div style={{
        position: "absolute", left: 60, bottom: 60,
        fontFamily: theme.mono, fontSize: 22, color: theme.textDim,
        backgroundColor: "rgba(0,0,0,0.55)", padding: "10px 18px", borderRadius: 6,
      }}>
        rafter agent scan --staged
      </div>
    </AbsoluteFill>
  );
};
