import { AbsoluteFill, OffthreadVideo, staticFile } from "remotion";
import type { Aspect } from "../Promo60";
import { theme } from "./theme";

// Beat 9 (0:30–0:34) — skill review overlay over the captured terminal.

export const SkillReview: React.FC<{ aspect: Aspect }> = ({ aspect }) => {
  return (
    <AbsoluteFill style={{ backgroundColor: theme.bg }}>
      <OffthreadVideo
        src={staticFile("tape/09-skill-review.mp4")}
        style={{ width: "100%", height: "100%", objectFit: aspect === "16x9" ? "contain" : "cover" }}
      />
      <div style={{
        position: "absolute", left: 0, right: 0, bottom: 80,
        textAlign: "center", fontFamily: theme.sans, fontSize: 40, fontWeight: 600, color: theme.text,
        textShadow: "0 2px 12px rgba(0,0,0,0.8)",
      }}>
        Treat third-party skills as hostile by default.
      </div>
    </AbsoluteFill>
  );
};
