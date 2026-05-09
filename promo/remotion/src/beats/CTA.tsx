import { AbsoluteFill, OffthreadVideo, interpolate, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import type { Aspect } from "../Promo60";
import { theme } from "./theme";

// Beats 14–15 (0:50–1:00). 0:50–0:55 = "Become AI-first. Safely."  0:55–1:00 = CTA card.
//
// Optional HeyGen avatar bookend: when `hostBookend` is true and
// scripts/render-host.sh produced remotion/public/host/cta.webm, the second
// half (0:55–1:00) overlays the talking-head host. Default is the pure
// motion-graphic CTA. The flag is wired through Promo60 from inputProps
// passed at render time by the Makefile when HEYGEN_AVATAR_ID is set.

export const CTA: React.FC<{ aspect: Aspect; hostBookend?: boolean }> = ({ aspect, hostBookend = false }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // First half: payoff line, large.
  const lineOpacity = interpolate(frame, [0, fps * 0.6, fps * 4.5, fps * 5.0], [0, 1, 1, 0], { extrapolateRight: "clamp" });
  // Second half: brand + CTA card.
  const cardOpacity = interpolate(frame, [fps * 5.0, fps * 5.5], [0, 1], { extrapolateRight: "clamp" });
  const urlChars = Math.min("rafter.so".length, Math.max(0, Math.floor((frame / fps - 5.5) * 12)));

  return (
    <AbsoluteFill style={{
      backgroundColor: theme.bg, alignItems: "center", justifyContent: "center",
      flexDirection: "column", gap: 32, fontFamily: theme.sans, color: theme.text,
    }}>
      {/* Payoff */}
      <div style={{
        position: "absolute",
        opacity: lineOpacity,
        fontSize: aspect === "9x16" ? 90 : 120, fontWeight: 700, letterSpacing: -3, textAlign: "center",
      }}>
        Become AI-first.<br />
        <span style={{ color: theme.rafterGreen }}>Safely.</span>
      </div>

      {/* Optional HeyGen avatar bookend — overlays the CTA card when set up */}
      {hostBookend && (
        <AbsoluteFill style={{ opacity: cardOpacity }}>
          <OffthreadVideo
            src={staticFile("host/cta.webm")}
            style={{
              width: aspect === "9x16" ? "100%" : "55%",
              height: "100%",
              objectFit: "cover",
              position: "absolute",
              left: aspect === "9x16" ? 0 : "5%",
              top: 0,
            }}
          />
        </AbsoluteFill>
      )}

      {/* CTA card */}
      <div style={{ opacity: cardOpacity, textAlign: "center", display: "flex", flexDirection: "column", gap: 28 }}>
        <div style={{ fontSize: aspect === "9x16" ? 140 : 180, fontWeight: 700, letterSpacing: -4 }}>
          Rafter
        </div>
        <div style={{ fontFamily: theme.mono, fontSize: aspect === "9x16" ? 44 : 56, color: theme.rafterGreen }}>
          {"rafter.so".slice(0, urlChars)}
          <span style={{
            display: "inline-block", width: "0.55ch", height: "1em", marginLeft: 4,
            background: theme.rafterGreen, verticalAlign: "text-bottom",
            opacity: Math.floor(frame / 20) % 2 === 0 ? 1 : 0,
          }} />
        </div>
        <div style={{ fontFamily: theme.mono, fontSize: 24, color: theme.textDim, marginTop: 12 }}>
          npm i -g @rafter-security/cli
        </div>
        <div style={{ fontSize: 20, color: theme.textDim, marginTop: 16 }}>
          Free forever for individuals &amp; OSS.
        </div>
      </div>
    </AbsoluteFill>
  );
};
