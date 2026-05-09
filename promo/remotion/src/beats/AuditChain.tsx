import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import type { Aspect } from "../Promo60";
import { theme } from "./theme";

// Beat 12 (0:42–0:46) — audit log scrolls; chain hashes link entries; final "chain ok ✓".

const ENTRIES = [
  { event: "secret_detected",     file: ".env:1",          rule: "aws-access-key-id" },
  { event: "command_intercepted", file: "—",               rule: "git push --force"   },
  { event: "scan_executed",       file: "src/api/auth.ts", rule: "21 patterns"        },
  { event: "policy_override",     file: "—",               rule: "approve-dangerous"  },
  { event: "secret_detected",     file: "config.yml:14",   rule: "stripe-secret-key"  },
  { event: "content_sanitized",   file: "logs/run.jsonl",  rule: "redact"             },
  { event: "config_changed",      file: ".rafter.yml",     rule: "risk_level"         },
];

export const AuditChain: React.FC<{ aspect: Aspect }> = ({ aspect }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const isVertical = aspect !== "16x9";

  const verifiedAt = fps * 3.0; // "chain ok ✓" lands 3s in
  const verifiedOpacity = interpolate(frame, [verifiedAt, verifiedAt + fps * 0.3], [0, 1], { extrapolateRight: "clamp" });

  return (
    <AbsoluteFill style={{
      backgroundColor: theme.bg, fontFamily: theme.mono, color: theme.text,
      padding: isVertical ? 40 : 80, justifyContent: "center",
    }}>
      <div style={{ fontSize: 22, color: theme.textDim, marginBottom: 24 }}>
        ~/.rafter/audit.jsonl
      </div>
      {ENTRIES.map((e, i) => {
        const appearAt = (i + 1) * fps * 0.25;
        const opacity = interpolate(frame, [appearAt, appearAt + fps * 0.2], [0, 1], { extrapolateRight: "clamp" });
        const hash = `${(0xdeadbeef + i * 0x1f3a5).toString(16).padStart(8, "0")}…`;
        return (
          <div key={i} style={{
            opacity, fontSize: isVertical ? 22 : 26, lineHeight: 1.6,
            display: "grid", gridTemplateColumns: "auto 1fr 1fr 1fr",
            gap: 24, alignItems: "center",
          }}>
            <span style={{ color: theme.textDim }}>prevHash:{hash}</span>
            <span style={{ color: theme.accentTeal }}>{e.event}</span>
            <span>{e.file}</span>
            <span style={{ color: theme.textDim }}>{e.rule}</span>
          </div>
        );
      })}
      <div style={{
        opacity: verifiedOpacity,
        marginTop: 40, fontSize: isVertical ? 36 : 44, fontWeight: 600,
        color: theme.rafterGreen, fontFamily: theme.sans,
      }}>
        chain ok ✓
      </div>
    </AbsoluteFill>
  );
};
