import { AbsoluteFill, Audio, Sequence, staticFile } from "remotion";
import { ColdOpen } from "./beats/ColdOpen";
import { ScanBeat } from "./beats/ScanBeat";
import { BlockedBeat } from "./beats/BlockedBeat";
import { LogoLockup } from "./beats/LogoLockup";
import { PlatformWall } from "./beats/PlatformWall";
import { SkillReview } from "./beats/SkillReview";
import { AuditChain } from "./beats/AuditChain";
import { CTA } from "./beats/CTA";

const FPS = 60;
const sec = (s: number) => Math.round(s * FPS);

export type Aspect = "16x9" | "9x16" | "1x1";

export type Promo60Props = {
  aspect: Aspect;
  /** When true, the CTA beat overlays the HeyGen avatar bookend at remotion/public/host/cta.webm. */
  hostBookend?: boolean;
};

export const Promo60: React.FC<Promo60Props> = ({ aspect, hostBookend = false }) => {
  return (
    <AbsoluteFill style={{ backgroundColor: "#0a0a0a" }}>
      {/* ── Visual beats ─────────────────────────────────────── */}
      <Sequence from={sec(0)}    durationInFrames={sec(5)}>
        <ColdOpen aspect={aspect} />
      </Sequence>
      <Sequence from={sec(5)}    durationInFrames={sec(4)}>
        <ScanBeat aspect={aspect} />
      </Sequence>
      <Sequence from={sec(9)}    durationInFrames={sec(4)}>
        <BlockedBeat aspect={aspect} />
      </Sequence>
      <Sequence from={sec(13)}   durationInFrames={sec(5)}>
        <LogoLockup aspect={aspect} subtitle="The security primitive for AI-first dev." />
      </Sequence>
      <Sequence from={sec(18)}   durationInFrames={sec(12)}>
        <PlatformWall aspect={aspect} />
      </Sequence>
      <Sequence from={sec(30)}   durationInFrames={sec(4)}>
        <SkillReview aspect={aspect} />
      </Sequence>
      <Sequence from={sec(42)}   durationInFrames={sec(4)}>
        <AuditChain aspect={aspect} />
      </Sequence>
      <Sequence from={sec(50)}   durationInFrames={sec(10)}>
        <CTA aspect={aspect} hostBookend={hostBookend} />
      </Sequence>

      {/* ── Audio beds (assembled at master time, but previewable here) */}
      <Audio src={staticFile("vo/full.mp3")} volume={1.0} />
      <Audio src={staticFile("music/bed.mp3")} volume={0.35} />
    </AbsoluteFill>
  );
};
