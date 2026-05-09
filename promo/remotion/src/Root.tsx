import { Composition } from "remotion";
import { Promo60 } from "./Promo60";

const FPS = 60;
const DURATION = 60 * FPS;

export const Root: React.FC = () => (
  <>
    <Composition
      id="Promo60-16x9"
      component={Promo60}
      durationInFrames={DURATION}
      fps={FPS}
      width={1920}
      height={1080}
      defaultProps={{ aspect: "16x9" as const, hostBookend: false }}
    />
    <Composition
      id="Promo60-9x16"
      component={Promo60}
      durationInFrames={DURATION}
      fps={FPS}
      width={1080}
      height={1920}
      defaultProps={{ aspect: "9x16" as const, hostBookend: false }}
    />
    <Composition
      id="Promo60-1x1"
      component={Promo60}
      durationInFrames={DURATION}
      fps={FPS}
      width={1080}
      height={1080}
      defaultProps={{ aspect: "1x1" as const, hostBookend: false }}
    />
  </>
);
