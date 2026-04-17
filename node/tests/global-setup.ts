import { execSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");

export default function globalSetup() {
  execSync("pnpm run build", {
    cwd: PROJECT_ROOT,
    stdio: "ignore",
    timeout: 120_000,
  });
}
