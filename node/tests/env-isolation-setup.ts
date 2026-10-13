/**
 * Session-wide test isolation from the real machine.
 *
 * Without this, a test that expects "no API key" instead reads the real
 * `~/.rafter/config.json` (if the developer running the suite has one) and
 * can send a REAL authenticated request to the live Rafter backend. Two
 * things make that possible, and this setup file closes both:
 *
 * 1. `getRafterDir`/`ConfigManager` resolve `os.homedir()` at call time, so
 *    any test that doesn't override HOME reads the real global config.
 * 2. The API base (`utils/api.ts`'s `resolveApiBase`) has no override in
 *    production, so even a correctly "no key" test can fall through to a
 *    real network call if something upstream of `resolveKey` goes wrong.
 *
 * Vitest runs this before a test file's own module graph is evaluated, so by
 * the time any source module (or the test file itself) reads `process.env`,
 * it already sees the isolated values below.
 *
 * Opt out with RAFTER_TEST_LIVE_API=1 to run against the real machine config
 * and the real backend (e.g. a deliberate live/manual run — this is also
 * what node/tests/backend-api.test.ts's own API-key gate needs to see a real
 * RAFTER_API_KEY). Leave it unset for every normal test run.
 */
import fs from "fs";
import os from "os";
import path from "path";

const LIVE_OPT_IN = process.env.RAFTER_TEST_LIVE_API === "1";

// Nothing should ever listen here, so an API call that escapes isolation
// fails fast (connection refused) instead of reaching the live backend.
const DEFAULT_CLOSED_PORT_URL = "http://127.0.0.1:1/api/";

// Preserved for tests (e.g. cross-runtime-parity) that must locate the real
// Python user site-packages dir, which depends on the real HOME, even though
// CLI invocations under test must see an isolated one.
if (!process.env.RAFTER_TEST_REAL_HOME) {
  process.env.RAFTER_TEST_REAL_HOME = os.homedir();
}

if (!LIVE_OPT_IN) {
  process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-test-home-"));

  const originalApiUrl = process.env.RAFTER_API_URL;
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("RAFTER_") && key !== "RAFTER_TEST_REAL_HOME") {
      delete process.env[key];
    }
  }
  // Re-apply the redirect. A pre-set RAFTER_API_URL (e.g. a proof run
  // pointing at a counting listener) is preserved rather than clobbered.
  process.env.RAFTER_API_URL = originalApiUrl || DEFAULT_CLOSED_PORT_URL;
}
