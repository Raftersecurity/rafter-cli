/**
 * A project `.env` must never supply a rafter setting.
 *
 * `dotenv.config()` runs at CLI startup (index.ts) and, with no path, loads
 * `$CWD/.env` — which, when rafter runs inside an agent hook or a scan on a
 * cloned repo, is a file IN THE UNTRUSTED REPOSITORY. dotenv does not override
 * a variable already present in the real environment, but it DOES introduce one
 * that was unset. Every `RAFTER_*` variable is an operator setting: the disable
 * switches and hook timeouts, but also the API key (which outranks the key the
 * operator stored in ~/.rafter/config.json), the GitHub token, the notify
 * webhook and the paid-scan confirmation. None of them may come from the repo
 * being scanned.
 *
 * This runs dotenv, then drops any `RAFTER_*` variable that was NOT already set
 * in the real environment before dotenv ran. The owner's real values are
 * preserved untouched. This matches the Python runtime, which never reads the
 * working directory's `.env`.
 */
const PROTECTED_PREFIX = /^RAFTER_/;

export function guardSecurityEnvFromDotenv(
  applyDotenv: () => void,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const present = new Set<string>();
  for (const k of Object.keys(env)) {
    if (PROTECTED_PREFIX.test(k)) present.add(k);
  }
  applyDotenv();
  for (const k of Object.keys(env)) {
    if (PROTECTED_PREFIX.test(k) && !present.has(k)) {
      delete env[k];
    }
  }
}
