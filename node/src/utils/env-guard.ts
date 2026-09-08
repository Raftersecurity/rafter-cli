/**
 * Security-control env vars must never be settable by a project `.env`.
 *
 * `dotenv.config()` runs at CLI startup (index.ts) and, with no path, loads
 * `$CWD/.env` — which, when rafter runs inside an agent hook on a cloned repo,
 * is a file IN THE UNTRUSTED REPOSITORY. dotenv does not override a variable
 * already present in the real environment, but it DOES introduce one that was
 * unset — so a repo shipping `RAFTER_DISABLE_HOOKS=1` (or any `RAFTER_DISABLE_*`
 * / `RAFTER_HOOK_*` value) could switch off the victim's command policy and
 * secret scanning. That defeats the control whose own contract (hook-control.ts)
 * says the disable signal is honored only from the machine owner's environment.
 *
 * This runs dotenv, then drops any `RAFTER_DISABLE_*` / `RAFTER_HOOK_*` variable
 * that was NOT already set in the real environment before dotenv ran. The
 * owner's real values are preserved untouched; legitimate `.env` keys that do
 * not match those prefixes (RAFTER_API_KEY, RAFTER_GITHUB_TOKEN, …) are
 * unaffected. rf-7dda / sable-nz4y sibling.
 */
const PROTECTED_PREFIX = /^RAFTER_(DISABLE_|HOOK_)/;

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
