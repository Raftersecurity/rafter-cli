import {
  apiUrl,
  resolveKey,
  writePayload,
  EXIT_SUCCESS,
  EXIT_GENERAL_ERROR,
  API_TIMEOUT_SHORT_MS,
  apiClient,
} from "../../utils/api.js";
import { describeSitesError } from "./errors.js";

/** Default `--timeout` for `sites create --wait` / `sites scan --wait`, in seconds. */
export const DEFAULT_WAIT_TIMEOUT_SECONDS = 900;

/** How often to poll the status route while waiting, in ms. */
const DEFAULT_POLL_INTERVAL_MS = 10_000;

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Clock and poll-interval overrides for tests. Production call sites omit
 * this entirely and get the real `setTimeout`/`Date.now`; a test passes a
 * zero (or near-zero) interval and a fake clock so `--wait` tests run in well
 * under a second instead of sleeping for real.
 */
export interface SitesWaitDeps {
  pollIntervalMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export interface SitesWaitOpts {
  apiKey?: string;
  format?: string;
  quiet?: boolean;
  timeoutSeconds: number;
}

/**
 * Poll `GET static/sites/:siteId` every `pollIntervalMs` until
 * `latest_run.status` is `"succeeded"` or `"failed"`, or until
 * `timeoutSeconds` elapses. Prints the final status payload the same way
 * `rafter sites get` does (`writePayload`) and returns the process exit code:
 * `0` on succeeded, `1` on failed, timeout, or a run-id mismatch.
 *
 * `startedRunId` guards against reporting the wrong run's outcome: if another
 * scan starts on the same site while we wait (its id will differ from
 * `startedRunId`), we stop and name both ids rather than printing that run's
 * status as if it were ours.
 */
export async function waitForSiteRun(
  siteId: string,
  startedRunId: string,
  opts: SitesWaitOpts,
  deps: SitesWaitDeps = {}
): Promise<number> {
  const pollIntervalMs = deps.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const sleep = deps.sleep ?? defaultSleep;
  const now = deps.now ?? Date.now;
  const key = resolveKey(opts.apiKey);
  const deadline = now() + opts.timeoutSeconds * 1000;

  for (;;) {
    let data: any;
    try {
      ({ data } = await apiClient.get(
        apiUrl(`static/sites/${encodeURIComponent(siteId)}`),
        { headers: { "x-api-key": key }, timeout: API_TIMEOUT_SHORT_MS }
      ));
    } catch (e: any) {
      const { message, exitCode } = describeSitesError(e);
      console.error(`Error: ${message}`);
      return exitCode;
    }

    const latestRun = data?.latest_run;

    if (latestRun && latestRun.id !== startedRunId) {
      console.error(
        `Error: another run (${latestRun.id}) started on site ${siteId} while waiting ` +
        `for run ${startedRunId} to finish — not reporting its status. ` +
        `Run 'rafter sites get ${siteId}' to see the current state.`
      );
      return EXIT_GENERAL_ERROR;
    }

    if (latestRun && (latestRun.status === "succeeded" || latestRun.status === "failed")) {
      writePayload(data, opts.format, opts.quiet);
      return latestRun.status === "succeeded" ? EXIT_SUCCESS : EXIT_GENERAL_ERROR;
    }

    if (now() >= deadline) {
      console.error(
        `Error: timed out after ${opts.timeoutSeconds}s waiting for run ${startedRunId} ` +
        `on site ${siteId} to finish. Resume with 'rafter sites get ${siteId}'.`
      );
      return EXIT_GENERAL_ERROR;
    }

    await sleep(pollIntervalMs);
  }
}

/** Parse and validate `--timeout <seconds>`. Returns an error message on a bad value, else the parsed seconds. */
export function parseWaitTimeout(raw: string | number | undefined): { seconds: number; error?: string } {
  if (raw === undefined) return { seconds: DEFAULT_WAIT_TIMEOUT_SECONDS };
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return { seconds: DEFAULT_WAIT_TIMEOUT_SECONDS, error: "Error: --timeout must be a positive number of seconds" };
  }
  return { seconds: parsed };
}
