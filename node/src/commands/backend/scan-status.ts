import ora from "ora";
import {
  API,
  API_TIMEOUT_SHORT_MS,
  writePayload,
  EXIT_GENERAL_ERROR,
  EXIT_SCAN_NOT_FOUND,
  apiClient,
  apiUrl} from "../../utils/api.js";
import { fmt as output } from "../../utils/formatter.js";

/**
 * sable-l10k — the report a scan writes is not durable the instant the scan
 * flips to completed, so a poll can legitimately hit a 5xx (commonly
 * "Failed to fetch report from storage: Object not found") on an otherwise
 * healthy scan. Retry those instead of failing the whole run; a scan that
 * would have succeeded 10 seconds later must not die on one bad read.
 *
 * 404 is transient only AFTER the scan is known to exist: once the first poll
 * has succeeded, a missing scan is read-after-write lag rather than a wrong id.
 * On the first poll a 404 is still fatal.
 */
export const MAX_TRANSIENT_POLL_FAILURES = 5;

/**
 * Total transient failures tolerated across one `handleScanStatus` call.
 *
 * The consecutive counter resets on every success, which is what we want — a
 * twenty-minute scan with one blip at minute 2 and another at minute 18 should
 * not die. But reset-on-success alone means a backend alternating 200/500
 * forever never exhausts the budget, and the CLI has no wall-clock deadline to
 * stop it. This is the backstop for that.
 */
export const MAX_TOTAL_TRANSIENT_POLL_FAILURES = 20;

/**
 * sable-96ex — a 429 during polling is ambiguous in this API: on scan SUBMIT it
 * means "you are out of credits" (exit 3), and on the poll endpoint it would
 * mean "you are going too fast". `Retry-After` is the disambiguator — a quota
 * rejection does not carry one, a rate limiter does — so a 429 is retried here
 * only when the server tells us how long to wait, and fails fast otherwise.
 *
 * Longest Retry-After we honor. A limiter is free to answer "come back in an
 * hour"; a CI job cannot sit there for it, and the failure budget still bounds
 * the total wait either way.
 */
export const MAX_RETRY_AFTER_MS = 60_000;

/**
 * `Retry-After` in milliseconds, or null when it is absent or unusable.
 *
 * Only the delay-seconds form is honored. The HTTP-date form is deliberately
 * not parsed: the composite action has to make the same decision in bash on
 * whatever `date` the runner ships, and a rule the three surfaces cannot state
 * identically is worse than a narrow one they can. An unparseable header is
 * treated as absent — which means fail fast, the conservative direction.
 */
export function retryAfterMs(e: any): number | null {
  const headers = e?.response?.headers;
  if (!headers) return null;
  let raw: unknown;
  if (typeof headers.get === "function") raw = headers.get("retry-after");
  if (raw === undefined || raw === null) {
    for (const k of Object.keys(headers)) {
      if (k.toLowerCase() === "retry-after") {
        raw = (headers as any)[k];
        break;
      }
    }
  }
  if (Array.isArray(raw)) raw = raw[0];
  if (raw === undefined || raw === null) return null;
  const text = String(raw).trim();
  if (!/^\d+$/.test(text)) return null;
  // A 400-digit header parses to Infinity; the clamp is what makes that safe.
  return Math.min(Number(text) * 1000, MAX_RETRY_AFTER_MS);
}

/** Longest single error detail we will echo back. Servers can be verbose. */
const MAX_ERROR_DETAIL_CHARS = 200;

/**
 * Transient = the request never got an answer, or got one the server itself
 * describes as temporary.
 *
 * `scanExists` gates 404: before the first successful poll a 404 means the
 * scan id is wrong, and retrying it just delays a clear answer.
 */
function isTransientPollError(e: any, scanExists: boolean): boolean {
  const status = e?.response?.status;
  if (status === undefined) {
    // Retry only errors that came from the HTTP layer. A TypeError thrown from
    // our own code also has no `response`, and must not be mistaken for a flaky
    // backend and retried five times.
    return Boolean(e?.isAxiosError || e?.request);
  }
  if (status === 404) return scanExists;
  // 429 is transient only when the server said when to come back. See
  // MAX_RETRY_AFTER_MS: without that header a 429 here is a quota rejection,
  // and retrying one for half a minute before failing anyway is worse than
  // failing now.
  if (status === 429) return retryAfterMs(e) !== null;
  return status >= 500 || status === 408;
}

function truncate(value: unknown): string {
  // A server is free to answer {"error": {"message": "..."}}. Coerce before
  // touching string methods — this used to throw, which turned a retryable
  // failure into an immediate crash with a nonsense message.
  const s = typeof value === "string" ? value : JSON.stringify(value) ?? String(value);
  const flat = s.replace(/[\r\n]+/g, " ").trim();
  return flat.length > MAX_ERROR_DETAIL_CHARS
    ? `${flat.slice(0, MAX_ERROR_DETAIL_CHARS)}…`
    : flat;
}

function describeHttpError(e: any): string {
  const status = e?.response?.status;
  const data = e?.response?.data;
  let detail: unknown = "";
  if (typeof data === "string") {
    detail = data;
  } else if (data && typeof data === "object") {
    detail = (data as any).error ?? data;
  } else if (e instanceof Error) {
    detail = e.message;
  }
  const detailText = truncate(detail);
  return status
    ? `HTTP ${status}${detailText ? ` — ${detailText}` : ""}`
    : detailText || String(e);
}

/**
 * The message a customer actually sees when the report never becomes readable.
 * Storage-layer wording ("Object not found") is kept as supporting detail, not
 * as the whole explanation, and the next action is spelled out.
 */
export function unreadableReportMessage(
  scan_id: string,
  lastError: string,
  attempts: number = MAX_TRANSIENT_POLL_FAILURES,
  reachedServer: boolean = true
): string {
  if (!reachedServer) {
    return (
      `Rafter could not reach the API after ${attempts} attempts.\n` +
      `Check your network and that https://rafter.so is reachable from here.\n` +
      `Your scan id is ${scan_id} — the scan may still be running.\n` +
      `Last error: ${lastError}`
    );
  }
  return (
    `Rafter could not read the report for scan ${scan_id} after ` +
    `${attempts} attempts.\n` +
    `The scan itself may have finished — retry with: rafter get ${scan_id}\n` +
    `or open the scan in your dashboard at https://rafter.so/dashboard\n` +
    `Last response from the server: ${lastError}`
  );
}

/**
 * The give-up message when polling was throttled rather than blocked on an
 * unreadable report. Telling a customer their report could not be read, when
 * what actually happened is that we were rate limited, points them at the
 * wrong thing — and at a `rafter get` that will be throttled too.
 */
export function rateLimitedMessage(
  scan_id: string,
  lastError: string,
  attempts: number = MAX_TRANSIENT_POLL_FAILURES
): string {
  return (
    `Rafter was rate limited by the API while polling scan ${scan_id} ` +
    `(${attempts} attempts).\n` +
    `The scan itself may still be running — retry with: rafter get ${scan_id}\n` +
    `or open the scan in your dashboard at https://rafter.so/dashboard\n` +
    `Last response from the server: ${lastError}`
  );
}

export const BASE_BACKOFF_MS = 2000;

/** 2s, 4s, 8s, 16s — the 5th failure gives up rather than sleeping again. */
export function backoffMs(consecutiveFailures: number): number {
  return BASE_BACKOFF_MS * 2 ** (consecutiveFailures - 1);
}

/**
 * Thrown when polling gives up after repeated transient failures. Carries the
 * customer-facing message so callers do not have to rebuild it.
 */
export class PollGaveUpError extends Error {}

/**
 * A failure budget shared across every poll in one `handleScanStatus` call.
 *
 * Counting per-request would let a backend that alternates 200/500 forever
 * reset the counter on each success and never exhaust it — the CLI has no
 * wall-clock deadline, so that loop would never end.
 */
class FailureBudget {
  consecutive = 0;
  total = 0;
  last = "";
  /** False once any failure carried no HTTP response at all. */
  lastReachedServer = true;
  /** True when the failure we gave up on was a throttled 429, not a bad read. */
  lastRateLimited = false;

  record(detail: string, reachedServer: boolean, rateLimited = false): number {
    this.consecutive += 1;
    this.total += 1;
    this.last = detail;
    this.lastReachedServer = reachedServer;
    this.lastRateLimited = rateLimited;
    return this.consecutive;
  }

  /** A success clears the consecutive run, but never refunds the total. */
  reset(): void {
    this.consecutive = 0;
  }

  get exhausted(): boolean {
    return (
      this.consecutive >= MAX_TRANSIENT_POLL_FAILURES ||
      this.total >= MAX_TOTAL_TRANSIENT_POLL_FAILURES
    );
  }
}

type RetryNotice = (
  attempt: number,
  waitMs: number,
  detail: string,
  rateLimited: boolean
) => void;

/**
 * Retries are printed to stderr, not just into the spinner: ora renders
 * nothing on a non-TTY, and CI is exactly where this diagnostic matters.
 */
function makeRetryNotice(quiet?: boolean): RetryNotice | undefined {
  if (quiet) return undefined;
  return (attempt, waitMs, detail, rateLimited) => {
    const what = rateLimited
      ? `Rate limited by the API (${detail})`
      : `Report not readable yet (${detail})`;
    console.error(
      `${what}; retrying in ${Math.round(waitMs / 1000)}s ` +
        `(${attempt}/${MAX_TRANSIENT_POLL_FAILURES})`
    );
  };
}

/**
 * One poll, with retry/backoff over transient failures.
 * Non-transient errors are rethrown for the caller to classify.
 */
async function pollUntilReadable(
  scan_id: string,
  headers: any,
  fmt: string,
  budget: FailureBudget,
  scanExists: boolean,
  onRetry?: RetryNotice
): Promise<any> {
  for (;;) {
    try {
      const res = await apiClient.get(apiUrl("static/scan"), {
        params: { scan_id, format: fmt },
        headers,
        // Without this a hung server stalls inside a single request, and the
        // retry loop can only notice between attempts.
        timeout: API_TIMEOUT_SHORT_MS,
      });
      budget.reset();
      return res;
    } catch (e: any) {
      if (!isTransientPollError(e, scanExists)) throw e;

      // Non-null only for a 429 that carried a usable Retry-After — the sole
      // reason such a 429 got past the classifier above.
      const retryAfter = e?.response?.status === 429 ? retryAfterMs(e) : null;
      const attempt = budget.record(
        describeHttpError(e),
        e?.response?.status !== undefined,
        retryAfter !== null
      );
      if (budget.exhausted) {
        throw new PollGaveUpError(
          budget.lastRateLimited
            ? rateLimitedMessage(scan_id, budget.last, budget.total)
            : unreadableReportMessage(
                scan_id,
                budget.last,
                budget.total,
                budget.lastReachedServer
              )
        );
      }

      // The server named the delay; obey it instead of our own schedule. It
      // still spends a failure from the budget, so an endlessly-throttling
      // API cannot keep the loop alive.
      const waitMs = retryAfter ?? backoffMs(attempt);
      onRetry?.(attempt, waitMs, budget.last, retryAfter !== null);
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
}

/**
 * A single scan fetch with the same retry budget the poll loop uses.
 *
 * `rafter get <id>` is what the give-up message tells customers to run, so it
 * must not be defeated by exactly the transient failure that produced the
 * message. A 404 here is still fatal — that is a wrong id, not lag.
 */
export async function fetchScanWithRetry(
  scan_id: string,
  headers: any,
  fmt: string,
  quiet?: boolean
): Promise<any> {
  const budget = new FailureBudget();
  return pollUntilReadable(
    scan_id,
    headers,
    fmt,
    budget,
    false,
    makeRetryNotice(quiet)
  );
}

const IN_PROGRESS = ["queued", "pending", "processing"];

export async function handleScanStatus(scan_id: string, headers: any, fmt: string, quiet?: boolean): Promise<number> {
  const budget = new FailureBudget();
  const onRetry = makeRetryNotice(quiet);

  // First poll. A 404 here really does mean "no such scan" — do not retry it.
  // Transient 5xx IS retried, so that the `rafter get <id>` this command
  // recommends on failure is not itself defeated by one bad read.
  let poll;
  try {
    poll = await pollUntilReadable(scan_id, headers, fmt, budget, false, onRetry);
  } catch (e: any) {
    if (e?.response?.status === 404) {
      console.error(output.error(`Scan '${scan_id}' not found`));
      return EXIT_SCAN_NOT_FOUND;
    }
    console.error(
      output.error(e instanceof PollGaveUpError ? e.message : describeHttpError(e))
    );
    return EXIT_GENERAL_ERROR;
  }

  let status = poll.data.status;
  if (IN_PROGRESS.includes(status)) {
    const spinner = quiet
      ? undefined
      : ora("Waiting for scan to complete... (this could take several minutes)").start();

    try {
      while (IN_PROGRESS.includes(status)) {
        await new Promise((r) => setTimeout(r, 10000));
        poll = await pollUntilReadable(scan_id, headers, fmt, budget, true, onRetry);
        status = poll.data.status;
        if (status === "completed") {
          spinner?.succeed("Scan completed");
          return writePayload(poll.data, fmt, quiet);
        } else if (status === "failed") {
          spinner?.fail("Scan failed");
          return EXIT_GENERAL_ERROR;
        }
      }
    } catch (e: any) {
      spinner?.fail("Could not retrieve scan report");
      console.error(
        output.error(e instanceof PollGaveUpError ? e.message : describeHttpError(e))
      );
      return EXIT_GENERAL_ERROR;
    }
    if (!quiet) {
      console.error(`Scan status: ${status}`);
    }
  } else if (status === "completed") {
    if (!quiet) {
      console.error("Scan completed");
    }
    return writePayload(poll.data, fmt, quiet);
  } else if (status === "failed") {
    console.error("Scan failed");
    return EXIT_GENERAL_ERROR;
  } else {
    if (!quiet) {
      console.error(`Scan status: ${status}`);
    }
  }

  return writePayload(poll.data, fmt, quiet);
}
