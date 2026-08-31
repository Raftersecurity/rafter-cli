import axios from "axios";
import ora from "ora";
import {
  API,
  API_TIMEOUT_SHORT_MS,
  writePayload,
  EXIT_GENERAL_ERROR,
  EXIT_SCAN_NOT_FOUND
} from "../../utils/api.js";
import { fmt as output } from "../../utils/formatter.js";

/**
 * sable-l10k — the report a scan writes is not durable the instant the scan
 * flips to completed, so a poll can legitimately hit a 5xx (commonly
 * "Failed to fetch report from storage: Object not found") on an otherwise
 * healthy scan. Retry those instead of failing the whole run; a scan that
 * would have succeeded 10 seconds later must not die on one bad read.
 *
 * 404 is transient HERE and only here: by the time the poll loop runs we have
 * already been handed a scan_id, so a missing scan mid-poll is read-after-write
 * lag, not a wrong id. The FIRST poll still treats 404 as fatal.
 */
export const MAX_TRANSIENT_POLL_FAILURES = 5;

function isTransientPollError(e: any): boolean {
  const status = e?.response?.status;
  // No response at all: transport error (DNS, reset, timeout).
  if (status === undefined) return true;
  return status >= 500 || status === 408 || status === 404;
}

function describeHttpError(e: any): string {
  const status = e?.response?.status;
  const data = e?.response?.data;
  let detail = "";
  if (typeof data === "string") {
    detail = data;
  } else if (data && typeof data === "object") {
    detail = (data as any).error ?? JSON.stringify(data);
  } else if (e instanceof Error) {
    detail = e.message;
  }
  return status ? `HTTP ${status}${detail ? ` — ${detail}` : ""}` : detail || String(e);
}

/**
 * The message a customer actually sees when the report never becomes readable.
 * Storage-layer wording ("Object not found") is kept as supporting detail, not
 * as the whole explanation, and the next action is spelled out.
 */
export function unreadableReportMessage(scan_id: string, lastError: string): string {
  return (
    `Rafter could not read the report for scan ${scan_id} after ` +
    `${MAX_TRANSIENT_POLL_FAILURES} attempts.\n` +
    `The scan itself may have finished — retry with: rafter get ${scan_id}\n` +
    `or open the scan in your dashboard at https://rafter.so/dashboard\n` +
    `Last response from the server: ${lastError}`
  );
}

const BASE_BACKOFF_MS = 2000;

function backoffMs(consecutiveFailures: number): number {
  // 2s, 4s, 8s, 16s, 32s
  return BASE_BACKOFF_MS * 2 ** (consecutiveFailures - 1);
}

/**
 * Thrown when polling gives up after repeated transient failures. Carries the
 * customer-facing message so callers do not have to rebuild it.
 */
export class PollGaveUpError extends Error {}

/**
 * One poll, with retry/backoff over transient failures.
 * Non-transient errors are rethrown for the caller to classify.
 */
async function pollUntilReadable(
  scan_id: string,
  headers: any,
  fmt: string,
  onRetry?: (attempt: number, waitMs: number, detail: string) => void
): Promise<any> {
  let consecutiveFailures = 0;
  let lastError = "";

  for (;;) {
    try {
      return await axios.get(`${API}/static/scan`, {
        params: { scan_id, format: fmt },
        headers,
        // Without this a hung server stalls inside a single request, and the
        // retry loop can only notice between attempts.
        timeout: API_TIMEOUT_SHORT_MS,
      });
    } catch (e: any) {
      if (!isTransientPollError(e)) throw e;

      consecutiveFailures += 1;
      lastError = describeHttpError(e);

      if (consecutiveFailures >= MAX_TRANSIENT_POLL_FAILURES) {
        throw new PollGaveUpError(unreadableReportMessage(scan_id, lastError));
      }

      const waitMs = backoffMs(consecutiveFailures);
      onRetry?.(consecutiveFailures, waitMs, lastError);
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
}

const IN_PROGRESS = ["queued", "pending", "processing"];

export async function handleScanStatus(scan_id: string, headers: any, fmt: string, quiet?: boolean): Promise<number> {
  // First poll. A 404 here really does mean "no such scan" — do not retry it.
  let poll;
  try {
    poll = await axios.get(
      `${API}/static/scan`,
      { params: { scan_id, format: fmt }, headers }
    );
  } catch (e: any) {
    if (e.response?.status === 404) {
      console.error(output.error(`Scan '${scan_id}' not found`));
      return EXIT_SCAN_NOT_FOUND;
    }
    console.error(output.error(`${e.response?.data || e.message}`));
    return EXIT_GENERAL_ERROR;
  }

  let status = poll.data.status;
  if (IN_PROGRESS.includes(status)) {
    const spinner = quiet
      ? undefined
      : ora("Waiting for scan to complete... (this could take several minutes)").start();
    const onRetry = quiet
      ? undefined
      : (attempt: number, waitMs: number, detail: string) => {
          spinner!.text =
            `Report not readable yet (${detail}); retrying in ${Math.round(waitMs / 1000)}s ` +
            `(${attempt}/${MAX_TRANSIENT_POLL_FAILURES})`;
        };

    try {
      while (IN_PROGRESS.includes(status)) {
        await new Promise((r) => setTimeout(r, 10000));
        poll = await pollUntilReadable(scan_id, headers, fmt, onRetry);
        status = poll.data.status;
        if (status === "completed") {
          spinner?.succeed("Scan completed");
          return writePayload(poll.data, fmt, quiet);
        } else if (status === "failed") {
          spinner?.fail("Scan failed");
          return EXIT_GENERAL_ERROR;
        }
        if (spinner) {
          spinner.text = "Waiting for scan to complete... (this could take several minutes)";
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
