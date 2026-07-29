import {
  EXIT_GENERAL_ERROR,
  EXIT_QUOTA_EXHAUSTED,
  EXIT_INSUFFICIENT_SCOPE,
  EXIT_SCAN_NOT_FOUND,
} from "../../utils/api.js";
import { ConfigManager } from "../../core/config-manager.js";

/**
 * Resolve the Rafter API key for a context with no CLI flag (e.g. an MCP tool
 * call). Same precedence as resolveKey() in utils/api.ts (env > stored config)
 * minus the --api-key flag, but returns undefined instead of calling
 * process.exit — killing the whole MCP server over one tool's missing key
 * would take every other tool down with it.
 */
export function resolveMcpApiKey(): string | undefined {
  if (process.env.RAFTER_API_KEY) return process.env.RAFTER_API_KEY;
  try {
    const stored = new ConfigManager().get("backend.apiKey");
    if (typeof stored === "string" && stored.trim()) return stored.trim();
  } catch {
    // Config unreadable — fall through.
  }
  return undefined;
}

/** Extract a human-readable message from a Sites API error response body. */
function errorBodyMessage(e: any): string {
  const body = e?.response?.data;
  if (typeof body === "string" && body.trim()) return body;
  if (body && typeof body === "object") {
    if (typeof body.error === "string" && body.error) return body.error;
    if (typeof body.message === "string" && body.message) return body.message;
  }
  // Deliberately no non-empty fallback here — an unconditional default (e.g.
  // "Unknown error") would make every `msg || "<status-specific default>"`
  // check in describeSitesError() below unreachable, since msg would never
  // be falsy. Let describeSitesError()'s own per-status defaults apply.
  return e?.message || "";
}

export interface SitesErrorResult {
  message: string;
  exitCode: number;
}

/**
 * The Sites API never returns a `markdown` field, so `--format md` has nothing
 * to render. Rather than silently falling back to JSON (which looks like
 * success but produces the wrong format), reject up front with a clear error.
 * Returns true (and prints the error) when `fmt` is unsupported.
 */
export function rejectUnsupportedFormat(fmt: string | undefined): boolean {
  if (fmt !== "md") return false;
  console.error("Error: Sites does not support --format md yet, use --format json");
  return true;
}

/**
 * Map a Sites API (/api/static/sites*) error to a CLI-friendly message + exit code.
 *
 * Unlike the remote-scan API (see handle403 in utils/api.ts, which infers "quota"
 * from a `scan_mode` field), the Sites API returns 403 for BOTH wrong API-key
 * scope and plan/site limits — the only signal is the free-text `error` string.
 * Never assume 403 == quota here. 404 means "not found or not owned by this
 * account" — the Sites API deliberately does not distinguish the two.
 */
export function describeSitesError(e: any): SitesErrorResult {
  const status = e?.response?.status;
  const msg = errorBodyMessage(e);

  switch (status) {
    case 400:
      return { message: `Bad request — ${msg}`, exitCode: EXIT_GENERAL_ERROR };
    case 401:
      return { message: `Unauthorized — ${msg || "invalid or missing API key"}`, exitCode: EXIT_GENERAL_ERROR };
    case 403:
      return { message: `Forbidden — ${msg || "access denied"}`, exitCode: EXIT_INSUFFICIENT_SCOPE };
    case 404:
      return { message: `Not found — ${msg || "site not found, or not owned by this account"}`, exitCode: EXIT_SCAN_NOT_FOUND };
    case 429:
      return { message: `Rate limited — ${msg || "too many requests, try again later"}`, exitCode: EXIT_QUOTA_EXHAUSTED };
    default:
      return { message: msg || "Request failed", exitCode: EXIT_GENERAL_ERROR };
  }
}
