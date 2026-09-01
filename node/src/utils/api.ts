import axios from "axios";
import { ConfigManager } from "../core/config-manager.js";

export const API = "https://rafter.so/api/";

/**
 * sable-2s6p — the HTTP client for every authenticated Rafter API call.
 *
 * `maxRedirects: 0` is the point of it. axios (via follow-redirects) replays
 * request headers on a redirect, and unlike `Authorization` the custom
 * `x-api-key` header is not stripped when the host changes. Since the API base
 * is user-settable (`--rafter-url`, self-hosted installs), a 302 from a
 * misconfigured or hostile endpoint would walk the caller's API key to another
 * host. Nothing in this CLI needs to follow a redirect, so none of them do.
 *
 * Use this for anything that sends `x-api-key`. Plain `axios` is fine for
 * user-supplied webhooks and other unauthenticated calls.
 */
export const apiClient = axios.create({
  maxRedirects: 0,
});

/**
 * A redirect target is attacker-controlled if the endpoint is. Header values
 * cannot contain CR/LF, but ESC is a legal byte, so an unsanitized Location can
 * emit ANSI sequences that rewrite the user's terminal. Strip anything
 * non-printable and cap the length.
 */
function safeForTerminal(value: unknown): string {
  if (typeof value !== "string") return "";
  // eslint-disable-next-line no-control-regex
  const printable = value.replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
  return printable.length > 200 ? `${printable.slice(0, 200)}…` : printable;
}

// A refused redirect otherwise surfaces as a bare "Request failed with status
// code 302", which tells the user nothing about why. Name the cause.
apiClient.interceptors.response.use(undefined, (error: any) => {
  const status = error?.response?.status;
  if (status >= 300 && status < 400) {
    const target = safeForTerminal(error?.response?.headers?.location) || "another host";
    error.message =
      `The Rafter API redirected to ${target}, and Rafter does not follow redirects ` +
      `on authenticated requests — your API key would be sent to the redirect target. ` +
      `If you are pointing Rafter at a self-hosted instance, use its final URL.`;
  }
  return Promise.reject(error);
});

/** Join API with a path segment without producing a double slash, regardless of leading/trailing slashes on either side. */
export function apiUrl(path: string): string {
  return `${API.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

// Exit codes
/**
 * Read timeout for short-lived API calls (status polls and the like), in ms.
 * Mirrors the read half of Python's `API_TIMEOUT_SHORT`.
 */
export const API_TIMEOUT_SHORT_MS = 30_000;

export const EXIT_SUCCESS = 0;
export const EXIT_GENERAL_ERROR = 1;
export const EXIT_SCAN_NOT_FOUND = 2;
export const EXIT_QUOTA_EXHAUSTED = 3;
export const EXIT_INSUFFICIENT_SCOPE = 4;
// sable-9ddf — a paid Plus scan was refused because approval is required and no
// explicit confirmation (--yes / RAFTER_CONFIRM=1 / interactive yes) was given.
export const EXIT_CONFIRMATION_REQUIRED = 5;

/**
 * Detect a 403 error from the API and print a helpful message.
 * Returns the appropriate exit code, or -1 if not a 403.
 */
export function handle403(e: any): number {
  if (!e || e.response?.status !== 403) return -1;
  const body = e.response?.data;
  if (typeof body === "object" && body?.scan_mode) {
    const mode = body.scan_mode;
    const limit = body.limit ?? "?";
    const used = body.used ?? limit;
    console.error(
      `Error: ${mode.charAt(0).toUpperCase() + mode.slice(1)} scan limit reached (${used}/${limit} used this billing period).\nUpgrade your plan or wait for your quota to reset.`
    );
    return EXIT_QUOTA_EXHAUSTED;
  }
  const msg = typeof body === "string" ? body : body?.error ?? "";
  if (msg.includes("scope")) {
    console.error(
      'Error: This API key only has read access.\nTo trigger scans, create a key with "Read & Scan" scope at https://rfrr.co/account'
    );
  } else {
    console.error(`Error: Forbidden (403) — ${msg || "access denied"}`);
  }
  return EXIT_INSUFFICIENT_SCOPE;
}

/** @deprecated Use handle403 instead */
export function handleScopeError(e: any): boolean {
  return handle403(e) >= 0;
}

export function resolveKey(cliKey?: string): string {
  if (cliKey) return cliKey;
  if (process.env.RAFTER_API_KEY) return process.env.RAFTER_API_KEY;
  // Lowest precedence: a key persisted in the GLOBAL ~/.rafter/config.json via
  // `rafter agent config set backend.apiKey`. Read through load() (global only)
  // — loadWithPolicy() never merges backend.*, so a project-local .rafter.yml
  // can NOT inject a key that would redirect scans to another account.
  try {
    const stored = new ConfigManager().get("backend.apiKey");
    if (typeof stored === "string" && stored.trim()) return stored.trim();
  } catch {
    // Config unreadable — fall through to the error below.
  }
  console.error("No API key provided. Use --api-key, set RAFTER_API_KEY, or run 'rafter agent config set backend.apiKey <key>'");
  process.exit(EXIT_GENERAL_ERROR);
}

export function writePayload(data: any, fmt?: string, quiet?: boolean): number {
  const payload = fmt === "md" && data.markdown ? data.markdown : JSON.stringify(data, null, quiet ? 0 : 2);

  // Stream to stdout for pipelines
  process.stdout.write(payload);
  return EXIT_SUCCESS;
}
