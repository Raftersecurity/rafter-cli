export const API = "https://rafter.so/api/";

// Exit codes
export const EXIT_SUCCESS = 0;
export const EXIT_GENERAL_ERROR = 1;
export const EXIT_SCAN_NOT_FOUND = 2;
export const EXIT_QUOTA_EXHAUSTED = 3;
export const EXIT_INSUFFICIENT_SCOPE = 4;

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
  console.error("No API key provided. Use --api-key or set RAFTER_API_KEY");
  process.exit(EXIT_GENERAL_ERROR);
}

export function writePayload(data: any, fmt?: string, quiet?: boolean): number {
  const payload = fmt === "md" && data.markdown ? data.markdown : JSON.stringify(data, null, quiet ? 0 : 2);

  // Stream to stdout for pipelines
  process.stdout.write(payload);
  return EXIT_SUCCESS;
}
