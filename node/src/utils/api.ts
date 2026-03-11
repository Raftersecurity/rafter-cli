export const API = "https://rafter.so/api/";

// Exit codes
export const EXIT_SUCCESS = 0;
export const EXIT_GENERAL_ERROR = 1;
export const EXIT_SCAN_NOT_FOUND = 2;
export const EXIT_QUOTA_EXHAUSTED = 3;
export const EXIT_INSUFFICIENT_SCOPE = 4;

/**
 * Detect a 403 scope-enforcement error from the API and print a helpful message.
 * Returns true if the error was a scope error (caller should exit), false otherwise.
 */
export function handleScopeError(e: any): boolean {
  if (!e || e.response?.status !== 403) return false;
  const body = e.response?.data;
  const msg = typeof body === "string" ? body : body?.error ?? "";
  if (msg.includes("scope")) {
    console.error(
      'Error: This API key only has read access.\nTo trigger scans, create a key with "Read & Scan" scope at https://rfrr.co/account'
    );
  } else {
    console.error(`Error: Forbidden (403) — ${msg || "access denied"}`);
  }
  return true;
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
