export const API = "https://rafter.so/api/";

// Exit codes
export const EXIT_SUCCESS = 0;
export const EXIT_GENERAL_ERROR = 1;
export const EXIT_SCAN_NOT_FOUND = 2;
export const EXIT_QUOTA_EXHAUSTED = 3;

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
