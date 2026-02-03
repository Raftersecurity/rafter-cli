import { Command } from "commander";
import axios from "axios";
import {
  API,
  resolveKey,
  writePayload,
  EXIT_GENERAL_ERROR,
  EXIT_SCAN_NOT_FOUND
} from "../../utils/api.js";
import { handleScanStatus } from "./scan-status.js";

export function createGetCommand(): Command {
  return new Command("get")
    .argument("<scan_id>")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("--interactive", "poll until done")
    .option("--quiet", "suppress status messages")
    .action(async (scan_id, opts) => {
      const key = resolveKey(opts.apiKey);
      if (!opts.interactive) {
        try {
          const { data } = await axios.get(
            `${API}/static/scan`,
            { params: { scan_id, format: opts.format }, headers: { "x-api-key": key } }
          );
          const exitCode = writePayload(data, opts.format, opts.quiet);
          process.exit(exitCode);
        } catch (e: any) {
          if (e.response?.status === 404) {
            console.error(`Scan '${scan_id}' not found`);
            process.exit(EXIT_SCAN_NOT_FOUND);
          } else if (e.response?.data) {
            console.error(e.response.data);
          } else if (e instanceof Error) {
            console.error(e.message);
          } else {
            console.error(e);
          }
          process.exit(EXIT_GENERAL_ERROR);
        }
        return;
      }
      const exitCode = await handleScanStatus(scan_id, { "x-api-key": key }, opts.format, opts.quiet);
      process.exit(exitCode);
    });
}
