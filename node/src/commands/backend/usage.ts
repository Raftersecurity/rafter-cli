import { Command } from "commander";
import { API, resolveKey, EXIT_GENERAL_ERROR, apiClient, apiUrl} from "../../utils/api.js";

export function createUsageCommand(): Command {
  return new Command("usage")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .action(async (opts) => {
      const key = resolveKey(opts.apiKey);
      try {
        const { data } = await apiClient.get(apiUrl("static/usage"), { headers: { "x-api-key": key } });
        console.log(JSON.stringify(data, null, 2));
      } catch (e: any) {
        if (e.response?.data) {
          console.error(e.response.data);
        } else {
          console.error(e.message);
        }
        process.exit(EXIT_GENERAL_ERROR);
      }
    });
}
