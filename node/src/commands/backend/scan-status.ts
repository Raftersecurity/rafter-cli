import axios from "axios";
import ora from "ora";
import {
  API,
  writePayload,
  EXIT_GENERAL_ERROR,
  EXIT_SCAN_NOT_FOUND
} from "../../utils/api.js";

export async function handleScanStatus(scan_id: string, headers: any, fmt: string, quiet?: boolean): Promise<number> {
  // First poll
  let poll;
  try {
    poll = await axios.get(
      `${API}/static/scan`,
      { params: { scan_id, format: fmt }, headers }
    );
  } catch (e: any) {
    if (e.response?.status === 404) {
      console.error(`Scan '${scan_id}' not found`);
      return EXIT_SCAN_NOT_FOUND;
    }
    console.error(`Error: ${e.response?.data || e.message}`);
    return EXIT_GENERAL_ERROR;
  }

  let status = poll.data.status;
  if (["queued", "pending", "processing"].includes(status)) {
    if (!quiet) {
      const spinner = ora("Waiting for scan to complete... (this could take several minutes)").start();
      while (["queued", "pending", "processing"].includes(status)) {
        await new Promise((r) => setTimeout(r, 10000));
        poll = await axios.get(
          `${API}/static/scan`,
          { params: { scan_id, format: fmt }, headers }
        );
        status = poll.data.status;
        if (status === "completed") {
          spinner.succeed("Scan completed");
          return writePayload(poll.data, fmt, quiet);
        } else if (status === "failed") {
          spinner.fail("Scan failed");
          return EXIT_GENERAL_ERROR;
        }
      }
      console.error(`Scan status: ${status}`);
    } else {
      while (["queued", "pending", "processing"].includes(status)) {
        await new Promise((r) => setTimeout(r, 10000));
        poll = await axios.get(
          `${API}/static/scan`,
          { params: { scan_id, format: fmt }, headers }
        );
        status = poll.data.status;
        if (status === "completed") {
          return writePayload(poll.data, fmt, quiet);
        } else if (status === "failed") {
          return EXIT_GENERAL_ERROR;
        }
      }
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
