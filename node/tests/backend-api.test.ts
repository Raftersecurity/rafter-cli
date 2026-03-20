import { describe, it, expect, beforeAll } from "vitest";
import axios from "axios";
import { API } from "../src/utils/api.js";

/**
 * Backend API integration tests — run against the live Rafter API.
 *
 * These tests are SKIPPED unless RAFTER_API_KEY is set.
 * See bead rc-ap7 for setting up the key in GitHub CI.
 */

const API_KEY = process.env.RAFTER_API_KEY;
const describeWithKey = API_KEY ? describe : describe.skip;

describeWithKey("Backend API integration (live)", () => {
  const headers = { "x-api-key": API_KEY! };

  describe("POST /static/scan — trigger a scan", () => {
    let scanId: string;

    it("triggers a fast scan and returns a scan_id", async () => {
      const { data } = await axios.post(
        `${API}/static/scan`,
        {
          repository_name: "raftersecurity/rafter-cli",
          branch_name: "main",
          scan_mode: "fast",
        },
        { headers }
      );

      expect(data.scan_id).toBeDefined();
      expect(typeof data.scan_id).toBe("string");
      scanId = data.scan_id;
    }, 30000);

    it("GET /scan/:id returns scan status", async () => {
      if (!scanId) return;

      const { data } = await axios.get(`${API}/scan/${scanId}`, { headers });

      // Status should be one of the valid states
      expect(["queued", "running", "completed", "failed"]).toContain(
        data.status || data.scan_status
      );
    }, 30000);
  });

  describe("GET /scan/:id — nonexistent scan", () => {
    it("returns 404 for fake scan ID", async () => {
      try {
        await axios.get(`${API}/scan/nonexistent-fake-id-12345`, { headers });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.response.status).toBe(404);
      }
    });
  });

  describe("GET /usage — quota check", () => {
    it("returns usage stats", async () => {
      const { data } = await axios.get(`${API}/usage`, { headers });

      // Should have some usage-related fields
      expect(data).toBeDefined();
      expect(typeof data).toBe("object");
    });
  });

  describe("POST /static/scan — invalid key", () => {
    it("returns 401 or 403 for bad key", async () => {
      try {
        await axios.post(
          `${API}/static/scan`,
          {
            repository_name: "raftersecurity/rafter-cli",
            branch_name: "main",
            scan_mode: "fast",
          },
          { headers: { "x-api-key": "invalid-key-12345" } }
        );
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect([401, 403]).toContain(e.response.status);
      }
    });
  });

  describe("scan modes", () => {
    it("accepts plus scan mode", async () => {
      // This may hit quota, so just verify the request is accepted
      try {
        const { data } = await axios.post(
          `${API}/static/scan`,
          {
            repository_name: "raftersecurity/rafter-cli",
            branch_name: "main",
            scan_mode: "plus",
          },
          { headers }
        );
        expect(data.scan_id).toBeDefined();
      } catch (e: any) {
        // 403 with scan_mode body = quota reached, which is valid
        if (e.response?.status === 403 && e.response?.data?.scan_mode) {
          expect(e.response.data.scan_mode).toBe("plus");
          expect(e.response.data.limit).toBeDefined();
        } else {
          throw e;
        }
      }
    }, 30000);
  });
});

// ── Always-run tests (no API key required) ──────────────────────────

describe("Backend API — offline validation", () => {
  it("API base URL has trailing slash", () => {
    expect(API.endsWith("/")).toBe(true);
  });

  it("API base URL uses HTTPS", () => {
    expect(API.startsWith("https://")).toBe(true);
  });
});
