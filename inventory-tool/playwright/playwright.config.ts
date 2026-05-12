import { defineConfig, devices } from "@playwright/test";

// trove's Playwright suite doubles as the design-iteration harness.
// Screenshots are taken at 1280x800 so the docs/screenshots/*.png files
// look consistent regardless of host display size.

export default defineConfig({
  testDir: ".",
  timeout: 60_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,    // one trove process per test, keep them sequential
  reporter: [["list"]],
  use: {
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: true,
    headless: true,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 800 } },
    },
  ],
});
