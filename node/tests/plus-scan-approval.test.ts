import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * sable-9ddf — the opt-in approval gate for paid Plus scans.
 *
 * Covers:
 * - plusApprovalGateEnabled: OR semantics across global config + project policy,
 *   the security-critical "policy can tighten but never loosen" property, and
 *   fail-open on a config/policy read error.
 * - confirmPlusScan: mode gating, the --yes / RAFTER_CONFIRM overrides, the TTY
 *   prompt path, and the non-interactive refusal (exit 5).
 * - runRemoteScan: the gate fires before the billable API call.
 */

// ── Mutable mock state (hoisted so the vi.mock factories can read it) ────
const state = vi.hoisted(() => ({
  globalFlag: undefined as boolean | undefined,
  policyFlag: undefined as boolean | undefined,
  configThrows: false,
  promptAnswer: false,
}));

vi.mock("../src/core/config-manager.js", () => ({
  ConfigManager: class {
    load() {
      if (state.configThrows) throw new Error("corrupt config");
      return { agent: { scan: { plusRequiresApproval: state.globalFlag } } };
    }
  },
}));

vi.mock("../src/core/policy-loader.js", () => ({
  loadPolicy: () =>
    state.policyFlag === undefined
      ? null
      : { scan: { plusRequiresApproval: state.policyFlag } },
}));

vi.mock("../src/utils/prompt.js", () => ({
  askYesNo: vi.fn(async () => state.promptAnswer),
}));

vi.mock("axios");
vi.mock("ora", () => ({
  default: () => ({
    start: vi.fn().mockReturnThis(),
    succeed: vi.fn().mockReturnThis(),
    fail: vi.fn().mockReturnThis(),
    stop: vi.fn().mockReturnThis(),
  }),
}));

import axios from "axios";
import {
  plusApprovalGateEnabled,
  confirmPlusScan,
  runRemoteScan,
} from "../src/commands/backend/run.js";
import { EXIT_CONFIRMATION_REQUIRED } from "../src/utils/api.js";

const mockedAxios = vi.mocked(axios, true);

function resetState() {
  state.globalFlag = undefined;
  state.policyFlag = undefined;
  state.configThrows = false;
  state.promptAnswer = false;
}

// ── plusApprovalGateEnabled ─────────────────────────────────────────────

describe("plusApprovalGateEnabled", () => {
  beforeEach(() => {
    resetState();
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());

  it("is off by default (neither source opts in)", () => {
    expect(plusApprovalGateEnabled()).toBe(false);
  });

  it("is on when only global config opts in", () => {
    state.globalFlag = true;
    expect(plusApprovalGateEnabled()).toBe(true);
  });

  it("is on when only project policy opts in", () => {
    state.policyFlag = true;
    expect(plusApprovalGateEnabled()).toBe(true);
  });

  it("SECURITY: project policy cannot loosen a global opt-in", () => {
    // Machine owner enabled it globally; a hostile repo sets it false.
    state.globalFlag = true;
    state.policyFlag = false;
    expect(plusApprovalGateEnabled()).toBe(true);
  });

  it("fails open (off) when the global config cannot be read", () => {
    state.configThrows = true;
    expect(plusApprovalGateEnabled()).toBe(false);
  });
});

// ── confirmPlusScan ─────────────────────────────────────────────────────

describe("confirmPlusScan", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  const origTTY = process.stdin.isTTY;
  const origConfirm = process.env.RAFTER_CONFIRM;

  beforeEach(() => {
    resetState();
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    delete process.env.RAFTER_CONFIRM;
    exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit");
    }) as any);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    (process.stdin as any).isTTY = origTTY;
    if (origConfirm === undefined) delete process.env.RAFTER_CONFIRM;
    else process.env.RAFTER_CONFIRM = origConfirm;
  });

  it("is a no-op for a fast scan even when the gate is on", async () => {
    state.globalFlag = true;
    await expect(confirmPlusScan({ mode: "fast" })).resolves.toBeUndefined();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("is a no-op for a plus scan when the gate is off", async () => {
    await expect(confirmPlusScan({ mode: "plus" })).resolves.toBeUndefined();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("proceeds when --yes is passed", async () => {
    state.globalFlag = true;
    await expect(confirmPlusScan({ mode: "plus", yes: true })).resolves.toBeUndefined();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("proceeds when RAFTER_CONFIRM=1", async () => {
    state.globalFlag = true;
    process.env.RAFTER_CONFIRM = "1";
    await expect(confirmPlusScan({ mode: "plus" })).resolves.toBeUndefined();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("refuses with exit 5 in a non-interactive context without confirmation", async () => {
    state.globalFlag = true;
    (process.stdin as any).isTTY = false;
    await expect(confirmPlusScan({ mode: "plus" })).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(EXIT_CONFIRMATION_REQUIRED);
  });

  it("proceeds when the interactive prompt is answered yes", async () => {
    state.globalFlag = true;
    state.promptAnswer = true;
    (process.stdin as any).isTTY = true;
    await expect(confirmPlusScan({ mode: "plus" })).resolves.toBeUndefined();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("refuses with exit 5 when the interactive prompt is answered no", async () => {
    state.globalFlag = true;
    state.promptAnswer = false;
    (process.stdin as any).isTTY = true;
    await expect(confirmPlusScan({ mode: "plus" })).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(EXIT_CONFIRMATION_REQUIRED);
  });
});

// ── runRemoteScan integration — gate fires before the API call ───────────

describe("runRemoteScan gate integration", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  const origTTY = process.stdin.isTTY;

  beforeEach(() => {
    resetState();
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit");
    }) as any);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    (process.stdin as any).isTTY = origTTY;
  });

  it("refuses a gated plus scan without ever calling the backend", async () => {
    state.globalFlag = true;
    (process.stdin as any).isTTY = false;
    await expect(
      runRemoteScan({
        apiKey: "test-key",
        repo: "owner/repo",
        branch: "main",
        mode: "plus",
        skipInteractive: true,
        quiet: true,
      })
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(EXIT_CONFIRMATION_REQUIRED);
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it("submits a gated plus scan when --yes confirms it", async () => {
    state.globalFlag = true;
    mockedAxios.post.mockResolvedValueOnce({ data: { scan_id: "scan-abc" } });

    await runRemoteScan({
      apiKey: "test-key",
      repo: "owner/repo",
      branch: "main",
      mode: "plus",
      yes: true,
      skipInteractive: true,
      quiet: true,
    });

    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ scan_mode: "plus" }),
      expect.any(Object)
    );
  });
});
