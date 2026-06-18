import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import {
  ConfigManager,
  redactConfigSecrets,
  maskSecretValue,
  isSecretConfigKey,
} from "../src/core/config-manager.js";
import { resolveKey } from "../src/utils/api.js";

// Hardening for sable-q9to: API key never stored world-readable, never echoed
// in cleartext, and backend.apiKey is an actual (lowest-precedence) cred source.

describe("config secret handling", () => {
  describe("redaction helpers", () => {
    it("masks credential-named keys, leaves the rest, never mutates input", () => {
      const cfg = {
        backend: { apiKey: "sk-secret-7777777" },
        agent: { riskLevel: "moderate" },
        token: "tok-abcdef",
        nested: { authToken: "zzzz9999", note: "plain" },
        list: [{ password: "hunter2xx" }],
      };
      const r = redactConfigSecrets(cfg) as any;
      expect(r.backend.apiKey).toBe("sk-s****");
      expect(r.token).toBe("tok-****");
      expect(r.nested.authToken).toBe("zzzz****");
      expect(r.nested.note).toBe("plain");
      expect(r.agent.riskLevel).toBe("moderate");
      expect(r.list[0].password).toBe("hunt****");
      // input untouched
      expect(cfg.backend.apiKey).toBe("sk-secret-7777777");
    });

    it("maskSecretValue handles short/empty/non-string", () => {
      expect(maskSecretValue("")).toBe("****");
      expect(maskSecretValue("abcd")).toBe("****");
      expect(maskSecretValue("abcde")).toBe("abcd****");
      expect(maskSecretValue(undefined)).toBe("****");
      expect(maskSecretValue(12345)).toBe("****");
    });

    it("isSecretConfigKey matches credential leaf names only", () => {
      for (const k of ["apiKey", "api_key", "apikey", "token", "authToken", "secret", "password", "credential"]) {
        expect(isSecretConfigKey(k)).toBe(true);
      }
      for (const k of ["riskLevel", "mode", "name", "url", "version"]) {
        expect(isSecretConfigKey(k)).toBe(false);
      }
    });
  });

  describe("save() writes the config 0600", () => {
    const p = path.join(os.tmpdir(), `rafter-perm-${Date.now()}-${process.pid}.json`);
    afterEach(() => { if (fs.existsSync(p)) fs.unlinkSync(p); });

    it("a freshly written config is owner-only", () => {
      new ConfigManager(p).set("backend.apiKey", "sk-xyz");
      expect(fs.statSync(p).mode & 0o777).toBe(0o600);
    });

    it("an existing world-readable config is tightened on next write", () => {
      fs.writeFileSync(p, "{}", { mode: 0o644 });
      fs.chmodSync(p, 0o644);
      new ConfigManager(p).set("agent.riskLevel", "minimal");
      expect(fs.statSync(p).mode & 0o777).toBe(0o600);
    });
  });

  describe("resolveKey precedence: --api-key > RAFTER_API_KEY > global config", () => {
    const origHome = process.env.HOME;
    const origKey = process.env.RAFTER_API_KEY;
    let home: string;

    beforeEach(() => {
      home = fs.mkdtempSync(path.join(os.tmpdir(), "rk-home-"));
      process.env.HOME = home;
      delete process.env.RAFTER_API_KEY;
      // Hand-write the config under the temp HOME — never via a default-path
      // ConfigManager, so the real ~/.rafter is never touched.
      const dir = path.join(home, ".rafter");
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify({ backend: { apiKey: "CONFIG-key" } }));
    });
    afterEach(() => {
      process.env.HOME = origHome;
      if (origKey) process.env.RAFTER_API_KEY = origKey; else delete process.env.RAFTER_API_KEY;
      fs.rmSync(home, { recursive: true, force: true });
    });

    it("flag wins over env and config", () => {
      process.env.RAFTER_API_KEY = "ENV-key";
      expect(resolveKey("FLAG-key")).toBe("FLAG-key");
    });

    it("env wins over config", () => {
      process.env.RAFTER_API_KEY = "ENV-key";
      expect(resolveKey(undefined)).toBe("ENV-key");
    });

    it("global config backend.apiKey is used when no flag/env (no longer a dead path)", () => {
      expect(resolveKey(undefined)).toBe("CONFIG-key");
    });
  });
});
