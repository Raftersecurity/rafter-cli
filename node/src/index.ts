#!/usr/bin/env node
import { Command } from "commander";
import axios from "axios";
import ora from "ora";
import * as dotenv from "dotenv";
import { writeFileSync } from "fs";
import { resolve } from "path";
import { execSync } from "child_process";

dotenv.config();
const program = new Command();
const API = "https://rafter.so/api/";

function resolveKey(cliKey?: string): string {
  if (cliKey) return cliKey;
  if (process.env.RAFTER_API_KEY) return process.env.RAFTER_API_KEY;
  console.error("No API key provided. Use --api-key or set RAFTER_API_KEY");
  process.exit(1);
}

function saveResult(data: any, path?: string, name?: string, fmt?: string) {
  const ext = fmt === "md" ? "md" : "json";
  const file = name || `rafter_static_${Date.now()}`;
  const outPath = resolve(path || ".", `${file}.${ext}`);
  if (fmt === "md" && data.markdown) {
    writeFileSync(outPath, data.markdown);
  } else {
    writeFileSync(outPath, JSON.stringify(data, null, 2));
  }
  console.log(`Saved to ${outPath}`);
}

function git(cmd: string): string {
  return execSync(`git ${cmd}`, { stdio: ["ignore", "pipe", "ignore"] })
    .toString()
    .trim();
}

function safeBranch(gitFn: (c: string) => string) {
  try {
    return gitFn("symbolic-ref --quiet --short HEAD");
  } catch {
    return gitFn("rev-parse --short HEAD");
  }
}

function parseRemote(url: string): string {
  url = url.replace(/^(https?:\/\/|git@)/, "").replace(":", "/");
  if (url.endsWith(".git")) url = url.slice(0, -4);
  const parts = url.split("/");
  return parts.slice(-2).join("/"); // owner/repo
}

function detectRepo(opts: { repo?: string; branch?: string }) {
  if (opts.repo && opts.branch) return opts;
  const repoEnv = process.env.GITHUB_REPOSITORY || process.env.CI_REPOSITORY;
  const branchEnv = process.env.GITHUB_REF_NAME || process.env.CI_COMMIT_BRANCH || process.env.CI_BRANCH;
  let repoSlug = opts.repo || repoEnv;
  let branch = opts.branch || branchEnv;
  try {
    if (!repoSlug || !branch) {
      if (git("rev-parse --is-inside-work-tree") !== "true")
        throw new Error("not a repo");
      if (!repoSlug) repoSlug = parseRemote(git("remote get-url origin"));
      if (!branch) {
        try {
          branch = safeBranch(git);
        } catch {
          branch = "main";
        }
      }
    }
    if (!opts.repo || !opts.branch) {
      console.log(`\u{1F50D}  Repo auto-detected: ${repoSlug} @ ${branch}`);
    }
    return { repo: repoSlug, branch };
  } catch {
    throw new Error(
      "Could not auto-detect Git repository. Please pass --repo and --branch explicitly."
    );
  }
}

async function handleScanStatus(scan_id: string, headers: any, fmt: string, savePath?: string, saveName?: string) {
  // First poll
  let poll = await axios.get(
    `${API}/static/scan`,
    { params: { scan_id, format: fmt }, headers }
  );
  let status = poll.data.status;
  if (["queued", "pending", "processing"].includes(status)) {
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
        saveResult(poll.data, fmt, savePath, saveName);
        return;
      } else if (status === "failed") {
        spinner.fail("Scan failed");
        process.exit(1);
      }
    }
    console.log(`Scan status: ${status}`);
  } else if (status === "completed") {
    console.log("Scan completed");
    saveResult(poll.data, fmt, savePath, saveName);
    return;
  } else if (status === "failed") {
    console.log("Scan failed");
    process.exit(1);
  } else {
    console.log(`Scan status: ${status}`);
  }
}

program
  .name("rafter")
  .description("Rafter CLI");

program
  .command("run")
  .option("-r, --repo <repo>", "org/repo (default: current)")
  .option("-b, --branch <branch>", "branch (default: current else main)")
  .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
  .option("-f, --format <format>", "json | md", "json")
  .option("--skip-interactive", "do not wait for scan to complete")
  .option("--save-path <path>", "save file to path (default: current directory)")
  .option("--save-name <name>", "filename override (default: rafter_static_<timestamp>)")
  .action(async (opts) => {
    const key = resolveKey(opts.apiKey);
    let repo, branch;
    try {
      ({ repo, branch } = detectRepo({ repo: opts.repo, branch: opts.branch }));
    } catch (e) {
      if (e instanceof Error) {
        console.error(e.message);
      } else {
        console.error(e);
      }
      process.exit(1);
    }
    const spinner = ora("Submitting scan").start();
    try {
      const { data } = await axios.post(
        `${API}/static/scan`,
        { repository_name: repo, branch_name: branch },
        { headers: { "x-api-key": key } }
      );
      spinner.succeed(`Scan ID: ${data.scan_id}`);
      if (opts.skipInteractive) return;
      await handleScanStatus(data.scan_id, { "x-api-key": key }, opts.format, opts.savePath, opts.saveName);
    } catch (e) {
      spinner.fail("Request failed");
      if (e && typeof e === "object" && "response" in e && e.response && typeof e.response === "object" && "data" in e.response) {
        // Likely an AxiosError
        // @ts-ignore
        console.error(e.response.data);
      } else if (e instanceof Error) {
        console.error(e.message);
      } else {
        console.error(e);
      }
      process.exit(1);
    }
  });

program
  .command("get")
  .argument("<scan_id>")
  .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
  .option("-f, --format <format>", "json | md", "json")
  .option("--interactive", "poll until done")
  .option("--save-path <path>", "save file to path (default: current directory)")
  .option("--save-name <name>", "filename override (default: rafter_static_<timestamp>)")
  .action(async (scan_id, opts) => {
    const key = resolveKey(opts.apiKey);
    if (!opts.interactive) {
      const { data } = await axios.get(
        `${API}/static/scan`,
        { params: { scan_id, format: opts.format }, headers: { "x-api-key": key } }
      );
      saveResult(data, opts.format, opts.savePath, opts.saveName);
      return;
    }
    await handleScanStatus(scan_id, { "x-api-key": key }, opts.format, opts.savePath, opts.saveName);
  });

program
  .command("usage")
  .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
  .action(async (opts) => {
    const key = resolveKey(opts.apiKey);
    try {
      const { data } = await axios.get(`${API}/static/usage`, { headers: { "x-api-key": key } });
      console.log(JSON.stringify(data, null, 2));
    } catch (e: any) {
      if (e.response) {
        console.error(e.response.data);
      } else {
        console.error(e.message);
      }
      process.exit(1);
    }
  });

program.parse(); 