#!/usr/bin/env node
import { Command } from "commander";
import axios from "axios";
import ora from "ora";
import * as dotenv from "dotenv";
import { execSync } from "child_process";

dotenv.config();
const program = new Command();
const API = "https://rafter.so/api/";

// Exit codes
const EXIT_SUCCESS = 0;
const EXIT_GENERAL_ERROR = 1;
const EXIT_SCAN_NOT_FOUND = 2;
const EXIT_QUOTA_EXHAUSTED = 3;

function resolveKey(cliKey?: string): string {
  if (cliKey) return cliKey;
  if (process.env.RAFTER_API_KEY) return process.env.RAFTER_API_KEY;
  console.error("No API key provided. Use --api-key or set RAFTER_API_KEY");
  process.exit(EXIT_GENERAL_ERROR);
}

function writePayload(data: any, fmt?: string, quiet?: boolean): number {
  const payload = fmt === "md" && data.markdown ? data.markdown : JSON.stringify(data, null, quiet ? 0 : 2);
  
  // Stream to stdout for pipelines
  process.stdout.write(payload);
  return EXIT_SUCCESS;
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

function detectRepo(opts: { repo?: string; branch?: string, quiet?: boolean }) {
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
    if ((!opts.repo || !opts.branch) && !opts.quiet) {
      console.error(`Repo auto-detected: ${repoSlug} @ ${branch} (note: scanning remote)`);
    }
    return { repo: repoSlug, branch };
  } catch {
    throw new Error(
      "Could not auto-detect Git repository. Please pass --repo and --branch explicitly."
    );
  }
}

async function handleScanStatus(scan_id: string, headers: any, fmt: string, quiet?: boolean): Promise<number> {
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
  .option("--quiet", "suppress status messages")
  .action(async (opts) => {
    const key = resolveKey(opts.apiKey);
    let repo, branch;
    try {
      ({ repo, branch } = detectRepo({ repo: opts.repo, branch: opts.branch, quiet: opts.quiet }));
    } catch (e) {
      if (e instanceof Error) {
        console.error(e.message);
      } else {
        console.error(e);
      }
      process.exit(EXIT_GENERAL_ERROR);
    }
    
    if (!opts.quiet) {
      const spinner = ora("Submitting scan").start();
      try {
        const { data } = await axios.post(
          `${API}/static/scan`,
          { repository_name: repo, branch_name: branch },
          { headers: { "x-api-key": key } }
        );
        spinner.succeed(`Scan ID: ${data.scan_id}`);
        if (opts.skipInteractive) return;
        const exitCode = await handleScanStatus(data.scan_id, { "x-api-key": key }, opts.format, opts.quiet);
        process.exit(exitCode);
      } catch (e: any) {
        spinner.fail("Request failed");
        if (e.response?.status === 429) {
          console.error("Quota exhausted");
          process.exit(EXIT_QUOTA_EXHAUSTED);
        } else if (e.response?.data) {
          console.error(e.response.data);
        } else if (e instanceof Error) {
          console.error(e.message);
        } else {
          console.error(e);
        }
        process.exit(EXIT_GENERAL_ERROR);
      }
    } else {
      try {
        const { data } = await axios.post(
          `${API}/static/scan`,
          { repository_name: repo, branch_name: branch },
          { headers: { "x-api-key": key } }
        );
        if (opts.skipInteractive) return;
        const exitCode = await handleScanStatus(data.scan_id, { "x-api-key": key }, opts.format, opts.quiet);
        process.exit(exitCode);
      } catch (e: any) {
        if (e.response?.status === 429) {
          process.exit(EXIT_QUOTA_EXHAUSTED);
        } else if (e.response?.data) {
          console.error(e.response.data);
        } else if (e instanceof Error) {
          console.error(e.message);
        } else {
          console.error(e);
        }
        process.exit(EXIT_GENERAL_ERROR);
      }
    }
  });

program
  .command("get")
  .argument("<scan_id>")
  .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
  .option("-f, --format <format>", "json | md", "json")
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

program
  .command("usage")
  .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
  .action(async (opts) => {
    const key = resolveKey(opts.apiKey);
    try {
      const { data } = await axios.get(`${API}/static/usage`, { headers: { "x-api-key": key } });
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

program.parse(); 