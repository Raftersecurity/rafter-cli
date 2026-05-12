// Test fixture: spins up a trove server against a synthetic HOME and
// returns the launch URL. Used both for ui.spec.ts and the screenshot
// iteration script.
//
// Strategy:
//   1. Build a tmp dir with subdirs: $HOME-equivalent (the fixture root)
//      and $XDG_CONFIG_HOME-equivalent (where trove writes its global.json).
//   2. Populate the fixture HOME with 4-6 files with mixed mode bits:
//        - a 0644 .env inside a git repo + a real-looking secret    (DANGER)
//        - a 0600 .envrc (clean)
//        - a 0644 .zshrc with one secret                            (WARN)
//        - a 0644 .bashrc with one secret                           (WARN)
//        - a 0600 ~/.aws/credentials (clean)
//        - a 0644 ~/.npmrc with a token                             (WARN)
//   3. Pre-populate trove/global.json so the first-run wizard is skipped
//      and the rescanner picks up the fixture roots on launch.
//   4. Spawn `trove --no-open --idle-timeout=10m`, parse stderr for the
//      "serving on http://..." line, return the URL.

import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

export interface TroveFixture {
  home: string;
  xdg: string;
  url: string;
  proc: ChildProcessWithoutNullStreams;
  stop: () => Promise<void>;
  envFilePath: string;
  envrcPath: string;
  zshrcPath: string;
  bashrcPath: string;
  awsCredsPath: string;
  npmrcPath: string;
}

export interface StartOpts {
  // When true, pre-populate global.json with synthetic secrets carrying
  // InGitRepo=true (and other flags) and DO NOT mutate any files after
  // launch — the rescanner only fires on fsnotify events, so a quiet
  // launch lets the synthetic flags survive. Useful for screenshots
  // and tests that exercise UI states the live scanner can't currently
  // produce (e.g. InGitRepo, AppearsInGitHistory).
  syntheticGitFlags?: boolean;
}

const TROVE_BIN = process.env.TROVE_BIN || "/tmp/trove";

export async function startTrove(opts: StartOpts = {}): Promise<TroveFixture> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "trove-pw-"));
  const home = path.join(root, "home");
  const xdg = path.join(root, "xdg");
  await fs.mkdir(home, { recursive: true });
  await fs.mkdir(xdg, { recursive: true });

  const codeRepo = path.join(home, "code", "myapp");
  await fs.mkdir(codeRepo, { recursive: true });
  await fs.mkdir(path.join(home, "code", "lib"), { recursive: true });
  await fs.mkdir(path.join(home, ".aws"), { recursive: true });

  // .env in a git repo (DANGER tile).
  // String halves are concatenated at runtime so GitHub's push-protection
  // secret scanner doesn't see a literal AWS/GitHub key pattern in source.
  // These are textbook fixtures, not real credentials.
  const envFilePath = path.join(codeRepo, ".env");
  const fakeAws    = "wJalrXUtnFEMI" + "/K7MDENG/" + "bPxRfiCYEX" + "AMPLEKEY";
  const fakeStripe = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc";
  const fakeGh     = "ghp_" + "a" + "B3xQQQQQQ" + "QQQQQQQQQQ" + "QQQQQQQQQQQ16hN";
  await fs.writeFile(envFilePath,
    "AWS_SECRET_ACCESS_KEY=" + fakeAws + "\n" +
    "STRIPE_SECRET_KEY="     + fakeStripe + "\n" +
    "GITHUB_TOKEN="          + fakeGh + "\n" +
    "DATABASE_URL=postgres://user:hunter2@db.example.com/app\n");
  await fs.chmod(envFilePath, 0o644);
  // make codeRepo a git repo so InGitRepo == true
  await fs.mkdir(path.join(codeRepo, ".git"), { recursive: true });
  await fs.writeFile(path.join(codeRepo, ".git", "HEAD"), "ref: refs/heads/main\n");
  await fs.writeFile(path.join(codeRepo, ".git", "config"),
    "[core]\n\trepositoryformatversion = 0\n");

  // .envrc clean (0600, no git).
  const envrcPath = path.join(home, "code", "lib", ".envrc");
  await fs.writeFile(envrcPath,
    "export OPENAI_API_KEY=" + "sk-" + "proj-fixture-clean-0600\n" +
    "export ANTHROPIC_API_KEY=" + "sk-" + "ant-fixture-clean-0600\n");
  await fs.chmod(envrcPath, 0o600);

  // .zshrc world-readable (WARN tile).
  const zshrcPath = path.join(home, ".zshrc");
  await fs.writeFile(zshrcPath,
    "export PATH=$PATH:/usr/local/bin\n" +
    "export HOMEBREW_GITHUB_API_TOKEN=" + "ghp_" + "zsh_fixture_token_aaaaaaaaaaaaaaa\n" +
    "alias gs='git status'\n");
  await fs.chmod(zshrcPath, 0o644);

  // .bashrc world-readable (WARN tile).
  const bashrcPath = path.join(home, ".bashrc");
  await fs.writeFile(bashrcPath,
    "export NPM_TOKEN=" + "npm_" + "bashrc_fixture_token_aaaaaaaaaaaaaaaaaa\n");
  await fs.chmod(bashrcPath, 0o644);

  // ~/.aws/credentials clean (0600).
  const awsCredsPath = path.join(home, ".aws", "credentials");
  await fs.writeFile(awsCredsPath,
    "[default]\n" +
    "aws_access_key_id = "     + "AK" + "IAIOSFODNN7" + "FIXTURE\n" +
    "aws_secret_access_key = " + "wJalrXUtnFEMI" + "/fixture/aws/secret/key/value\n");
  await fs.chmod(awsCredsPath, 0o600);

  // ~/.npmrc world-readable (WARN tile).
  const npmrcPath = path.join(home, ".npmrc");
  await fs.writeFile(npmrcPath,
    "//registry.npmjs.org/:_authToken=" + "npm_" + "npmrc_fixture_token_bbbbbbbbbbbbbbbb\n");
  await fs.chmod(npmrcPath, 0o644);

  // Pre-populate trove's global.json so the first-run wizard is skipped.
  // Roots include the fixture home — the scanner will discover the files
  // above on first rescan.
  const troveDir = path.join(xdg, "trove");
  await fs.mkdir(troveDir, { recursive: true });
  const globalJson: any = {
    version: 1,
    schema_compat: "1.x",
    scan_config: { roots: [home], excludes: [] },
    telemetry: { enabled: false },
    reveal_policy: "session",
    secrets: [],
  };
  if (opts.syntheticGitFlags) {
    // Hand-rolled secret carrying an InGitRepo=true FoundIn so the
    // dashboard tile "env in git + secrets" lights up red.
    const now = new Date().toISOString();
    globalJson.secrets = [
      {
        id: "fixture-aws-key",
        key_name: "AWS_SECRET_ACCESS_KEY",
        value_fingerprint: "fixture-aws-key",
        value_preview: "wJal*****EXAMPLEKEY",
        found_in: [
          {
            source_type: "envfile",
            path: envFilePath,
            line: 1,
            permissions: "0644",
            in_git_repo: true,
            in_gitignore: false,
            appears_in_git_history: true,
          },
        ],
        annotation: { source_url: "", owner: "", notes: "", rotate_url: "", tags: [], stale: false },
        first_seen: now,
        last_seen: now,
        value_history: [],
      },
      {
        id: "fixture-stripe-key",
        key_name: "STRIPE_SECRET_KEY",
        value_fingerprint: "fixture-stripe-key",
        value_preview: "sk_te****1zdp7dc",
        found_in: [
          {
            source_type: "envfile",
            path: envFilePath,
            line: 2,
            permissions: "0644",
            in_git_repo: true,
            in_gitignore: false,
          },
        ],
        annotation: { source_url: "", owner: "", notes: "", rotate_url: "", tags: [], stale: false },
        first_seen: now,
        last_seen: now,
        value_history: [],
      },
    ];
  }
  await fs.writeFile(path.join(troveDir, "global.json"),
    JSON.stringify(globalJson, null, 2));
  await fs.chmod(path.join(troveDir, "global.json"), 0o600);

  // Launch trove. --no-open keeps it headless; long idle-timeout so a
  // test session won't get reaped mid-screenshot.
  const proc = spawn(TROVE_BIN, ["--no-open", "--idle-timeout=10m"], {
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: xdg },
    stdio: ["ignore", "pipe", "pipe"],
  });

  // Capture the URL from stderr. The main loop logs:
  //   trove: serving on http://127.0.0.1:PORT/?token=HEX
  const url = await new Promise<string>((resolve, reject) => {
    let buf = "";
    const onErr = (chunk: Buffer) => {
      buf += chunk.toString();
      const m = buf.match(/serving on (https?:\S+)/);
      if (m) {
        proc.stderr.off("data", onErr);
        resolve(m[1]);
      }
    };
    proc.stderr.on("data", onErr);
    proc.once("exit", (code) => {
      reject(new Error(`trove exited before printing URL (code=${code}): ${buf}`));
    });
    setTimeout(() => reject(new Error(`trove launch timed out: ${buf}`)), 10_000);
  });

  // Trigger an initial scan so files are picked up before the page loads.
  // The watcher does this automatically once files change, but cold-start
  // we want results immediately. Easiest path: touch one of the files
  // to fire an fsnotify event.
  //
  // SKIP when syntheticGitFlags is set — the rescanner would clobber the
  // hand-rolled InGitRepo flags via Upsert (FoundIn[j] = u.Found). With
  // no mutation, the watcher stays quiet and our synthetic state is
  // exactly what the UI renders.
  await new Promise((r) => setTimeout(r, 250));
  if (!opts.syntheticGitFlags) {
    await fs.utimes(envFilePath, new Date(), new Date());
    // Give the rescanner a beat to debounce + scan.
    await new Promise((r) => setTimeout(r, 1500));
  }

  const stop = async () => {
    if (proc.exitCode === null) {
      proc.kill("SIGTERM");
      await new Promise((r) => proc.once("exit", r));
    }
    await fs.rm(root, { recursive: true, force: true }).catch(() => {});
  };

  return {
    home, xdg, url, proc, stop,
    envFilePath, envrcPath, zshrcPath, bashrcPath, awsCredsPath, npmrcPath,
  };
}
