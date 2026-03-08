/**
 * rafter issues create from-text — create a GitHub issue from natural language.
 *
 * Input sources: stdin (pipe), --file, --text inline.
 * Parses natural text to extract title, description, labels, severity, affected files.
 * Works as a skill: /rafter-issue in Claude Code / OpenClaw.
 */
import { Command } from "commander";
import fs from "fs";
import { detectRepo } from "../../utils/git.js";
import { fmt } from "../../utils/formatter.js";
import { EXIT_GENERAL_ERROR } from "../../utils/api.js";
import { createIssue } from "./github-client.js";

export function createFromTextCommand(): Command {
  return new Command("from-text")
    .description(
      "Create a GitHub issue from natural language text (stdin, file, or inline)"
    )
    .option("-r, --repo <repo>", "Target GitHub repo (org/repo)")
    .option("-t, --text <text>", "Inline text to convert to an issue")
    .option("-f, --file <path>", "Read text from file")
    .option("--title <title>", "Override extracted title")
    .option("--labels <labels>", "Comma-separated labels to add")
    .option("--dry-run", "Show parsed issue without creating it")
    .option("--quiet", "Suppress status messages")
    .action(async (opts) => {
      try {
        await runFromText(opts);
      } catch (e: any) {
        console.error(fmt.error(e.message || String(e)));
        process.exit(EXIT_GENERAL_ERROR);
      }
    });
}

interface ParsedIssue {
  title: string;
  body: string;
  labels: string[];
}

async function runFromText(opts: {
  repo?: string;
  text?: string;
  file?: string;
  title?: string;
  labels?: string;
  dryRun?: boolean;
  quiet?: boolean;
}): Promise<void> {
  // Read input text
  const input = await readInput(opts);
  if (!input.trim()) {
    console.error(fmt.error("No input text provided. Use --text, --file, or pipe via stdin"));
    process.exit(EXIT_GENERAL_ERROR);
  }

  // Resolve target repo
  let repo: string;
  if (opts.repo) {
    repo = opts.repo;
  } else {
    const detected = detectRepo({});
    repo = detected.repo!;
  }

  // Parse the natural text into a structured issue
  const parsed = parseNaturalText(input);

  // Apply overrides
  if (opts.title) parsed.title = opts.title;
  if (opts.labels) {
    const extra = opts.labels.split(",").map((l) => l.trim()).filter(Boolean);
    parsed.labels.push(...extra);
  }

  if (!opts.quiet) {
    console.error(fmt.info(`Target repo: ${repo}`));
    console.error(fmt.info(`Title: ${parsed.title}`));
    if (parsed.labels.length) {
      console.error(fmt.info(`Labels: ${parsed.labels.join(", ")}`));
    }
  }

  if (opts.dryRun) {
    process.stdout.write(JSON.stringify(parsed, null, 2));
    return;
  }

  const issue = createIssue({
    repo,
    title: parsed.title,
    body: parsed.body,
    labels: parsed.labels,
  });

  if (!opts.quiet) {
    console.error(fmt.success(`Created: ${issue.html_url}`));
  }
  process.stdout.write(issue.html_url + "\n");
}

async function readInput(opts: {
  text?: string;
  file?: string;
}): Promise<string> {
  if (opts.text) return opts.text;
  if (opts.file) return fs.readFileSync(opts.file, "utf-8");

  // Read from stdin if available (piped input)
  if (!process.stdin.isTTY) {
    return new Promise<string>((resolve) => {
      let data = "";
      process.stdin.setEncoding("utf-8");
      process.stdin.on("data", (chunk) => (data += chunk));
      process.stdin.on("end", () => resolve(data));
    });
  }

  return "";
}

/**
 * Parse natural language text into a structured GitHub issue.
 *
 * Heuristics-based extraction:
 * - First line or sentence → title
 * - Severity keywords → labels
 * - File paths → mentioned in body
 * - Security keywords → security label
 */
function parseNaturalText(text: string): ParsedIssue {
  const lines = text.trim().split("\n");
  const labels: string[] = [];

  // Extract title: first non-empty line, cleaned up
  let title = "";
  let bodyStart = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line) {
      // Strip markdown headers
      title = line.replace(/^#+\s*/, "").trim();
      bodyStart = i + 1;
      break;
    }
  }

  if (!title) {
    title = "Security issue reported via Rafter CLI";
  }

  // Truncate long titles
  if (title.length > 120) {
    title = title.slice(0, 117) + "...";
  }

  // Build body from remaining text
  const bodyLines = lines.slice(bodyStart);
  let body = bodyLines.join("\n").trim();

  if (!body) {
    body = text.trim();
  }

  // Extract severity from text
  const textLower = text.toLowerCase();
  if (textLower.includes("critical") || textLower.includes("p0")) {
    labels.push("severity:critical");
  } else if (
    textLower.includes("high severity") ||
    textLower.includes("high risk") ||
    textLower.includes("p1")
  ) {
    labels.push("severity:high");
  } else if (textLower.includes("medium") || textLower.includes("p2")) {
    labels.push("severity:medium");
  } else if (textLower.includes("low") || textLower.includes("p3")) {
    labels.push("severity:low");
  }

  // Detect security-related content
  const securityKeywords = [
    "security",
    "vulnerability",
    "cve",
    "cwe",
    "owasp",
    "secret",
    "credential",
    "token",
    "password",
    "injection",
    "xss",
    "csrf",
    "ssrf",
    "exploit",
  ];
  if (securityKeywords.some((kw) => textLower.includes(kw))) {
    labels.push("security");
  }

  // Extract file paths mentioned in text
  const fileRefs = text.match(
    /(?:^|\s)([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,10})(?::(\d+))?/gm
  );
  if (fileRefs && fileRefs.length > 0) {
    const files = fileRefs
      .map((f) => f.trim())
      .filter((f) => f.includes("/") || f.includes("."));
    if (files.length > 0) {
      body += `\n\n### Referenced Files\n\n`;
      for (const f of files.slice(0, 10)) {
        body += `- \`${f}\`\n`;
      }
    }
  }

  body += `\n\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n`;

  return { title, body, labels: [...new Set(labels)] };
}
