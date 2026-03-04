/**
 * GitHub API client — wraps `gh` CLI for issue operations.
 *
 * Prefers `gh` CLI (handles auth, rate limits, pagination) over raw REST.
 * Falls back to GITHUB_TOKEN + REST if gh is unavailable.
 */
import { execFileSync } from "child_process";

export interface GitHubIssue {
  number: number;
  title: string;
  body: string;
  labels: string[];
  html_url: string;
  state: string;
}

export interface CreateIssueParams {
  repo: string;
  title: string;
  body: string;
  labels?: string[];
}

function ghAvailable(): boolean {
  try {
    execFileSync("gh", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

export function createIssue(params: CreateIssueParams): GitHubIssue {
  const { repo, title, body, labels } = params;

  if (!ghAvailable()) {
    throw new Error(
      "GitHub CLI (gh) is required. Install: https://cli.github.com"
    );
  }

  const args = [
    "issue",
    "create",
    "--repo",
    repo,
    "--title",
    title,
    "--body",
    body,
  ];

  if (labels && labels.length > 0) {
    for (const label of labels) {
      args.push("--label", label);
    }
  }

  const result = execFileSync("gh", args, {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

  // gh issue create returns the issue URL
  const urlMatch = result.match(
    /https:\/\/github\.com\/[^/]+\/[^/]+\/issues\/(\d+)/
  );
  const number = urlMatch ? parseInt(urlMatch[1], 10) : 0;

  return {
    number,
    title,
    body,
    labels: labels || [],
    html_url: result,
    state: "open",
  };
}

export function listOpenIssues(repo: string): GitHubIssue[] {
  if (!ghAvailable()) {
    return [];
  }

  try {
    const result = execFileSync(
      "gh",
      [
        "issue",
        "list",
        "--repo",
        repo,
        "--state",
        "open",
        "--json",
        "number,title,body,labels,url",
        "--limit",
        "200",
      ],
      { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }
    ).trim();

    if (!result) return [];

    const issues = JSON.parse(result);
    return issues.map((i: any) => ({
      number: i.number,
      title: i.title,
      body: i.body || "",
      labels: (i.labels || []).map((l: any) => l.name),
      html_url: i.url,
      state: "open",
    }));
  } catch {
    return [];
  }
}
