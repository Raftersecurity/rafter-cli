"""GitHub API client — wraps `gh` CLI for issue operations."""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class GitHubIssue:
    number: int
    title: str
    body: str
    labels: list[str] = field(default_factory=list)
    html_url: str = ""
    state: str = "open"


def _gh_available() -> bool:
    return shutil.which("gh") is not None


def create_issue(
    repo: str,
    title: str,
    body: str,
    labels: list[str] | None = None,
) -> GitHubIssue:
    """Create a GitHub issue via gh CLI."""
    if not _gh_available():
        raise RuntimeError(
            "GitHub CLI (gh) is required. Install: https://cli.github.com"
        )

    args = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body]
    if labels:
        for label in labels:
            args.extend(["--label", label])

    result = subprocess.run(
        args, capture_output=True, text=True, check=True
    )
    url = result.stdout.strip()

    # Extract issue number from URL
    number = 0
    import re
    m = re.search(r"/issues/(\d+)", url)
    if m:
        number = int(m.group(1))

    return GitHubIssue(
        number=number,
        title=title,
        body=body,
        labels=labels or [],
        html_url=url,
        state="open",
    )


def list_open_issues(repo: str) -> list[GitHubIssue]:
    """List open issues in a repo via gh CLI."""
    if not _gh_available():
        return []

    try:
        result = subprocess.run(
            [
                "gh", "issue", "list",
                "--repo", repo,
                "--state", "open",
                "--json", "number,title,body,labels,url",
                "--limit", "200",
            ],
            capture_output=True, text=True, check=True,
        )
        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        return [
            GitHubIssue(
                number=i["number"],
                title=i["title"],
                body=i.get("body", ""),
                labels=[l["name"] for l in (i.get("labels") or [])],
                html_url=i.get("url", ""),
                state="open",
            )
            for i in data
        ]
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return []
