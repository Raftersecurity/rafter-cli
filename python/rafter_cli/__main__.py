import typer
import requests
import time
import os
import json
import pathlib
import subprocess
import re
import sys
from dotenv import load_dotenv
from rich import print, progress

app = typer.Typer()
API_BASE = "https://rafter.so/api"

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_SCAN_NOT_FOUND = 2
EXIT_QUOTA_EXHAUSTED = 3

class GitInfo:
    def __init__(self):
        self.inside_repo = self._run(["git", "rev-parse", "--is-inside-work-tree"]) == "true"
        if not self.inside_repo:
            raise RuntimeError("Not inside a Git repository")
        self.root = pathlib.Path(self._run(["git", "rev-parse", "--show-toplevel"]))
        self.branch = self._detect_branch()
        self.repo_slug = self._parse_remote(self._run(["git", "remote", "get-url", "origin"]))

    def _run(self, cmd):
        return subprocess.check_output(cmd, text=True).strip()

    def _detect_branch(self):
        try:
            return self._run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"])
        except subprocess.CalledProcessError:
            try:
                return self._run(["git", "rev-parse", "--short", "HEAD"])
            except subprocess.CalledProcessError:
                return "main"

    def _parse_remote(self, url: str) -> str:
        url = re.sub(r"^(https?://|git@)", "", url)
        url = url.replace(":", "/")
        url = url[:-4] if url.endswith(".git") else url
        return "/".join(url.split("/")[-2:])

def resolve_key(cli_opt):
    if cli_opt:
        return cli_opt
    load_dotenv()
    env_key = os.getenv("RAFTER_API_KEY")
    if env_key:
        return env_key
    print("No API key provided. Use --api-key or set RAFTER_API_KEY", file=sys.stderr)
    raise typer.Exit(code=EXIT_GENERAL_ERROR)

def resolve_repo_branch(repo_opt, branch_opt, quiet):
    if repo_opt and branch_opt:
        return repo_opt, branch_opt
    repo_env = os.getenv("GITHUB_REPOSITORY") or os.getenv("CI_REPOSITORY")
    branch_env = os.getenv("GITHUB_REF_NAME") or os.getenv("CI_COMMIT_BRANCH") or os.getenv("CI_BRANCH")
    repo = repo_opt or repo_env
    branch = branch_opt or branch_env
    try:
        if not repo or not branch:
            git = GitInfo()
            if not repo:
                repo = git.repo_slug
            if not branch:
                branch = git.branch
        if not repo_opt or not branch_opt:
            if not quiet: 
                print(f"Repo auto-detected: {repo} @ {branch} (note: scanning remote)", file=sys.stderr)
        return repo, branch
    except Exception:
        print("Could not auto-detect Git repository. Please pass --repo and --branch explicitly.", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

def write_payload(data, fmt="json", quiet=False):
    """Write payload to stdout following UNIX principles"""
    if fmt == "md":
        payload = data.get("markdown", "")
    else:
        payload = json.dumps(data, indent=2 if not quiet else None)
    
    # Stream to stdout for pipelines
    sys.stdout.write(payload)
    return EXIT_SUCCESS

def handle_scan_status_interactive(scan_id, headers, fmt, quiet):
    # First poll
    poll = requests.get(f"{API_BASE}/static/scan", headers=headers, params={"scan_id": scan_id, "format": fmt})
    
    if poll.status_code == 404:
        print(f"Scan '{scan_id}' not found", file=sys.stderr)
        raise typer.Exit(code=EXIT_SCAN_NOT_FOUND)
    elif poll.status_code != 200:
        print(f"Error: {poll.text}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    
    data = poll.json()
    status = data.get("status")
    
    if status in ("queued", "pending", "processing"):
        if not quiet:
            print("Waiting for scan to complete... (this could take several minutes)", file=sys.stderr)
        while status in ("queued", "pending", "processing"):
            time.sleep(10)
            poll = requests.get(f"{API_BASE}/static/scan", headers=headers, params={"scan_id": scan_id, "format": fmt})
            data = poll.json()
            status = data.get("status")
            if status == "completed":
                if not quiet:
                    print("Scan completed!", file=sys.stderr)
                return write_payload(data, fmt, quiet)
            elif status == "failed":
                print("Scan failed.", file=sys.stderr)
                raise typer.Exit(code=EXIT_GENERAL_ERROR)
        if not quiet:
            print(f"Scan status: {status}", file=sys.stderr)
    elif status == "completed":
        if not quiet:
            print("Scan completed!", file=sys.stderr)
        return write_payload(data, fmt, quiet)
    elif status == "failed":
        print("Scan failed.", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    else:
        if not quiet:
            print(f"Scan status: {status}", file=sys.stderr)
    
    return write_payload(data, fmt, quiet)

@app.command()
def run(
    repo: str = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: str = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key or RAFTER_API_KEY env var"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    key = resolve_key(api_key)
    repo, branch = resolve_repo_branch(repo, branch, quiet)
    headers = {"x-api-key": key, "Content-Type": "application/json"}
    
    resp = requests.post(f"{API_BASE}/static/scan", headers=headers, json={"repository_name": repo, "branch_name": branch})
    
    if resp.status_code == 429:
        print("Quota exhausted", file=sys.stderr)
        raise typer.Exit(code=EXIT_QUOTA_EXHAUSTED)
    elif resp.status_code != 200:
        print(f"Error: {resp.text}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    
    scan_id = resp.json()["scan_id"]
    if not quiet:
        print(f"Scan ID: {scan_id}", file=sys.stderr)
    
    if skip_interactive:
        return
    
    handle_scan_status_interactive(scan_id, headers, fmt, quiet)

@app.command()
def get(
    scan_id: str = typer.Argument(...),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key or RAFTER_API_KEY env var"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    interactive: bool = typer.Option(False, "--interactive", help="poll until done"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
):
    key = resolve_key(api_key)
    headers = {"x-api-key": key}
    
    if not interactive:
        resp = requests.get(f"{API_BASE}/static/scan", headers=headers, params={"scan_id": scan_id, "format": fmt})
        
        if resp.status_code == 404:
            print(f"Scan '{scan_id}' not found", file=sys.stderr)
            raise typer.Exit(code=EXIT_SCAN_NOT_FOUND)
        elif resp.status_code != 200:
            print(f"Error: {resp.text}", file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)
        
        data = resp.json()
        return write_payload(data, fmt, quiet)
    
    handle_scan_status_interactive(scan_id, headers, fmt, quiet)

@app.command()
def usage(
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key or RAFTER_API_KEY env var"),
):
    key = resolve_key(api_key)
    headers = {"x-api-key": key}
    resp = requests.get(f"{API_BASE}/static/usage", headers=headers)
    
    if resp.status_code != 200:
        print(f"Error: {resp.text}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    
    print(json.dumps(resp.json(), indent=2))

if __name__ == "__main__":
    app() 