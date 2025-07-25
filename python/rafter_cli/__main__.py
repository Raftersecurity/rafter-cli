import typer
import requests
import time
import os
import json
import pathlib
import subprocess
import re
from dotenv import load_dotenv
from rich import print, progress

app = typer.Typer()
API_BASE = "https://rafter.so/api"

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
    typer.echo("No API key provided. Use --api-key or set RAFTER_API_KEY", err=True)
    raise typer.Exit(code=1)

def resolve_repo_branch(repo_opt, branch_opt):
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
            print(f"[bold cyan]\U0001F50D  Repo auto-detected: {repo} @ {branch}")
        return repo, branch
    except Exception:
        typer.echo("Could not auto-detect Git repository. Please pass --repo and --branch explicitly.", err=True)
        raise typer.Exit(code=1)

def save_result(data, path, name, fmt):
    path = pathlib.Path(path or ".")
    name = name or f"rafter_static_{int(time.time())}"
    ext = "md" if fmt == "md" else "json"
    out = path / f"{name}.{ext}"
    if fmt == "md":
        out.write_text(data["markdown"])
    else:
        out.write_text(json.dumps(data, indent=2))
    print(f"Saved to {out.resolve()}")

@app.command()
def run(
    repo: str = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
    branch: str = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key or RAFTER_API_KEY env var"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
    save: str = typer.Option(None, "--save", help="save file to path (default: current directory)"),
    save_name: str = typer.Option(None, "--save-name", help="filename override (default: rafter_static_<timestamp>)"),
):
    key = resolve_key(api_key)
    repo, branch = resolve_repo_branch(repo, branch)
    headers = {"x-api-key": key, "Content-Type": "application/json"}
    resp = requests.post(f"{API_BASE}/static/scan", headers=headers, json={"repository_name": repo, "branch_name": branch})
    if resp.status_code != 200:
        print(f"[red]Error: {resp.text}")
        raise typer.Exit(code=1)
    scan_id = resp.json()["scan_id"]
    print(f"Scan ID: {scan_id}")
    if skip_interactive:
        return
    with progress.Progress() as prog:
        task = prog.add_task("Waiting for scan to complete...", start=False)
        status = "queued"
        while status in ("queued", "pending", "processing"):
            prog.start_task(task)
            time.sleep(5)
            poll = requests.get(f"{API_BASE}/static/scan", headers=headers, params={"scan_id": scan_id, "format": fmt})
            data = poll.json()
            status = data.get("status")
            if status == "completed":
                prog.update(task, completed=100)
                print("[green]Scan completed!")
                if save is not None:
                    save_result(data, save, save_name, fmt)
                else: # TODO: check if this is correct (unreachable)
                    if fmt == "md":
                        print(data["markdown"])
                    else:
                        print(json.dumps(data, indent=2))
                return
            elif status == "failed":
                print("[red]Scan failed.")
                raise typer.Exit(code=1)
        print(f"[yellow]Scan status: {status}")

@app.command()
def get(
    scan_id: str = typer.Argument(...),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key or RAFTER_API_KEY env var"),
    fmt: str = typer.Option("json", "--format", "-f", help="json | md"),
    interactive: bool = typer.Option(False, "--interactive", help="poll until done"),
    save: str = typer.Option(None, "--save", help="save file to path (default: current directory)"),
    save_name: str = typer.Option(None, "--save-name", help="filename override (default: rafter_static_<timestamp>)"),
):
    key = resolve_key(api_key)
    headers = {"x-api-key": key}
    if not interactive:
        resp = requests.get(f"{API_BASE}/static/scan", headers=headers, params={"scan_id": scan_id, "format": fmt})
        data = resp.json()
        if save is not None:
            save_result(data, save, save_name, fmt)
        else: # TODO: check if this is correct (unreachable)
            if fmt == "md":
                print(data["markdown"])
            else:
                print(json.dumps(data, indent=2))
        return
    with progress.Progress() as prog:
        task = prog.add_task("Waiting for scan to complete...", start=False)
        status = "queued"
        while status in ("queued", "pending", "processing"):
            prog.start_task(task)
            time.sleep(5)
            poll = requests.get(f"{API_BASE}/static/scan", headers=headers, params={"scan_id": scan_id, "format": fmt})
            data = poll.json()
            status = data.get("status")
            if status == "completed":
                prog.update(task, completed=100)
                print("[green]Scan completed!")
                if save is not None:
                    save_result(data, save, save_name, fmt)
                else: # TODO: check if this is correct (unreachable)
                    if fmt == "md":
                        print(data["markdown"])
                    else:
                        print(json.dumps(data, indent=2))
                return
            elif status == "failed":
                print("[red]Scan failed.")
                raise typer.Exit(code=1)
        print(f"[yellow]Scan status: {status}")

@app.command()
def usage(
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key or RAFTER_API_KEY env var"),
):
    key = resolve_key(api_key)
    headers = {"x-api-key": key}
    resp = requests.get(f"{API_BASE}/static/usage", headers=headers)
    if resp.status_code != 200:
        print(f"[red]Error: {resp.text}")
        raise typer.Exit(code=1)
    print(json.dumps(resp.json(), indent=2))

if __name__ == "__main__":
    app() 