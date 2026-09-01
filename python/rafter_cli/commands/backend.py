"""Backend commands: run, get, usage — extracted from original __main__.py."""
from __future__ import annotations

import json
import sys
import time

import requests
import typer

from ..utils.api import (
    api_url,
    api_get,
    api_post,
    API_BASE,
    API_TIMEOUT,
    API_TIMEOUT_SHORT,
    EXIT_CONFIRMATION_REQUIRED,
    EXIT_GENERAL_ERROR,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    EXIT_SUCCESS,
    handle_403,
    resolve_key,
    write_payload,
)
from ..utils.git import detect_repo


def _plus_approval_gate_enabled() -> bool:
    """sable-9ddf — is the Plus-scan approval gate enabled?

    OR semantics across the machine-owner's global config and the project's
    ``.rafter.yml``: if EITHER opts in, approval is required. A project policy
    can turn the gate ON but can NEVER turn it OFF — a hostile repo must not be
    able to silently re-open the credit-burn hole a user closed globally.

    Fails open (returns False) if config/policy can't be read, consistent with
    the OFF-by-default product behavior and the codebase's config-load fallback.
    """
    from ..core.config_manager import ConfigManager
    from ..core.policy_loader import load_policy

    global_flag = False
    try:
        global_flag = ConfigManager().load().agent.scan.plus_requires_approval is True
    except Exception:
        pass  # fail open
    policy_flag = False
    try:
        policy = load_policy()
        policy_flag = bool(policy and policy.get("scan", {}).get("plus_requires_approval") is True)
    except Exception:
        pass  # fail open
    return global_flag or policy_flag


def _confirm_plus_scan(mode: str, yes: bool) -> None:
    """Gate a paid Plus scan behind explicit confirmation when the switch is on.

    Returns normally if the scan may proceed; raises ``typer.Exit`` otherwise.
    No-op for non-plus modes and when the gate is disabled (the default).
    """
    import os as _os

    if (mode or "fast") != "plus":
        return
    if not _plus_approval_gate_enabled():
        return

    env_confirm = _os.environ.get("RAFTER_CONFIRM")
    if yes or env_confirm in ("1", "true"):
        return

    if sys.stdin.isatty():
        answer = input(
            "  Plus is a PAID scan tier and will consume your credits. Proceed? [y/N] "
        ).strip().lower()
        if answer in ("y", "yes"):
            return
        print("Plus scan cancelled.", file=sys.stderr)
        raise typer.Exit(code=EXIT_CONFIRMATION_REQUIRED)

    print(
        "Refusing to run a paid Plus scan: approval is required "
        "(scan.plus_requires_approval is enabled).\n"
        "Re-run with --yes (or set RAFTER_CONFIRM=1) to confirm the credit spend, "
        "or use the free --mode fast scan.",
        file=sys.stderr,
    )
    raise typer.Exit(code=EXIT_CONFIRMATION_REQUIRED)


# sable-l10k — the report a scan writes is not durable the instant the scan
# flips to completed, so a poll can legitimately hit a 5xx (commonly
# "Failed to fetch report from storage: Object not found") on an otherwise
# healthy scan. Retry those instead of failing the whole run; a scan that would
# have succeeded 10 seconds later must not die on one bad read.
MAX_TRANSIENT_POLL_FAILURES = 5

#: Total transient failures tolerated across one interactive call.
#:
#: The consecutive counter resets on every success, which is what we want — a
#: twenty-minute scan with one blip at minute 2 and another at minute 18 should
#: not die. But reset-on-success alone means a backend alternating 200/500
#: forever never exhausts the budget, and the CLI has no wall-clock deadline to
#: stop it. This is the backstop for that.
MAX_TOTAL_TRANSIENT_POLL_FAILURES = 20

BASE_BACKOFF_SECONDS = 2

#: Longest single error detail we will echo back. Servers can be verbose.
MAX_ERROR_DETAIL_CHARS = 200

IN_PROGRESS = ("queued", "pending", "processing")


class PollGaveUpError(RuntimeError):
    """Polling gave up after exhausting its retry budget.

    Carries the customer-facing message so callers need not rebuild it.
    """


class PollFatalError(RuntimeError):
    """A poll failed in a way retrying cannot fix (bad key, bad request).

    Distinct from :class:`PollGaveUpError` so that "we tried five times" is
    never confused with "we did not try at all".
    """

    def __init__(self, message: str, status_code: "int | None" = None):
        super().__init__(message)
        self.status_code = status_code


def backoff_seconds(consecutive_failures: int) -> int:
    """2s, 4s, 8s, 16s — the 5th failure gives up rather than sleeping again."""
    return BASE_BACKOFF_SECONDS * 2 ** (consecutive_failures - 1)


def _is_transient_poll_status(status_code: int, scan_exists: bool) -> bool:
    """Transient = the server itself describes the condition as temporary.

    ``scan_exists`` gates 404: before the first successful poll a 404 means the
    scan id is wrong, and retrying it just delays a clear answer. After it, a
    missing scan is read-after-write lag.
    """
    if status_code == 404:
        return scan_exists
    return status_code >= 500 or status_code == 408


def _truncate(value) -> str:
    """Coerce before truncating.

    A server is free to answer ``{"error": {"message": "..."}}``. This used to
    call ``.split()`` on a dict, raising an ``AttributeError`` that no caller
    catches — turning a retryable failure into an unhandled traceback.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    flat = " ".join(text.split())
    if len(flat) > MAX_ERROR_DETAIL_CHARS:
        return flat[:MAX_ERROR_DETAIL_CHARS] + "\u2026"
    return flat


def _describe_http_error(status_code: int, body: str) -> str:
    detail = body
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            detail = parsed.get("error") or body
    except (ValueError, TypeError):
        pass
    detail = _truncate(detail)
    return f"HTTP {status_code}" + (f" \u2014 {detail}" if detail else "")


def unreadable_report_message(
    scan_id: str,
    last_error: str,
    attempts: int = MAX_TRANSIENT_POLL_FAILURES,
    reached_server: bool = True,
) -> str:
    """The message a customer actually sees when the report never becomes readable.

    Storage-layer wording ("Object not found") is kept as supporting detail, not
    as the whole explanation, and the next action is spelled out. ``attempts`` is
    the real count, which is not always ``MAX_TRANSIENT_POLL_FAILURES`` — the
    total budget can trip first.
    """
    if not reached_server:
        return (
            f"Rafter could not reach the API after {attempts} attempts.\n"
            "Check your network and that https://rafter.so is reachable from here.\n"
            f"Your scan id is {scan_id} \u2014 the scan may still be running.\n"
            f"Last error: {last_error}"
        )
    return (
        f"Rafter could not read the report for scan {scan_id} after "
        f"{attempts} attempts.\n"
        f"The scan itself may have finished \u2014 retry with: rafter get {scan_id}\n"
        f"or open the scan in your dashboard at https://rafter.so/dashboard\n"
        f"Last response from the server: {last_error}"
    )


class _FailureBudget:
    """A failure budget shared across every poll in one interactive call.

    Counting per-request would let a backend that alternates 200/500 forever
    reset the counter on each success and never exhaust it — the CLI has no
    wall-clock deadline, so that loop would never end.
    """

    def __init__(self) -> None:
        self.consecutive = 0
        self.total = 0
        self.last = ""
        #: False once any failure carried no HTTP response at all.
        self.last_reached_server = True

    def record(self, detail: str, reached_server: bool = True) -> int:
        self.consecutive += 1
        self.total += 1
        self.last = detail
        self.last_reached_server = reached_server
        return self.consecutive

    def reset(self) -> None:
        """A success clears the consecutive run, but never refunds the total."""
        self.consecutive = 0

    @property
    def exhausted(self) -> bool:
        return (
            self.consecutive >= MAX_TRANSIENT_POLL_FAILURES
            or self.total >= MAX_TOTAL_TRANSIENT_POLL_FAILURES
        )


def _poll_until_readable(
    scan_id: str,
    headers: dict,
    fmt: str,
    quiet: bool,
    budget: "_FailureBudget",
    scan_exists: bool,
):
    """One poll, retrying transient failures with exponential backoff.

    Returns the successful response. Raises ``PollGaveUpError`` once the retry
    budget is spent and ``PollFatalError`` for anything retrying cannot fix.
    """
    while True:
        try:
            resp = api_get(
                api_url("static/scan"),
                headers=headers,
                params={"scan_id": scan_id, "format": fmt},
                timeout=API_TIMEOUT_SHORT,
            )
            # Any 2xx is a success, matching the Node runtime's axios default.
            if 200 <= resp.status_code < 300:
                budget.reset()
                return resp
            if not _is_transient_poll_status(resp.status_code, scan_exists):
                raise PollFatalError(
                    _describe_http_error(resp.status_code, resp.text),
                    status_code=resp.status_code,
                )
            detail = _describe_http_error(resp.status_code, resp.text)
            reached_server = True
        except requests.RequestException as e:
            # Transport error (DNS, reset, timeout) — as retryable as a 5xx.
            detail = _truncate(str(e))
            reached_server = False

        attempt = budget.record(detail, reached_server)
        if budget.exhausted:
            raise PollGaveUpError(
                unreadable_report_message(
                    scan_id,
                    budget.last,
                    attempts=budget.total,
                    reached_server=budget.last_reached_server,
                )
            )

        wait = backoff_seconds(attempt)
        if not quiet:
            print(
                f"Report not readable yet ({budget.last}); retrying in {wait}s "
                f"({attempt}/{MAX_TRANSIENT_POLL_FAILURES})",
                file=sys.stderr,
            )
        time.sleep(wait)


def fetch_scan_with_retry(scan_id: str, headers: dict, fmt: str, quiet: bool):
    """A single scan fetch with the same retry budget the poll loop uses.

    ``rafter get <id>`` is what the give-up message tells customers to run, so
    it must not be defeated by exactly the transient failure that produced the
    message. A 404 here is still fatal — that is a wrong id, not lag.
    """
    return _poll_until_readable(
        scan_id, headers, fmt, quiet, _FailureBudget(), scan_exists=False
    )


def _handle_scan_status_interactive(
    scan_id: str, headers: dict, fmt: str, quiet: bool
) -> int:
    budget = _FailureBudget()

    # First poll. A 404 here really does mean "no such scan" — do not retry it.
    # Transient 5xx IS retried, so that the `rafter get <id>` this command
    # recommends on failure is not itself defeated by one bad read.
    try:
        poll = _poll_until_readable(
            scan_id, headers, fmt, quiet, budget, scan_exists=False
        )
    except PollFatalError as e:
        if e.status_code == 404:
            print(f"Scan '{scan_id}' not found", file=sys.stderr)
            raise typer.Exit(code=EXIT_SCAN_NOT_FOUND)
        print(f"Error: {e}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    except PollGaveUpError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    data = poll.json()
    status = data.get("status")

    if status in IN_PROGRESS:
        if not quiet:
            print(
                "Waiting for scan to complete... (this could take several minutes)",
                file=sys.stderr,
            )
        while status in IN_PROGRESS:
            time.sleep(10)
            try:
                poll = _poll_until_readable(
                    scan_id, headers, fmt, quiet, budget, scan_exists=True
                )
            except (PollGaveUpError, PollFatalError) as e:
                print(f"Error: {e}", file=sys.stderr)
                raise typer.Exit(code=EXIT_GENERAL_ERROR)
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


def _do_remote_scan(
    repo: "str | None",
    branch: "str | None",
    api_key: "str | None",
    fmt: str,
    skip_interactive: bool,
    quiet: bool,
    mode: str = "fast",
    github_token: "str | None" = None,
    provider: "str | None" = None,
    repo_url: "str | None" = None,
    yes: bool = False,
) -> None:
    """Shared implementation for remote backend scan — used by both `rafter run` and `rafter scan`."""
    import os as _os

    # sable-9ddf — gate paid Plus scans before doing any work (key resolution,
    # repo detection, or the billable API call).
    _confirm_plus_scan(mode, yes)

    key = resolve_key(api_key)
    gh_token = github_token or _os.environ.get("RAFTER_GITHUB_TOKEN")
    try:
        repo_slug, branch_name, detected_provider, detected_repo_url = detect_repo(repo, branch)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    if not (repo and branch) and not quiet:
        print(f"Repo auto-detected: {repo_slug} @ {branch_name} (note: scanning remote)", file=sys.stderr)

    # Explicit flags override inferred values.
    resolved_provider = provider or detected_provider
    resolved_repo_url = repo_url or detected_repo_url

    headers = {"x-api-key": key, "Content-Type": "application/json"}

    body: dict = {"repository_name": repo_slug, "branch_name": branch_name, "scan_mode": mode}
    if gh_token:
        body["github_token"] = gh_token

    # Additive, backward-compatible: only send provider + repo_url for non-github
    # remotes. For github (or an unknown host that defaulted to github), omit both
    # so the request body is byte-identical to the legacy github-only behavior.
    if resolved_provider and resolved_provider != "github" and resolved_repo_url:
        body["provider"] = resolved_provider
        body["repo_url"] = resolved_repo_url

    resp = api_post(
        api_url("static/scan"),
        headers=headers,
        json=body,
        timeout=API_TIMEOUT,
    )

    forbidden_code = handle_403(resp)
    if forbidden_code >= 0:
        raise typer.Exit(code=forbidden_code)
    elif resp.status_code == 429:
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

    _handle_scan_status_interactive(scan_id, headers, fmt, quiet)


def register_backend_commands(app: typer.Typer) -> None:
    """Register run/get/usage on the root typer app."""

    @app.command()
    def run(
        repo: str = typer.Option(None, "--repo", "-r", help="org/repo (default: current)"),
        branch: str = typer.Option(None, "--branch", "-b", help="branch (default: current else main)"),
        api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
        fmt: str = typer.Option("md", "--format", "-f", help="json | md"),
        mode: str = typer.Option("fast", "--mode", "-m", help="scan mode: fast | plus"),
        github_token: str = typer.Option(None, "--github-token", envvar="RAFTER_GITHUB_TOKEN", help="GitHub PAT for private repos"),
        provider: str = typer.Option(None, "--provider", help="git provider: gitlab | gitea | bitbucket (default: auto-detected; github requires nothing)"),
        repo_url: str = typer.Option(None, "--repo-url", help="full https clone URL for non-github remotes (default: auto-detected)"),
        skip_interactive: bool = typer.Option(False, "--skip-interactive", help="do not wait for scan to complete"),
        yes: bool = typer.Option(False, "--yes", "-y", help="confirm a paid Plus scan without prompting (when scan.plus_requires_approval is on)"),
        quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
    ):
        """Trigger a security scan."""
        _do_remote_scan(repo, branch, api_key, fmt, skip_interactive, quiet, mode, github_token=github_token, provider=provider, repo_url=repo_url, yes=yes)

    @app.command()
    def get(
        scan_id: str = typer.Argument(...),
        api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
        fmt: str = typer.Option("md", "--format", "-f", help="json | md"),
        interactive: bool = typer.Option(False, "--interactive", help="poll until done"),
        quiet: bool = typer.Option(False, "--quiet", help="suppress status messages"),
    ):
        """Retrieve scan results."""
        key = resolve_key(api_key)
        headers = {"x-api-key": key}

        if not interactive:
            # sable-l10k — retried, because this is the command the poll loop's
            # give-up message recommends. A remedy defeated by the same
            # transient failure it is recommended for is not a remedy.
            try:
                resp = fetch_scan_with_retry(scan_id, headers, fmt, quiet)
            except PollFatalError as e:
                if e.status_code == 404:
                    print(f"Scan '{scan_id}' not found", file=sys.stderr)
                    raise typer.Exit(code=EXIT_SCAN_NOT_FOUND)
                print(f"Error: {e}", file=sys.stderr)
                raise typer.Exit(code=EXIT_GENERAL_ERROR)
            except PollGaveUpError as e:
                print(f"Error: {e}", file=sys.stderr)
                raise typer.Exit(code=EXIT_GENERAL_ERROR)
            data = resp.json()
            return write_payload(data, fmt, quiet)

        _handle_scan_status_interactive(scan_id, headers, fmt, quiet)

    @app.command()
    def usage(
        api_key: str = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key"),
    ):
        """Check quota and usage."""
        key = resolve_key(api_key)
        headers = {"x-api-key": key}
        resp = api_get(
            api_url("static/usage"), headers=headers, timeout=API_TIMEOUT_SHORT
        )
        if resp.status_code != 200:
            print(f"Error: {resp.text}", file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)
        print(json.dumps(resp.json(), indent=2))
