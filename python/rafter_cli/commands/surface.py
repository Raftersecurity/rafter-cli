"""Attack-surface diff command.

Mirrors ``node/src/commands/surface/{index,diff,render}.ts``. stdout carries the
result and nothing else; every status message goes to stderr.
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

import typer

from ..core.surface.differ import DiffCoverage, diff_properties
from ..core.surface.kind_specs import KIND_SPECS
from ..core.surface.model import Property, Transition, Unanalyzed
from ..core.surface.registry import EXTRACTORS, Extractor
from ..core.surface.serialize import canonical_json, sort_unanalyzed, transition_to_wire
from ..utils.formatter import is_agent_mode
from ..utils.git_tree import (
    EMPTY_TREE_OID,
    BaseTreeReader,
    InvalidRefError,
    RefResolutionError,
)

surface_app = typer.Typer(
    name="surface", help="Attack-surface analysis", no_args_is_help=True
)

NOTE = (
    "Attack-surface diff: a delta of security properties between two trees, not a "
    "findings list. `change` is structural (added/removed/modified); `danger` is "
    "semantic and is the only thing severity attaches to. An empty `transitions` "
    "array with `coverage.inconclusive: false` means the analyzed surface is "
    "unchanged — it does not mean the code is safe."
)

SCHEMA_VERSION = 1
SEVERITY_ORDER = ("low", "medium", "high", "critical")
FORMATS = ("text", "json")
FAIL_ON = ("low", "medium", "high", "critical", "none")
ON_INCONCLUSIVE = ("exit", "warn")
MAX_ROWS = 10


class SurfaceCliError(Exception):
    """Exit 2 and exit 3 are raised, never returned — that is how 3 > 2 > 4 > 1 > 0 stays true."""

    def __init__(self, message: str, exit_code: int, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.code = code


@dataclasses.dataclass(frozen=True)
class SurfaceDiffOptions:
    base: str
    head: Optional[str]
    format: str
    fail_on: str
    min_severity: str
    on_inconclusive: str
    include_decreased: bool
    all: bool
    explain: bool
    fetch_base: bool
    quiet: bool


@dataclasses.dataclass(frozen=True)
class RenderModel:
    base_label: str
    head_label: str
    transitions: Sequence[Transition]
    unanalyzed: Sequence[Unanalyzed]
    degraded: bool
    inconclusive: bool


@dataclasses.dataclass(frozen=True)
class SurfaceDiffOutcome:
    exit_code: int
    report: dict[str, Any]
    model: RenderModel
    status: list[str]


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def _assert_choice(value: str, choices: Sequence[str], flag: str) -> str:
    if value not in choices:
        raise SurfaceCliError(
            f"Invalid value for {flag}: {value!r}. Expected one of: {', '.join(choices)}",
            2,
            "invalid_flag",
        )
    return value


def _invalid_ref(ref: str) -> SurfaceCliError:
    """Composed here rather than reused from git_tree so both runtimes emit the same bytes."""
    return SurfaceCliError(f"Invalid git ref: {json.dumps(ref)}", 2, "invalid_ref")


def _is_git_repo(repo_path: Path) -> bool:
    try:
        subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=repo_path,
            capture_output=True,
            check=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _fetch_base_ref(repo_path: Path, ref: str) -> bool:
    try:
        subprocess.run(
            ["git", "fetch", "--no-tags", "--depth=1", "--end-of-options", "origin", ref],
            cwd=repo_path,
            capture_output=True,
            check=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _run_extractors(
    extractors: Sequence[Extractor],
    files: Mapping[str, str],
    side: str,
    changed: set[str],
) -> tuple[list[Property], list[Unanalyzed]]:
    """Runs every extractor over one side's files. A crash is exit 2, never a silent pass."""
    properties: list[Property] = []
    unanalyzed: list[Unanalyzed] = []
    for extractor in extractors:
        subset = {
            file: content
            for file, content in files.items()
            if extractor.candidate(file, len(content.encode("utf-8")))
        }
        if not subset:
            continue
        try:
            result = extractor.extract(subset)
        except Exception as error:  # noqa: BLE001 — an extractor crash must not read as clean
            raise SurfaceCliError(
                f"Extractor {extractor.id!r} failed on the {side} side: {error}",
                2,
                "extractor_error",
            ) from error
        properties.extend(result.properties)
        # The extractor knows the file; only the caller knows the side and the hint set.
        for item in result.unanalyzed:
            unanalyzed.append(
                dataclasses.replace(item, side=side, changed=item.file in changed)
            )
    return properties, unanalyzed


def _count_analyzed(files: Mapping[str, str], unanalyzed: Sequence[Unanalyzed]) -> int:
    failed = {item.file for item in unanalyzed}
    return sum(1 for file in files if file not in failed)


def _summarize(transitions: Sequence[Transition], min_severity: str) -> dict[str, Any]:
    def count(predicate) -> int:
        return sum(1 for transition in transitions if predicate(transition))

    highest: Optional[str] = None
    for transition in transitions:
        if transition.severity is None:
            continue
        if highest is None or _severity_rank(transition.severity) > _severity_rank(highest):
            highest = transition.severity
    return {
        "increased": count(lambda t: t.danger == "increased"),
        "decreased": count(lambda t: t.danger == "decreased"),
        "incomparable": count(lambda t: t.danger == "incomparable"),
        "unchanged": count(lambda t: t.danger == "unchanged"),
        "unknown": count(lambda t: t.danger == "unknown"),
        "added": count(lambda t: t.change == "added"),
        "removed": count(lambda t: t.change == "removed"),
        "modified": count(lambda t: t.change == "modified"),
        "highest_severity": highest,
        "reportable": count(
            lambda t: t.severity is not None
            and _severity_rank(t.severity) >= _severity_rank(min_severity)
        ),
    }


def _resolve_base(
    reader: BaseTreeReader,
    repo_path: Path,
    options: SurfaceDiffOptions,
    status: list[str],
) -> str:
    try:
        return reader.resolve_ref(options.base)
    except RefResolutionError:
        # An unreachable base must never become an empty base — that reports the
        # whole surface as newly appeared (§4.4).
        if options.fetch_base:
            status.append(f"Fetching base ref '{options.base}' (--fetch-base)…")
            if _fetch_base_ref(repo_path, options.base):
                try:
                    return reader.resolve_ref("FETCH_HEAD")
                except Exception:  # noqa: BLE001 — fall through to exit 3
                    pass
        try:
            shallow = reader.is_shallow()
        except Exception:  # noqa: BLE001
            shallow = False
        raise SurfaceCliError(
            render_base_unresolved(options.base, shallow), 3, "base_unresolved"
        ) from None


def run_surface_diff(
    repo_path: Path,
    options: SurfaceDiffOptions,
    extractors: Sequence[Extractor] = EXTRACTORS,
) -> SurfaceDiffOutcome:
    if not repo_path.is_dir():
        raise SurfaceCliError(f"Path not found: {repo_path}", 2, "path_not_found")
    if not _is_git_repo(repo_path):
        raise SurfaceCliError(f"Not a git repository: {repo_path}", 2, "not_a_repo")

    reader = BaseTreeReader(repo_path)
    status: list[str] = []

    try:
        base_oid = _resolve_base(reader, repo_path, options, status)
    except InvalidRefError as error:
        raise _invalid_ref(options.base) from error

    head_oid: Optional[str] = None
    if options.head is not None:
        try:
            head_oid = reader.resolve_ref(options.head)
        except InvalidRefError as error:
            raise _invalid_ref(options.head or "") from error
        except RefResolutionError as error:
            raise SurfaceCliError(
                f"Cannot resolve head ref '{options.head}' — no such commit in this repository.",
                2,
                "invalid_ref",
            ) from error

    # Changed paths are a hint for §5 R4 and rendering only — never a filter on
    # extraction (§4.1). If the hint cannot be computed, assume everything
    # changed: an inconclusive gate is the conservative failure, a silent clean
    # is not.
    changed_hint_failed = False
    try:
        changed = reader.changed_paths(base_oid, head_oid)
    except Exception:  # noqa: BLE001
        changed = set()
        changed_hint_failed = True
        status.append(
            "Could not compute the changed-file hint; treating every candidate as changed."
        )

    def candidate(file: str, size_bytes: int) -> bool:
        return any(extractor.candidate(file, size_bytes) for extractor in extractors)

    base_read = reader.read_tree_candidates(base_oid, candidate, changed, "base")
    head_read = (
        reader.read_work_tree_candidates(candidate, changed)
        if head_oid is None
        else reader.read_tree_candidates(head_oid, candidate, changed, "head")
    )

    base_properties, base_unanalyzed = _run_extractors(
        extractors, base_read.files, "base", changed
    )
    head_properties, head_unanalyzed = _run_extractors(
        extractors, head_read.files, "head", changed
    )

    unanalyzed = [
        *base_read.unanalyzed,
        *head_read.unanalyzed,
        *base_unanalyzed,
        *head_unanalyzed,
    ]
    if changed_hint_failed:
        unanalyzed = [dataclasses.replace(item, changed=True) for item in unanalyzed]

    # The differ appends its own coverage records (duplicate keys), so the flags
    # below are computed from the post-diff list, not the pre-diff one.
    coverage = DiffCoverage(unanalyzed=unanalyzed)
    transitions = diff_properties(base_properties, head_properties, KIND_SPECS, coverage)

    sorted_unanalyzed = sort_unanalyzed(coverage.unanalyzed)
    degraded = len(sorted_unanalyzed) > 0
    inconclusive = any(item.changed for item in sorted_unanalyzed)

    report = {
        "_note": NOTE,
        "schema_version": SCHEMA_VERSION,
        "base": {
            "ref": "EMPTY_TREE" if base_oid == EMPTY_TREE_OID else options.base,
            "resolved": base_oid,
        },
        "head": {
            "ref": "WORKTREE" if options.head is None else options.head,
            "resolved": head_oid,
        },
        "summary": _summarize(transitions, options.min_severity),
        "transitions": [transition_to_wire(transition) for transition in transitions],
        "coverage": {
            "analyzed": _count_analyzed(base_read.files, base_unanalyzed)
            + _count_analyzed(head_read.files, head_unanalyzed),
            "degraded": degraded,
            "inconclusive": inconclusive,
            "unanalyzed": [
                {
                    "file": item.file,
                    "side": item.side,
                    "reason": item.reason,
                    "detail": item.detail,
                    "changed": item.changed,
                }
                for item in sorted_unanalyzed
            ],
        },
    }

    gating = (
        []
        if options.fail_on == "none"
        else [
            transition
            for transition in transitions
            if transition.severity is not None
            and transition.danger in ("increased", "incomparable")
            and _severity_rank(transition.severity) >= _severity_rank(options.fail_on)
        ]
    )

    exit_code = 0
    if gating:
        exit_code = 1
    if inconclusive and options.on_inconclusive == "exit":
        exit_code = 4
    if inconclusive and options.on_inconclusive == "warn":
        status.append(
            "Inconclusive result downgraded to a warning by --on-inconclusive warn."
        )

    return SurfaceDiffOutcome(
        exit_code=exit_code,
        report=report,
        status=status,
        model=RenderModel(
            base_label="empty tree" if base_oid == EMPTY_TREE_OID else options.base,
            head_label="working tree" if options.head is None else options.head,
            transitions=transitions,
            unanalyzed=sorted_unanalyzed,
            degraded=degraded,
            inconclusive=inconclusive,
        ),
    )


# ---------------------------------------------------------------------------
# Rendering (§9.2). Mirrors node/src/commands/surface/render.ts.
# ---------------------------------------------------------------------------


def _paint_severity(severity: str) -> str:
    if is_agent_mode():
        return severity
    colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}
    color = colors.get(severity)
    if color is None:
        return severity
    return typer.style(severity, fg=color, bold=severity in ("critical", "high"))


def _pad(text: str, width: int) -> str:
    return f"{text} " if len(text) >= width else text.ljust(width)


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else f"{text[: width - 1]}…"


def _plural(count: int, singular: str, plural_form: str) -> str:
    return singular if count == 1 else plural_form


def _evidence_of(transition: Transition) -> str:
    evidence = transition.head_evidence or transition.base_evidence
    if evidence is None:
        return ""
    return evidence.file if evidence.line is None else f"{evidence.file}:{evidence.line}"


def delta_phrase(transition: Transition) -> str:
    """The delta phrase.

    Per amendment A1, ``transitions[].label`` is the endpoint property's own
    description and carries no delta prose, so every "widened to X" phrasing is
    composed here and nowhere else.
    """
    if transition.danger == "incomparable":
        return "incomparable — review by hand"
    if transition.danger == "unknown":
        return "unknown — coverage loss on the other side"
    if transition.change == "added":
        return "new" if transition.danger == "increased" else "added"
    if transition.change == "removed":
        return "removed"
    moved = [axis for axis in transition.axes if axis.order != "equal"]
    if not moved:
        return "unchanged"
    direction = "narrowed" if transition.danger == "decreased" else "widened"
    return ", ".join(
        f"{axis.axis} {direction}: {axis.from_rank or 'absent'} → {axis.to_rank or 'absent'}"
        for axis in moved
    )


def _visible_transitions(
    model: RenderModel,
    min_severity: str,
    include_decreased: bool,
    show_all: bool,
) -> list[Transition]:
    visible = []
    for transition in model.transitions:
        if transition.danger == "decreased":
            if include_decreased:
                visible.append(transition)
            continue
        if transition.severity is None:
            if show_all:
                visible.append(transition)
            continue
        if _severity_rank(transition.severity) >= _severity_rank(min_severity):
            visible.append(transition)
    return visible


def _headline(visible: Sequence[Transition], pair: str) -> str:
    increased = sum(1 for transition in visible if transition.danger == "increased")
    ambiguous = sum(1 for transition in visible if transition.danger == "incomparable")
    parts = []
    if increased:
        parts.append(
            f"{increased} {_plural(increased, 'property', 'properties')} became more dangerous"
        )
    if ambiguous:
        parts.append(f"{ambiguous} {_plural(ambiguous, 'is', 'are')} ambiguous")
    if not parts:
        parts.append("no property became more dangerous")
    return f"Attack surface: {', '.join(parts)}  {pair}"


def _inconclusive_block(model: RenderModel, on_inconclusive: str) -> list[str]:
    blocking = [item for item in model.unanalyzed if item.changed]
    lines = [
        f"Attack surface: INCONCLUSIVE — {len(blocking)} "
        f"{_plural(len(blocking), 'file', 'files')} changed in this diff could not be analyzed.",
        "",
    ]
    for item in blocking[:MAX_ROWS]:
        lines.append(f"  {_pad(_truncate(item.file, 40), 42)}{item.detail} ({item.reason})")
    if len(blocking) > MAX_ROWS:
        lines.append(f"  +{len(blocking) - MAX_ROWS} more (--json)")
    lines.append("")
    if on_inconclusive == "warn":
        lines.append("Downgraded to a warning by --on-inconclusive warn — the exit code does not")
        lines.append("reflect it. This is still not a clean result.")
    else:
        lines.append("This is not a clean result. Fix the file, or pass --on-inconclusive warn to")
        lines.append("downgrade this to a warning.")
    return lines


def render_text(model: RenderModel, options: SurfaceDiffOptions) -> str:
    """The human-readable report (§9.2). Result lines only — status belongs on stderr."""
    pair = f"({model.base_label} → {model.head_label})"
    visible = _visible_transitions(
        model, options.min_severity, options.include_decreased, options.all
    )
    lines: list[str] = []

    if visible or model.transitions:
        lines.append(_headline(visible, pair))
        if visible:
            lines.append("")
        for transition in visible[:MAX_ROWS]:
            severity = transition.severity or "-"
            # Pad on the plain string; color codes must not count toward column width.
            lines.append(
                f"  {_paint_severity(severity)}{' ' * max(1, 10 - len(severity))}"
                f"{_pad(_truncate(transition.label, 38), 40)}"
                f"{_pad(_truncate(_evidence_of(transition), 28), 30)}"
                f"{delta_phrase(transition)}"
            )
        if len(visible) > MAX_ROWS:
            lines.append(f"  +{len(visible) - MAX_ROWS} more (--json)")
        hidden_decreased = (
            0
            if options.include_decreased
            else sum(1 for t in model.transitions if t.danger == "decreased")
        )
        if hidden_decreased:
            lines.append("")
            note = (
                f"{hidden_decreased} {_plural(hidden_decreased, 'property', 'properties')} "
                "became safer"
            )
            lines.append(f"  {_pad(note, 50)}(--include-decreased)")
        if not options.explain and model.unanalyzed:
            count = len(model.unanalyzed)
            note = f"{count} {_plural(count, 'file', 'files')} could not be analyzed"
            if not hidden_decreased:
                lines.append("")
            lines.append(f"  {_pad(note, 50)}(--explain)")
    elif not model.inconclusive:
        # Three outcomes that must never read alike: clean, degraded-clean, inconclusive.
        if model.degraded:
            count = len(model.unanalyzed)
            lines.append(
                f"Attack surface: no change detected, but {count} "
                f"{_plural(count, 'file', 'files')} could not be analyzed  {pair}"
                f"{'' if options.explain else '  (--explain)'}"
            )
        else:
            lines.append(f"Attack surface unchanged  {pair}")

    if model.inconclusive:
        if lines:
            lines.append("")
        lines.extend(_inconclusive_block(model, options.on_inconclusive))

    if options.explain and model.unanalyzed:
        lines.append("")
        lines.append(f"Unanalyzed candidates ({len(model.unanalyzed)}):")
        for item in model.unanalyzed:
            detail = f" — {item.detail}" if item.detail else ""
            changed = "  [changed]" if item.changed else ""
            lines.append(
                f"  {_pad(_truncate(item.file, 40), 42)}{item.side}  {item.reason}{detail}{changed}"
            )

    return "\n".join(lines) + "\n"


def render_base_unresolved(ref: str, shallow: bool) -> str:
    """§4.4 / §9.2 — the actionable exit-3 message. Never a bare "base not found"."""
    branch = ref.rsplit("/", 1)[-1]
    cause = (
        f"Cannot resolve base ref '{ref}' — this is a shallow clone."
        if shallow
        else f"Cannot resolve base ref '{ref}' — no such commit in this repository."
    )
    return "\n".join(
        [
            cause,
            "actions/checkout defaults to fetch-depth: 1. Fix with either:",
            "    - uses: actions/checkout@v4",
            "      with: { fetch-depth: 0 }",
            f"    - run: git fetch --no-tags --depth=1 origin {branch}",
            "Or run with --fetch-base to fetch it now.",
        ]
    )


@surface_app.command("diff")
def diff(
    path: Optional[str] = typer.Argument(None, help="Repository path (default: current directory)"),
    base: str = typer.Option("HEAD", "--base", help="Base ref"),
    head: Optional[str] = typer.Option(None, "--head", help="Head ref (default: the working tree)"),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json"),
    json_output: bool = typer.Option(False, "--json", help="Alias for --format json"),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Exit-1 threshold: low, medium, high, critical, none"
    ),
    min_severity: str = typer.Option(
        "low", "--min-severity", help="Display floor: low, medium, high, critical"
    ),
    on_inconclusive: Optional[str] = typer.Option(
        None,
        "--on-inconclusive",
        help="exit or warn (default: exit, or warn with --fail-on none)",
    ),
    include_decreased: bool = typer.Option(
        False, "--include-decreased", help="Show transitions that became safer"
    ),
    show_all: bool = typer.Option(False, "--all", help="Include severity-null transitions"),
    explain: bool = typer.Option(False, "--explain", help="Enumerate unanalyzed files"),
    fetch_base: bool = typer.Option(
        False, "--fetch-base", help="Permit one narrow git fetch to resolve the base"
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress stderr status messages"),
):
    """Diff the security-relevant attack surface between two trees."""
    try:
        exit_code = _execute(
            path,
            base,
            head,
            output_format,
            json_output,
            fail_on,
            min_severity,
            on_inconclusive,
            include_decreased,
            show_all,
            explain,
            fetch_base,
            quiet,
        )
    except SurfaceCliError as error:
        print(error.message, file=sys.stderr)
        raise typer.Exit(code=error.exit_code) from None
    except Exception as error:  # noqa: BLE001
        print(f"Attack-surface diff failed: {error}", file=sys.stderr)
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=exit_code)


def _execute(
    path: Optional[str],
    base: str,
    head: Optional[str],
    output_format: str,
    json_output: bool,
    fail_on: str,
    min_severity: str,
    on_inconclusive: Optional[str],
    include_decreased: bool,
    show_all: bool,
    explain: bool,
    fetch_base: bool,
    quiet: bool,
) -> int:
    resolved_format = (
        "json" if json_output else _assert_choice(output_format, FORMATS, "--format")
    )
    resolved_fail_on = _assert_choice(fail_on, FAIL_ON, "--fail-on")
    resolved_min_severity = _assert_choice(min_severity, SEVERITY_ORDER, "--min-severity")
    resolved_on_inconclusive = (
        ("warn" if resolved_fail_on == "none" else "exit")
        if on_inconclusive is None
        else _assert_choice(on_inconclusive, ON_INCONCLUSIVE, "--on-inconclusive")
    )

    options = SurfaceDiffOptions(
        base=base,
        head=head,
        format=resolved_format,
        fail_on=resolved_fail_on,
        min_severity=resolved_min_severity,
        on_inconclusive=resolved_on_inconclusive,
        include_decreased=include_decreased,
        all=show_all,
        explain=explain,
        fetch_base=fetch_base,
        quiet=quiet,
    )

    repo_path = Path(os.path.abspath(path if path is not None else os.getcwd()))
    outcome = run_surface_diff(repo_path, options)

    # stdout carries the result and nothing else; every status message is stderr.
    if resolved_format == "json":
        sys.stdout.write(canonical_json(outcome.report) + "\n")
    else:
        typer.echo(render_text(outcome.model, options), nl=False)
    if not quiet:
        for line in outcome.status:
            print(line, file=sys.stderr)
    return outcome.exit_code
