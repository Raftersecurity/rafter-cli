"""Output formatter with agent/human modes."""
from __future__ import annotations

_agent_mode: bool = False


def set_agent_mode(enabled: bool) -> None:
    global _agent_mode
    _agent_mode = enabled


def is_agent_mode() -> bool:
    return _agent_mode


class fmt:
    """Static formatter methods. Human mode uses Rich markup, agent mode is plain."""

    @staticmethod
    def header(text: str) -> str:
        if _agent_mode:
            return f"=== {text} ==="
        return f"\n[bold][cyan]\\u250c\\u2500[/cyan] {text} [cyan]\\u2500\\u2510[/cyan][/bold]\n"

    @staticmethod
    def success(text: str) -> str:
        if _agent_mode:
            return f"[OK] {text}"
        return f"[green]\\u2713 {text}[/green]"

    @staticmethod
    def warning(text: str) -> str:
        if _agent_mode:
            return f"[WARN] {text}"
        return f"[yellow]\\u26a0  {text}[/yellow]"

    @staticmethod
    def error(text: str) -> str:
        if _agent_mode:
            return f"[ERROR] {text}"
        return f"[red]\\u2717 {text}[/red]"

    @staticmethod
    def severity(level: str) -> str:
        upper = level.upper()
        if _agent_mode:
            return f"[{upper}]"
        styles = {
            "critical": f"[bold white on red] {upper} [/bold white on red]",
            "high": f"[bold black on yellow] {upper} [/bold black on yellow]",
            "medium": f"[white on blue] {upper} [/white on blue]",
            "low": f"[white on green] {upper} [/white on green]",
        }
        return styles.get(level, f"[{upper}]")

    @staticmethod
    def divider() -> str:
        if _agent_mode:
            return "---"
        return "[dim]" + "\u2550" * 50 + "[/dim]"

    @staticmethod
    def info(text: str) -> str:
        if _agent_mode:
            return text
        return f"[cyan]{text}[/cyan]"
