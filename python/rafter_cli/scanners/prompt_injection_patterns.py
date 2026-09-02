"""Prompt-injection detection patterns — port of Node prompt-injection-patterns.ts.

EXPERIMENTAL — see docs/research/prompt-injection-detector.md.
Pattern-based, English-only, trivially bypassable by paraphrase.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Literal

InjectionCategory = Literal[
    "role_override", "tool_exfil", "hidden_unicode", "html_comment", "encoded_payload"
]
InjectionSeverity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class InjectionPattern:
    name: str
    category: InjectionCategory
    severity: InjectionSeverity
    regex: re.Pattern[str]
    description: str


ROLE_OVERRIDE_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        name="ignore_previous_instructions",
        category="role_override",
        severity="high",
        regex=re.compile(
            r"\bignore(?:\s+(?:all|any|the))?\s+(?:previous|prior|above|preceding)\s+"
            r"(?:instructions?|rules?|directives?|prompts?|messages?)\b",
            re.IGNORECASE,
        ),
        description="Classic 'ignore previous instructions' jailbreak phrasing.",
    ),
    InjectionPattern(
        name="disregard_above",
        category="role_override",
        severity="high",
        regex=re.compile(
            r"\bdisregard\s+(?:the\s+)?(?:above|prior|previous|preceding)\b", re.IGNORECASE
        ),
        description="Variant of role-override using 'disregard'.",
    ),
    InjectionPattern(
        name="forget_everything",
        category="role_override",
        severity="high",
        regex=re.compile(
            r"\bforget\s+(?:everything|all)\s+(?:you(?:'ve|\s+have)\s+been\s+told|prior|previous)\b",
            re.IGNORECASE,
        ),
        description="Memory-wipe role override.",
    ),
    InjectionPattern(
        name="system_prompt_mimicry",
        category="role_override",
        severity="high",
        regex=re.compile(
            r"(?:^|\n)\s*(?:system\s*:\s*$|\[SYSTEM\]|<\s*system\s*>)",
            re.IGNORECASE | re.MULTILINE,
        ),
        description="Text impersonates a system-prompt delimiter.",
    ),
    InjectionPattern(
        name="new_instructions_block",
        category="role_override",
        severity="medium",
        regex=re.compile(
            r"(?:^|\n)\s*(?:new|updated|revised)\s+instructions?\s*:\s*\n", re.IGNORECASE
        ),
        description="Tries to declare a new instruction block.",
    ),
    InjectionPattern(
        name="developer_or_dan_mode",
        category="role_override",
        severity="high",
        regex=re.compile(
            r"\b(?:developer\s+mode|DAN\s+mode|jailbroken|do\s+anything\s+now|unfiltered\s+mode)\b",
            re.IGNORECASE,
        ),
        description="Known persona-jailbreak names.",
    ),
    InjectionPattern(
        name="you_are_now_persona",
        category="role_override",
        severity="medium",
        regex=re.compile(
            r"\byou\s+are\s+now\s+(?:[A-Z]\w+|an?\s+(?:unrestricted|unfiltered|jailbroken|evil|malicious|admin|root))\b",
            re.IGNORECASE,
        ),
        description="Persona swap attempt.",
    ),
]


TOOL_EXFIL_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        name="execute_following_command",
        category="tool_exfil",
        severity="high",
        regex=re.compile(
            r"\b(?:execute|run|invoke|call)\s+(?:the\s+|this\s+)?(?:following|below|next)\s+"
            r"(?:command|code|script|tool|function)\b",
            re.IGNORECASE,
        ),
        description="Instructs the agent to execute attacker-supplied content.",
    ),
    InjectionPattern(
        name="use_shell_to",
        category="tool_exfil",
        severity="medium",
        regex=re.compile(
            r"\buse\s+(?:the\s+)?(?:bash|shell|terminal|command\s+line)\s+to\b",
            re.IGNORECASE,
        ),
        description="Tells the agent to use a shell.",
    ),
    InjectionPattern(
        name="curl_pipe_shell",
        category="tool_exfil",
        severity="critical",
        regex=re.compile(r"curl\s+[^\n]*\|\s*(?:sh|bash|zsh)\b", re.IGNORECASE),
        description="curl|sh remote-execution pattern.",
    ),
    InjectionPattern(
        name="exfil_credentials",
        category="tool_exfil",
        severity="critical",
        regex=re.compile(
            r"\b(?:send|exfiltrate|post|upload|transmit|leak|share)\b[^\n]{0,80}"
            r"\b(?:api[\s_-]?keys?|tokens?|credentials?|secrets?|passwords?|\.env|ssh\s+keys?)\b",
            re.IGNORECASE,
        ),
        description="Asks the agent to exfiltrate secrets.",
    ),
    InjectionPattern(
        name="delete_all_files",
        category="tool_exfil",
        severity="critical",
        regex=re.compile(
            r"\b(?:delete|remove|wipe|erase|destroy)\s+(?:all|every|the)\s+"
            r"(?:files?|data|directories|folders|repos?)\b",
            re.IGNORECASE,
        ),
        description="Asks the agent to perform destructive action.",
    ),
]


HTML_COMMENT_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        name="html_comment_imperative",
        category="html_comment",
        severity="medium",
        regex=re.compile(
            r"<!--[^>]*?\b(?:ignore|disregard|forget|execute|run|delete|exfiltrate|send|reveal)\b[^>]*?-->",
            re.IGNORECASE,
        ),
        description="HTML comment contains imperative instruction.",
    ),
    InjectionPattern(
        name="markdown_html_hidden_directive",
        category="html_comment",
        severity="medium",
        regex=re.compile(
            r"\[//\]:\s*#\s*\([^)]*\b(?:ignore|disregard|execute|delete|exfiltrate|reveal)\b[^)]*\)",
            re.IGNORECASE,
        ),
        description="Markdown-style hidden directive.",
    ),
]


@dataclass(frozen=True)
class HiddenUnicodeRange:
    name: str
    severity: InjectionSeverity
    test: Callable[[int], bool]


HIDDEN_UNICODE_RANGES: list[HiddenUnicodeRange] = [
    HiddenUnicodeRange(
        name="tag_characters",
        severity="critical",
        test=lambda cp: 0xE0000 <= cp <= 0xE007F,
    ),
    HiddenUnicodeRange(
        name="bidi_override",
        severity="critical",
        test=lambda cp: cp in (0x202E, 0x202D, 0x2066, 0x2067),
    ),
    HiddenUnicodeRange(
        name="zero_width_in_word",
        severity="high",
        test=lambda cp: cp in (0x200B, 0x200C, 0x200D, 0xFEFF),
    ),
]


ALL_TEXT_PATTERNS: list[InjectionPattern] = [
    *ROLE_OVERRIDE_PATTERNS,
    *TOOL_EXFIL_PATTERNS,
    *HTML_COMMENT_PATTERNS,
]
