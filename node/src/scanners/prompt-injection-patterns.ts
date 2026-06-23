/**
 * Prompt-injection detection patterns.
 *
 * EXPERIMENTAL — see docs/research/prompt-injection-detector.md.
 * Pattern-based, English-only, trivially bypassable by paraphrase. We accept
 * this in exchange for zero-dependency, deterministic behavior. Pair with a
 * model-based judge for production deployments.
 */

export type InjectionCategory =
  | "role_override"
  | "tool_exfil"
  | "hidden_unicode"
  | "html_comment"
  | "encoded_payload";

export type InjectionSeverity = "low" | "medium" | "high" | "critical";

export interface InjectionPattern {
  name: string;
  category: InjectionCategory;
  severity: InjectionSeverity;
  regex: RegExp;
  description: string;
}

export const ROLE_OVERRIDE_PATTERNS: InjectionPattern[] = [
  {
    name: "ignore_previous_instructions",
    category: "role_override",
    severity: "high",
    regex: /\bignore(?:\s+(?:all|any|the))?\s+(?:previous|prior|above|preceding)\s+(?:instructions?|rules?|directives?|prompts?|messages?)\b/i,
    description: "Classic 'ignore previous instructions' jailbreak phrasing.",
  },
  {
    name: "disregard_above",
    category: "role_override",
    severity: "high",
    regex: /\bdisregard\s+(?:the\s+)?(?:above|prior|previous|preceding)\b/i,
    description: "Variant of role-override using 'disregard'.",
  },
  {
    name: "forget_everything",
    category: "role_override",
    severity: "high",
    regex: /\bforget\s+(?:everything|all)\s+(?:you(?:'ve|\s+have)\s+been\s+told|prior|previous)\b/i,
    description: "Memory-wipe role override.",
  },
  {
    name: "system_prompt_mimicry",
    category: "role_override",
    severity: "high",
    // Match a line that *opens* with system: / [SYSTEM] / <system> as if it
    // were a real system delimiter. Anchored to start-of-line.
    regex: /(?:^|\n)\s*(?:system\s*:\s*$|\[SYSTEM\]|<\s*system\s*>)/im,
    description: "Text impersonates a system-prompt delimiter.",
  },
  {
    name: "new_instructions_block",
    category: "role_override",
    severity: "medium",
    regex: /(?:^|\n)\s*(?:new|updated|revised)\s+instructions?\s*:\s*\n/i,
    description: "Tries to declare a new instruction block.",
  },
  {
    name: "developer_or_dan_mode",
    category: "role_override",
    severity: "high",
    regex: /\b(?:developer\s+mode|DAN\s+mode|jailbroken|do\s+anything\s+now|unfiltered\s+mode)\b/i,
    description: "Known persona-jailbreak names.",
  },
  {
    name: "you_are_now_persona",
    category: "role_override",
    severity: "medium",
    // "you are now X" where X looks like a persona/role-shift, not benign.
    regex: /\byou\s+are\s+now\s+(?:[A-Z]\w+|an?\s+(?:unrestricted|unfiltered|jailbroken|evil|malicious|admin|root))\b/i,
    description: "Persona swap attempt.",
  },
];

export const TOOL_EXFIL_PATTERNS: InjectionPattern[] = [
  {
    name: "execute_following_command",
    category: "tool_exfil",
    severity: "high",
    regex: /\b(?:execute|run|invoke|call)\s+(?:the\s+|this\s+)?(?:following|below|next)\s+(?:command|code|script|tool|function)\b/i,
    description: "Instructs the agent to execute attacker-supplied content.",
  },
  {
    name: "use_shell_to",
    category: "tool_exfil",
    severity: "medium",
    regex: /\buse\s+(?:the\s+)?(?:bash|shell|terminal|command\s+line)\s+to\b/i,
    description: "Tells the agent to use a shell.",
  },
  {
    name: "curl_pipe_shell",
    category: "tool_exfil",
    severity: "critical",
    regex: /curl\s+[^\n]*\|\s*(?:sh|bash|zsh)\b/i,
    description: "curl|sh remote-execution pattern.",
  },
  {
    name: "exfil_credentials",
    category: "tool_exfil",
    severity: "critical",
    regex: /\b(?:send|exfiltrate|post|upload|transmit|leak|share)\b[^\n]{0,80}\b(?:api[\s_-]?keys?|tokens?|credentials?|secrets?|passwords?|\.env|ssh\s+keys?)\b/i,
    description: "Asks the agent to exfiltrate secrets.",
  },
  {
    name: "delete_all_files",
    category: "tool_exfil",
    severity: "critical",
    regex: /\b(?:delete|remove|wipe|erase|destroy)\s+(?:all|every|the)\s+(?:files?|data|directories|folders|repos?)\b/i,
    description: "Asks the agent to perform destructive action.",
  },
];

export const HTML_COMMENT_PATTERNS: InjectionPattern[] = [
  {
    name: "html_comment_imperative",
    category: "html_comment",
    severity: "medium",
    // HTML comment containing an imperative verb suggestive of injection.
    regex: /<!--[^>]*?\b(?:ignore|disregard|forget|execute|run|delete|exfiltrate|send|reveal)\b[^>]*?-->/i,
    description: "HTML comment contains imperative instruction.",
  },
  {
    name: "markdown_html_hidden_directive",
    category: "html_comment",
    severity: "medium",
    // [//]: # (...) markdown-comment style with imperative
    regex: /\[\/\/\]:\s*#\s*\([^)]*\b(?:ignore|disregard|execute|delete|exfiltrate|reveal)\b[^)]*\)/i,
    description: "Markdown-style hidden directive.",
  },
];

/**
 * Hidden-unicode detection runs as code, not regex (cleaner for
 * codepoint-class checks). We export ranges here for parity with Python.
 */
export const HIDDEN_UNICODE_RANGES: Array<{ name: string; test: (cp: number) => boolean; severity: InjectionSeverity }> = [
  { name: "tag_characters", severity: "critical", test: (cp) => cp >= 0xe0000 && cp <= 0xe007f },
  { name: "bidi_override", severity: "critical", test: (cp) => cp === 0x202e || cp === 0x202d || cp === 0x2066 || cp === 0x2067 },
  // Zero-width chars are flagged ONLY when embedded in a word (not at edges
  // of an emoji ZWJ sequence). Detector handles that contextually.
  { name: "zero_width_in_word", severity: "high", test: (cp) => cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff },
];

export const ALL_TEXT_PATTERNS: InjectionPattern[] = [
  ...ROLE_OVERRIDE_PATTERNS,
  ...TOOL_EXFIL_PATTERNS,
  ...HTML_COMMENT_PATTERNS,
];
