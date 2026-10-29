/**
 * Leads for `rafter gates`: lines worth a closer look that no gate name
 * points to. Each lead is a question for the reader, not a finding. Rules are
 * syntactic and per-language: TLS verification turned off, client
 * certificates accepted unverified, insecure defaults, security-named
 * settings that are declared but never read, bodies read with no size limit,
 * limits set to "unlimited", and prefix/suffix/substring matching on hosts,
 * origins, URLs, paths and token claims.
 *
 * Keep in step with python/rafter_cli/scanners/gate_leads.py. Both runtimes
 * must produce identical output for the same tree (see CLI_SPEC.md).
 */

export interface Lead {
  file: string;
  line: number;
  rule: string;
  weight: number;
  question: string;
  snippet: string;
}

interface Candidate {
  name: string;
  file: string;
  line: number;
  weight: number;
  snippet: string;
}

export interface LeadState {
  leads: Lead[];
  candidates: Candidate[];
  files: { rel: string; lines: string[] }[];
}

export function newLeadState(): LeadState {
  return { leads: [], candidates: [], files: [] };
}

const MAX_SNIPPET = 90;
const MAX_LINE = 400;
/** Leads of one rule kept per file; a router full of prefix checks is one place to look, not twenty. */
const MAX_PER_FILE_RULE = 3;
const MAX_CONFIG_UNREAD = 10;
const MAX_CANDIDATES = 2000;
export const MAX_LEADS_JSON = 200;

function snippetOf(line: string): string {
  const s = line.trim();
  return s.length > MAX_SNIPPET ? s.slice(0, MAX_SNIPPET - 3) + "..." : s;
}

// ── Code views ───────────────────────────────────────────────────────

/** Replace string literals with "" and drop line comments. */
function codeOf(line: string, lang: string): string {
  let s = line.replace(/"(\\.|[^"\\])*"|'(\\.|[^'\\])*'|`(\\.|[^`\\])*`/g, '""');
  if (lang === "python" || lang === "ruby") s = s.replace(/#.*$/, "");
  else s = s.replace(/\/\/.*$/, "");
  return s;
}

/**
 * Python: blank the inside of triple-quoted strings (docstrings), keeping
 * line numbers, so example code in a docstring is neither a definition nor
 * a lead. Text outside the quotes on an opening or closing line is kept.
 */
export function blankTripleQuoted(lines: string[]): string[] {
  const out: string[] = [];
  let open = "";
  for (const line of lines) {
    // A line that starts inside a string keeps its indentation, so indentation-based bodies still close where they did.
    let kept = open ? line.slice(0, line.length - line.trimStart().length) : "";
    let i = 0;
    while (i <= line.length) {
      if (open) {
        const j = line.indexOf(open, i);
        if (j < 0) break;
        kept += '""';
        i = j + 3;
        open = "";
      } else {
        const a = line.indexOf('"""', i);
        const b = line.indexOf("'''", i);
        let j = -1;
        if (a >= 0 && (b < 0 || a < b)) { j = a; open = '"""'; }
        else if (b >= 0) { j = b; open = "'''"; }
        if (j < 0) { kept += line.slice(i); break; }
        kept += line.slice(i, j);
        i = j + 3;
      }
    }
    out.push(kept);
  }
  return out;
}

// ── Names ────────────────────────────────────────────────────────────

const WORD_RE = /[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+/g;

function words(name: string): string[] {
  const ws: string[] = [];
  for (const part of name.split(/[^A-Za-z0-9]+/)) {
    for (const w of part.match(WORD_RE) ?? []) ws.push(w.toLowerCase());
  }
  return ws;
}

/** Word prefixes that make a setting security-named. */
const SECURITY_SETTING_PREFIXES = [
  "verif", "secur", "insecur", "strict", "requir", "allow", "deny", "limit", "max", "timeout",
  "auth", "tls", "ssl", "csrf", "xsrf", "origin", "trust",
];

function isSecurityName(name: string): boolean {
  if (name.length < 4) return false;
  return words(name).some((w) =>
    SECURITY_SETTING_PREFIXES.some((p) => w.startsWith(p)) &&
    !(w.startsWith("author") && !w.startsWith("authoriz") && !w.startsWith("authoris")));
}

/** Identifier classes for loose matching. */
const MATCH_CLASSES: [string, Set<string>][] = [
  ["host", new Set(["host", "hostname", "origin", "domain", "referer", "referrer"])],
  ["url", new Set(["redirect", "url", "uri"])],
  ["claim", new Set(["scope", "audience", "aud", "issuer", "iss", "role", "subject"])],
  ["path", new Set(["path"])],
];

/** The class of an identifier, or "" when it names no security value or names a collection. */
function matchClass(ident: string): string {
  const ws = words(ident);
  if (ws.length === 0) return "";
  const last = ws[ws.length - 1];
  for (const [cls, set] of MATCH_CLASSES) {
    if (!set.has(last)) continue;
    return cls;
  }
  return "";
}

/** The last identifier in an expression: `r.URL.Path` → `Path`, `u.Hostname()` → `Hostname`. */
function lastIdent(expr: string): string {
  const m = expr.match(/([A-Za-z_$][\w$]*)\s*(\(\s*\))?\s*$/);
  return m ? m[1] : "";
}

/**
 * A passing example with the real needle from the line (has letters, so it
 * reads as an actual value rather than a bare symbol): names the specific
 * value that would slip past the check at this line.
 */
function namedPassPhrase(kind: string, cls: string, n: string): string | null {
  switch (`${kind}:${cls}`) {
    case "prefix:host": return `a value starting with ${n}, e.g. ${n}.evil.com, also passes`;
    case "prefix:url": return `a value starting with ${n}, e.g. ${n}.evil.com or ${n}@evil.com, also passes`;
    case "prefix:claim": return `a value starting with ${n}, e.g. ${n}-x, also passes`;
    case "prefix:path": return `a value starting with ${n}, e.g. ${n}-sibling or ${n}/../secret, also passes`;
    case "suffix:host": return `a value ending in ${n} with no dot boundary, e.g. evil${n}, also passes`;
    case "suffix:url": return `a value ending in ${n}, e.g. https://evil.com/?x=${n}, also passes`;
    case "suffix:claim": return `a value merely ending in ${n} also passes`;
    case "suffix:path": return `a value merely ending in ${n}, from another directory, also passes`;
    case "contains:host": return `a value merely containing ${n}, e.g. attacker.${n}.evil.com, also passes`;
    case "contains:url": return `a value merely containing ${n}, e.g. https://evil.com/?r=${n}, also passes`;
    case "contains:claim": return `a value merely containing ${n} also passes`;
    case "contains:path": return `a value merely containing ${n} also passes`;
    default: return null; // case folding: no single value to name
  }
}

/** Fallback when the needle is not a literal, or is a bare symbol with no letters (e.g. "/"). */
const GENERIC_PASS_PHRASE: Record<string, string> = {
  "prefix:host": "a value like example.com.evil.com also passes",
  "prefix:url": "a value like //evil.com also passes",
  "prefix:claim": "a value like admin-x also passes",
  "prefix:path": "a value like /allowed/../secret also passes",
  "suffix:host": "a value like evilexample.com, with no dot boundary, also passes",
  "suffix:url": "a value like https://evil.com/?x=example.com also passes",
  "suffix:claim": "a value that merely ends with the expected one also passes",
  "suffix:path": "a value from another directory can still match the suffix",
  "contains:host": "a value like attacker.example.evil.com also passes",
  "contains:url": "a value like https://evil.com/?r=example.com also passes",
  "contains:claim": "any value merely containing the expected one also passes",
  "contains:path": "any path merely containing the allowed part also passes",
  "fold:claim": "a differently-cased value also passes",
  "fold:path": "a differently-cased value also passes",
  "fold:url": "a differently-cased value also passes",
};

/** The passing-example phrase for this kind/class, grounded in the real needle when it names a concrete value. */
function loosePhrase(kind: string, cls: string, lit: string | null): string | null {
  if (lit && /[A-Za-z]/.test(lit)) {
    const dyn = namedPassPhrase(kind, cls, lit);
    if (dyn) return dyn;
  }
  return GENERIC_PASS_PHRASE[`${kind}:${cls}`] ?? null;
}

const LOOSE_WEIGHT: Record<string, number> = { host: 4, url: 4, claim: 4, path: 2 };

const OP_KIND: Record<string, string> = {
  HasPrefix: "prefix", HasSuffix: "suffix", Contains: "contains", EqualFold: "fold",
  startswith: "prefix", endswith: "suffix", in: "contains",
  startsWith: "prefix", endsWith: "suffix", includes: "contains", indexOf: "contains",
  contains: "contains", equalsIgnoreCase: "fold",
  "start_with?": "prefix", "end_with?": "suffix", "include?": "contains",
};

/** A literal that is only a scheme ("https://"): a scheme check, not a trust decision. */
const SCHEME_LITERAL = /["'`](https?|wss?|file|ftp|data|javascript|mailto):(\/\/)?["'`]/i;

// ── Per-line rules ───────────────────────────────────────────────────

interface Hit {
  rule: string;
  weight: number;
  question: string;
}

const GO_LOOSE = /\b(?:strings|bytes)\.(HasPrefix|HasSuffix|Contains|EqualFold)\(\s*([^,]+?)\s*,\s*([^)]*)/g;
const PY_LOOSE = /([A-Za-z_][\w.]*(?:\(\s*\))?)\.(startswith|endswith)\(([^)]*)/g;
const PY_IN = /(?:^|[\s(,=])(""|[A-Za-z_][\w.]*)\s+(?:not\s+)?in\s+([A-Za-z_][\w.]*(?:\(\s*\))?)(?=\s*(?:$|[:),]|and\b|or\b|if\b|else\b))/g;
const JS_LOOSE = /([A-Za-z_$][\w$.]*(?:\(\s*\))?)\.(startsWith|endsWith|includes|indexOf)\(([^)]*)/g;
const JAVA_LOOSE = /([A-Za-z_$][\w$.]*(?:\(\s*\))?)\.(startsWith|endsWith|contains|equalsIgnoreCase)\(([^)]*)/g;
const RB_LOOSE = /([A-Za-z_][\w.]*)\.(start_with\?|end_with\?|include\?)\(([^)]*)/g;

const RAW_LITERAL = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|`((?:\\.|[^`\\])*)`/g;

function rawLiterals(raw: string): string[] {
  const out: string[] = [];
  RAW_LITERAL.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = RAW_LITERAL.exec(raw)) !== null) out.push(m[1] ?? m[2] ?? m[3] ?? "");
  return out;
}

/**
 * A literal needle with no letters (`"/"`, `"*"`, `":"`) tests for a
 * character, not a trusted value; a suffix like `".py"` on a path tests a
 * file extension. Neither is a trust decision. The raw line's literals
 * stand in for the needle's.
 */
function literalNoise(kind: string, cls: string, needle: string, raw: string, litIndex: number): boolean {
  // A redirect that only has to start with "/" also accepts //evil.com.
  if (needle.trim() !== '""' || (kind === "prefix" && cls === "url")) return false;
  // The code view replaced each literal with "", in order, so the count of "" before the needle indexes the raw literals.
  const all = rawLiterals(raw);
  const lits = litIndex >= 0 && litIndex < all.length ? [all[litIndex]] : all;
  if (lits.every((l) => !/[A-Za-z]/.test(l.replace(/\\./g, "")))) return true;
  return kind === "suffix" && cls === "path" && lits.every((l) => /^\.[A-Za-z0-9]{1,5}$/.test(l));
}

/** How many literals precede offset `pos` of the code view (-1: unknown). */
function literalIndex(code: string, pos: number): number {
  return pos < 0 ? -1 : code.slice(0, pos).split('""').length - 1;
}

/** The raw literal text the needle stands for, or null when it is not a literal at all. */
function rawNeedle(needle: string, raw: string, litIndex: number): string | null {
  if (needle.trim() !== '""') return null;
  const lits = rawLiterals(raw);
  return litIndex >= 0 && litIndex < lits.length ? lits[litIndex] : null;
}

function looseHit(op: string, ident: string, needle: string, raw: string, litIndex: number): Hit | null {
  const cls = matchClass(ident);
  if (!cls) return null;
  const kind = OP_KIND[op];
  if (literalNoise(kind, cls, needle, raw, litIndex)) return null;
  const phrase = loosePhrase(kind, cls, rawNeedle(needle, raw, litIndex));
  if (!phrase) return null; // case folding a host, origin or domain is correct
  const opLabel = op === "in" ? "`in`" : `${op}`;
  return { rule: "loose-match", weight: LOOSE_WEIGHT[cls], question: `${opLabel} on ${ident}: ${phrase}; is that intended?` };
}

function looseMatches(lang: string, code: string, raw: string): Hit[] {
  const hits: Hit[] = [];
  if (SCHEME_LITERAL.test(raw)) return hits;
  let m: RegExpExecArray | null;
  if (lang === "go") {
    GO_LOOSE.lastIndex = 0;
    while ((m = GO_LOOSE.exec(code)) !== null) {
      let ident = lastIdent(m[2]);
      let needle = m[3];
      let pos = m.index + m[0].length - m[3].length;
      if (m[1] === "EqualFold" && !matchClass(ident)) { ident = lastIdent(m[3]); needle = m[2]; pos = -1; }
      const h = looseHit(m[1], ident, needle, raw, literalIndex(code, pos));
      if (h) hits.push(h);
    }
    return hits;
  }
  if (lang === "python") {
    PY_IN.lastIndex = 0;
    // `for x in path` iterates; it does not match.
    while (!/\bfor\b/.test(code) && (m = PY_IN.exec(code)) !== null) {
      const h = looseHit("in", lastIdent(m[2]), m[1], raw, literalIndex(code, m.index + m[0].indexOf(m[1])));
      if (h) hits.push(h);
    }
  }
  const re = lang === "python" ? PY_LOOSE : lang === "java" ? JAVA_LOOSE : lang === "ruby" ? RB_LOOSE
    : lang === "javascript" || lang === "typescript" ? JS_LOOSE : null;
  if (!re) return hits;
  re.lastIndex = 0;
  while ((m = re.exec(code)) !== null) {
    const h = looseHit(m[2], lastIdent(m[1]), m[3], raw, literalIndex(code, m.index + m[0].length - m[3].length));
    if (h) hits.push(h);
  }
  return hits;
}

const Q_TLS_OFF = "certificate verification is off here, so a network attacker can impersonate the peer; is that intended?";

interface LineRule {
  langs: string[];
  re: RegExp;
  rule: string;
  weight: number;
  /** Question, given the regex match. */
  q: (m: RegExpMatchArray) => string;
  /** Match against the raw line instead of the code view. */
  raw?: boolean;
}

const NEG_SETTING = "(?:[A-Za-z_]\\w*)?(?:[Ii]nsecure|[Ss]kip_?[Vv]erify|SKIP_VERIFY|[Nn]o_?[Vv]erify|NO_VERIFY|[Dd]isable_?(?:[Tt]ls|TLS|[Ss]sl|SSL)|DISABLE_(?:TLS|SSL)|INSECURE)\\w*";

const LINE_RULES: LineRule[] = [
  // TLS verification turned off by a literal.
  { langs: ["go"], re: /\bInsecureSkipVerify\s*(?::|=)\s*true\b/, rule: "tls-verify-off", weight: 5, q: () => `InsecureSkipVerify is true: ${Q_TLS_OFF}` },
  { langs: ["python"], re: /\b(verify|verify_ssl|ssl_verify|verify_certs|verify_tls|tls_verify|validate_certs)\s*=\s*False\b/, rule: "tls-verify-off", weight: 5, q: (m) => `${m[1]}=False: ${Q_TLS_OFF}` },
  { langs: ["python"], re: /\b(CERT_NONE|_create_unverified_context)\b/, rule: "tls-verify-off", weight: 5, q: (m) => `${m[1]}: ${Q_TLS_OFF}` },
  { langs: ["python"], re: /\bcheck_hostname\s*=\s*False\b/, rule: "tls-verify-off", weight: 5, q: () => "check_hostname=False: any valid certificate is accepted for any host; is that intended?" },
  { langs: ["javascript", "typescript"], re: /\b(rejectUnauthorized|strictSSL)\s*:\s*false\b/, rule: "tls-verify-off", weight: 5, q: (m) => `${m[1]}: false: ${Q_TLS_OFF}` },
  { langs: ["javascript", "typescript"], re: /NODE_TLS_REJECT_UNAUTHORIZED\D*["'`]?0["'`]?/, rule: "tls-verify-off", weight: 5, raw: true, q: () => `NODE_TLS_REJECT_UNAUTHORIZED=0: ${Q_TLS_OFF}` },
  { langs: ["java"], re: /\b(NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy|InsecureTrustManagerFactory)\b/, rule: "tls-verify-off", weight: 5, q: (m) => `${m[1]}: ${Q_TLS_OFF}` },
  { langs: ["ruby"], re: /\bVERIFY_NONE\b/, rule: "tls-verify-off", weight: 5, q: () => `VERIFY_NONE: ${Q_TLS_OFF}` },
  // TLS verification taken from a value: where does it come from?
  { langs: ["go"], re: /\bInsecureSkipVerify\s*(?::|=)\s*(?!true\b|false\b)(!?[A-Za-z_][\w.]*(?:\(\s*\))?)/, rule: "tls-verify-config", weight: 4, q: (m) => `InsecureSkipVerify is set from ${m[1]} here, not fixed, so this path can disable verification; is that intended?` },
  { langs: ["javascript", "typescript"], re: /\brejectUnauthorized\s*:\s*(?!true\b|false\b)(!?[A-Za-z_$][\w$.]*)/, rule: "tls-verify-config", weight: 4, q: (m) => `rejectUnauthorized is set from ${m[1]} here, not fixed, so this path can disable verification; is that intended?` },
  // A negatively named option ("insecure", "skip verify") that defaults to on.
  { langs: ["go"], re: /\bflag\.Bool(?:Var)?\([^)]*?["'`]([\w-]*(?:insecure|skip-verify|skip_verify|no-verify|disable-tls|disable-ssl)[\w-]*)["'`]\s*,\s*true\b/, rule: "insecure-default", weight: 4, raw: true, q: (m) => `flag ${m[1]} defaults to true: every deployment that does not override it skips verification; is that intended?` },
  { langs: ["go", "python", "javascript", "typescript", "ruby"], re: new RegExp(`\\b(${NEG_SETTING})\\s*(?::\\s*bool\\s*)?(?:=|:)\\s*(true|True)\\b`), rule: "insecure-default", weight: 4, q: (m) => `${m[1]} is ${m[2]}: if that is the default, every deployment that does not override it skips the check; is that intended?` },
];

/** Lines scanned on each side of a ClientAuth line for a configured CA pool: the same window used elsewhere for "nearby" context, not a true struct-literal or function boundary. */
const CLIENT_CA_WINDOW = 15;
const GO_CLIENT_AUTH = /\bClientAuth\s*(?::|=)\s*tls\.(RequestClientCert|RequireAnyClientCert|VerifyClientCertIfGiven)\b/;
const GO_CLIENT_CA_SET = /\bClientCAs\s*(?::|=)/;

/** Client certificates requested but not verified: weight and wording depend on whether a CA pool is configured nearby. */
function clientCertHit(lang: string, code: string[], i: number): Hit | null {
  if (lang !== "go") return null;
  const m = code[i].match(GO_CLIENT_AUTH);
  if (!m) return null;
  const mode = m[1];
  const given = mode === "VerifyClientCertIfGiven";
  let hasCA = false;
  for (let j = Math.max(0, i - CLIENT_CA_WINDOW); j <= Math.min(code.length - 1, i + CLIENT_CA_WINDOW); j++) {
    if (GO_CLIENT_CA_SET.test(code[j])) { hasCA = true; break; }
  }
  if (hasCA) {
    const risk = given ? "lets a client skip presenting one" : "does not verify certificates against them";
    return { rule: "client-cert-unverified", weight: 6, question: `client CAs are configured here, but ClientAuth=${mode} ${risk}; is that intended?` };
  }
  const risk = given ? "lets a client connect with no certificate at all" : "accepts a client certificate without verifying it against any CA";
  return { rule: "client-cert-unverified", weight: 5, question: `ClientAuth=${mode} ${risk}; is that intended?` };
}

/**
 * A limit set to a value that usually means "unlimited", where it is a
 * setting rather than a local: a key (`maxSize: -1`), a keyword default
 * (`max_size=-1`), an attribute (`cfg.MaxSize = -1`) or a constant
 * (`MAX_SIZE = -1`). Not a Go `:=` local.
 */
const LIMIT_SET = /(^|[\s(,{.])([A-Za-z_]\w*)\s*(:=|=(?!=)|:)\s*(-1|Infinity|Number\.POSITIVE_INFINITY|math\.Inf\(1\)|float\(""\)|math\.inf)(?![\w.])/;

function limitHit(code: string): Hit | null {
  const m = code.match(LIMIT_SET);
  if (!m) return null;
  const name = m[2];
  if (!words(name).some((w) => w === "limit" || w === "max" || w.startsWith("maxi"))) return null;
  const setting = m[3] === ":" || m[1] === "(" || m[1] === "," || m[1] === "." || /^[A-Z][A-Z0-9_]*$/.test(name);
  if (!setting) return null;
  const v = m[4] === 'float("")' ? "infinite" : `${m[4]} (unlimited)`;
  return { rule: "limit-disabled", weight: 2, question: `${name} is ${v}: a client can exhaust memory or time through it; is that intended?` };
}

/** Go: io.ReadAll / ioutil.ReadAll / json.NewDecoder on a request or response body. */
const GO_BODY_READ = /\b(io|ioutil)\.ReadAll\(\s*([A-Za-z_][\w.]*\.)?(Body|body)\s*\)|\bjson\.NewDecoder\(\s*([A-Za-z_][\w.]*\.)?Body\s*\)/;
const GO_LIMIT_NEAR = /LimitReader|MaxBytesReader|LimitedReader|MaxBytes/;
/** Python: .read() with no size on a request, stream or socket file. */
const PY_BODY_READ = /\b([A-Za-z_][\w.]*\.)?(request|req|rfile|stream|body|wsgi_input|input_stream)\.read\(\s*\)/;
const JS_DATA_EVENT = /\.on\(\s*""\s*,/;
const JS_DATA_RAW = /\.on\(\s*["'`]data["'`]/;
const JS_SIZE_NEAR = /length|size|limit|max|byteLength/i;
const LIMIT_WINDOW = 15;

function bodyReadHit(lang: string, code: string[], raw: string[], i: number): Hit | null {
  const line = code[i];
  if (lang === "go") {
    const m = line.match(GO_BODY_READ);
    if (!m) return null;
    for (let j = Math.max(0, i - LIMIT_WINDOW); j <= i; j++) if (GO_LIMIT_NEAR.test(code[j])) return null;
    const recv = m[1] ? m[2] ?? "" : m[4] ?? "";
    const expr = m[1] ? `${m[1]}.ReadAll(${recv}${m[3]})` : `json.NewDecoder(${recv}Body)`;
    // A request body comes from the client; a response body from a server this code chose to call.
    const isRequest = /^(r|req|request)\.$/.test(recv);
    const weight = isRequest ? 3 : 2;
    const who = isRequest ? "a client" : "the called server";
    return { rule: "unbounded-read", weight, question: `${expr} reads the whole body with no size limit: ${who} can send a body of any size here; is that intended?` };
  }
  if (lang === "python") {
    const m = line.match(PY_BODY_READ);
    if (!m) return null;
    return { rule: "unbounded-read", weight: 3, question: `${m[1] ?? ""}${m[2]}.read() has no size limit: a client can send a body of any size here; is that intended?` };
  }
  if (lang === "javascript" || lang === "typescript") {
    if (!JS_DATA_EVENT.test(line) || !JS_DATA_RAW.test(raw[i])) return null;
    for (let j = i; j < Math.min(code.length, i + 8); j++) if (JS_SIZE_NEAR.test(code[j])) return null;
    return { rule: "unbounded-read", weight: 3, question: "chunks from a 'data' event are collected with no size check: a client can send a body of any size here; is that intended?" };
  }
  return null;
}

// ── Declarations of security-named settings ──────────────────────────

const GO_STRUCT_OPEN = /^\s*type\s+[A-Za-z_]\w*\s+struct\s*\{\s*$/;
const GO_FIELD = /^\s+([A-Za-z_]\w*)\s+[*\[\]]*[A-Za-z_][\w.]*(\s+"")?\s*$/;
const PY_CLASS_FIELD = /^\s+([A-Za-z_]\w*)\s*:\s*[A-Za-z_][\w\[\], .|]*(=.*)?$/;
const PY_SELF_ASSIGN = /^\s+self\.([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)/;
const PY_SETTING = /^([A-Z][A-Z0-9_]*)\s*=(?!=)/;
const TS_FIELD = /^\s+(?:readonly\s+)?([A-Za-z_]\w*)\??\s*:\s*(?:boolean|number|string|string\[\]|RegExp)\s*;?\s*$/;
const JS_THIS_ASSIGN = /^\s+this\.([A-Za-z_]\w*)\s*=(?!=)/;
const JAVA_FIELD = /^\s+(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*(?:=[^;]*)?;\s*$/;

/** Go: a positively named bool (`VerifyHostname bool`) whose zero value, false, is the insecure one. */
const GO_POSITIVE_BOOL = /^\s+([A-Za-z_]\w*)\s+bool(\s+"")?\s*$/;
const POSITIVE_WORDS = new Set(["verify", "secure", "strict", "require", "enforce", "validate", "check"]);
const NEGATING_WORDS = new Set(["insecure", "skip", "disable", "disabled", "no", "not", "allow", "ignore", "optional", "without", "unsafe", "lax"]);

function goPositiveBool(name: string): boolean {
  const ws = words(name);
  if (ws.some((w) => NEGATING_WORDS.has(w))) return false;
  if (!ws.some((w) => POSITIVE_WORDS.has(w) || w.startsWith("verif"))) return false;
  // Only checks of a peer or a protocol, not "Strict" mode of a parser.
  return ws.some((w) => ["tls", "ssl", "cert", "certs", "certificate", "certificates", "hostname", "host", "peer", "signature", "https", "verify", "verification"].includes(w));
}

// ── Scan one file ────────────────────────────────────────────────────

/**
 * Collect the leads of one file. `code` is the comment- and string-free
 * view (Python docstrings blanked), `raw` the original lines.
 */
export function scanLeads(state: LeadState, rel: string, lang: string, raw: string[], pathWeight: number): void {
  const pre = lang === "python" ? blankTripleQuoted(raw) : raw;
  const code = pre.map((l) => (l.length > MAX_LINE ? "" : codeOf(l, lang)));
  state.files.push({ rel, lines: pre });
  const perRule = new Map<string, number>();
  const bonus = pathWeight > 0 ? 1 : 0;
  const add = (i: number, h: Hit) => {
    const n = perRule.get(h.rule) ?? 0;
    if (n >= MAX_PER_FILE_RULE) return;
    perRule.set(h.rule, n + 1);
    state.leads.push({ file: rel, line: i + 1, rule: h.rule, weight: h.weight + bonus, question: h.question, snippet: snippetOf(raw[i]) });
  };
  let goStructDepth = 0;
  let pyClassIndent = -1;
  let pyBodyIndent = -1;
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (c.trim() === "") continue;
    // One lead per line: the heaviest hit, the first on a tie.
    let best = null as Hit | null;
    const offer = (h: Hit | null) => {
      if (h && (!best || h.weight > best.weight)) best = h;
    };
    for (const r of LINE_RULES) {
      if (!r.langs.includes(lang)) continue;
      const m = (r.raw ? pre[i] : c).match(r.re);
      if (m) offer({ rule: r.rule, weight: r.weight, question: r.q(m) });
    }
    offer(clientCertHit(lang, code, i));
    offer(bodyReadHit(lang, code, pre, i));
    offer(limitHit(c));
    for (const h of looseMatches(lang, c, pre[i])) offer(h);
    if (best) add(i, best);

    // Declarations.
    let decl = "";
    if (lang === "go") {
      if (goStructDepth > 0) {
        let m: RegExpMatchArray | null;
        if (goStructDepth === 1 && (m = c.match(GO_FIELD))) {
          decl = m[1];
          const pb = c.match(GO_POSITIVE_BOOL);
          if (pb && goPositiveBool(pb[1])) {
            add(i, { rule: "insecure-default", weight: 3, question: `${pb[1]} defaults to false (the zero value), so any config that does not set it skips the check; is that intended?` });
          }
        }
        for (const ch of c) {
          if (ch === "{") goStructDepth++;
          else if (ch === "}") goStructDepth--;
        }
      } else if (GO_STRUCT_OPEN.test(c)) {
        goStructDepth = 1;
      }
    } else if (lang === "python") {
      const ind = c.length - c.trimStart().length;
      if (/^\s*class\s+[A-Za-z_]\w*/.test(c)) { pyClassIndent = ind; pyBodyIndent = -1; }
      else if (pyClassIndent >= 0 && ind <= pyClassIndent) pyClassIndent = -1;
      else if (pyClassIndent >= 0 && pyBodyIndent < 0) pyBodyIndent = ind;
      let m: RegExpMatchArray | null;
      if ((m = c.match(PY_SETTING))) decl = m[1];
      else if ((m = c.match(PY_SELF_ASSIGN))) decl = m[1];
      else if (pyClassIndent >= 0 && ind === pyBodyIndent && (m = c.match(PY_CLASS_FIELD)) && !/^\s*(def|class|return|if|for|while|with|elif|else|try|except|lambda)\b/.test(c)) decl = m[1];
    } else if (lang === "typescript" || lang === "javascript") {
      let m: RegExpMatchArray | null;
      if (lang === "typescript" && (m = c.match(TS_FIELD))) decl = m[1];
      else if ((m = c.match(JS_THIS_ASSIGN))) decl = m[1];
    } else if (lang === "java") {
      const m = c.match(JAVA_FIELD);
      if (m) decl = m[1];
    }
    if (decl && isSecurityName(decl) && state.candidates.length < MAX_CANDIDATES) {
      state.candidates.push({ name: decl, file: rel, line: i + 1, weight: 3 + bonus, snippet: snippetOf(raw[i]) });
    }
  }
}

// ── Finish: settings never read, ranking, caps ───────────────────────

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** After an occurrence: an assignment or a key, so it sets the value rather than reads it. */
const SET_AFTER = /^\s*(?:=(?![=>~])|:=|:(?![:=]))/;

/**
 * The names among the candidates that are read somewhere: an occurrence
 * that is not a declaration line, not an assignment target or key
 * (`x.Name = `, `Name: `, `name=`), not an address taken to set it
 * (`&cfg.Name`), and not the right-hand side of a pass-through
 * (`self.name = name`).
 */
function readNames(state: LeadState, names: string[]): Set<string> {
  const read = new Set<string>();
  if (names.length === 0) return read;
  const declAt = new Set(state.candidates.map((c) => `${c.file}:${c.line}:${c.name}`));
  const alt = [...names].sort((a, b) => b.length - a.length || cmp(a, b)).join("|");
  const re = new RegExp(`(?<![\\w$])(${alt})(?![\\w$])`, "g");
  for (const f of state.files) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (line.length > MAX_LINE) continue;
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const name = m[1];
        if (read.has(name)) continue;
        if (declAt.has(`${f.rel}:${i + 1}:${name}`)) continue;
        const after = line.slice(m.index + name.length);
        const before = line.slice(0, m.index);
        // `x.name:` ends a Python condition; only a bare `name:` is a key or annotation.
        if (SET_AFTER.test(after) && !(before.endsWith(".") && /^\s*:(?![:=])\s*(#.*)?$/.test(after))) continue;
        if (/&[\w.]*$/.test(before)) continue;
        if (new RegExp(`\\.${name}\\s*=\\s*$`).test(before)) continue;
        read.add(name);
      }
    }
  }
  return read;
}

export function finishLeads(state: LeadState): { leads: Lead[]; found: number } {
  // A name declared in several places is a common one; its reads cannot be told apart.
  // Repeated declarations in one file (`self.x = ...` in two methods) are one setting.
  const declFiles = new Map<string, Set<string>>();
  for (const c of state.candidates) {
    const s = declFiles.get(c.name) ?? new Set<string>();
    s.add(c.file);
    declFiles.set(c.name, s);
  }
  const firstDecl = new Set<string>();
  const unique = state.candidates.filter((c) => {
    if (declFiles.get(c.name)!.size !== 1 || firstDecl.has(c.name)) return false;
    firstDecl.add(c.name);
    return true;
  });
  const read = readNames(state, unique.map((c) => c.name));
  const unread = unique
    .filter((c) => !read.has(c.name))
    .sort((a, b) => b.weight - a.weight || cmp(a.file, b.file) || a.line - b.line)
    .slice(0, MAX_CONFIG_UNREAD);
  const leads = [...state.leads];
  for (const c of unread) {
    leads.push({
      file: c.file,
      line: c.line,
      rule: "config-unread",
      weight: c.weight,
      question: `${c.name} is set in config but nothing reads it: the check it names never runs.`,
      snippet: c.snippet,
    });
  }
  leads.sort((a, b) => b.weight - a.weight || cmp(a.file, b.file) || a.line - b.line || cmp(a.rule, b.rule));
  return { leads: leads.slice(0, MAX_LEADS_JSON), found: leads.length };
}
