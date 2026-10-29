"""Leads for `rafter gates`: lines worth a closer look that no gate name points to.

Each lead is a question for the reader, not a finding. Rules are syntactic
and per-language: TLS verification turned off, client certificates accepted
unverified, insecure defaults, security-named settings that are declared but
never read, bodies read with no size limit, limits set to "unlimited", and
prefix/suffix/substring matching on hosts, origins, URLs, paths and token
claims.

Keep in step with node/src/scanners/gate-leads.ts. Both runtimes must
produce identical output for the same tree (see CLI_SPEC.md).
"""
from __future__ import annotations

import re

A = re.ASCII

MAX_SNIPPET = 90
MAX_LINE = 400
# Leads of one rule kept per file; a router full of prefix checks is one place to look, not twenty.
MAX_PER_FILE_RULE = 3
MAX_CONFIG_UNREAD = 10
MAX_CANDIDATES = 2000
MAX_LEADS_JSON = 200


def new_lead_state() -> dict:
    return {"leads": [], "candidates": [], "files": []}


def _snippet(line: str) -> str:
    s = line.strip()
    return s[:MAX_SNIPPET - 3] + "..." if len(s) > MAX_SNIPPET else s


# ── Code views ───────────────────────────────────────────────────────

_STRING_RE = re.compile(r'"(\\.|[^"\\])*"|\'(\\.|[^\'\\])*\'|`(\\.|[^`\\])*`', A)
_HASH_COMMENT_RE = re.compile(r"#.*$", A)
_LINE_COMMENT_RE = re.compile(r"//.*$", A)


def _code_of(line: str, lang: str) -> str:
    """Replace string literals with "" and drop line comments."""
    s = _STRING_RE.sub('""', line)
    if lang in ("python", "ruby"):
        return _HASH_COMMENT_RE.sub("", s, count=1)
    return _LINE_COMMENT_RE.sub("", s, count=1)


def blank_triple_quoted(lines: list[str]) -> list[str]:
    """Python: blank the inside of triple-quoted strings (docstrings), keeping line numbers.

    Example code in a docstring is then neither a definition nor a lead.
    Text outside the quotes on an opening or closing line is kept.
    """
    out: list[str] = []
    open_q = ""
    for line in lines:
        # A line that starts inside a string keeps its indentation, so
        # indentation-based bodies still close where they did.
        kept = line[:len(line) - len(line.lstrip())] if open_q else ""
        i = 0
        while i <= len(line):
            if open_q:
                j = line.find(open_q, i)
                if j < 0:
                    break
                kept += '""'
                i = j + 3
                open_q = ""
            else:
                a = line.find('"""', i)
                b = line.find("'''", i)
                j = -1
                if a >= 0 and (b < 0 or a < b):
                    j = a
                    open_q = '"""'
                elif b >= 0:
                    j = b
                    open_q = "'''"
                if j < 0:
                    kept += line[i:]
                    break
                kept += line[i:j]
                i = j + 3
        out.append(kept)
    return out


# ── Names ────────────────────────────────────────────────────────────

WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", A)
SPLIT_RE = re.compile(r"[^A-Za-z0-9]+", A)


def _words(name: str) -> list[str]:
    ws: list[str] = []
    for part in SPLIT_RE.split(name):
        ws.extend(w.lower() for w in WORD_RE.findall(part))
    return ws


# Word prefixes that make a setting security-named.
SECURITY_SETTING_PREFIXES = [
    "verif", "secur", "insecur", "strict", "requir", "allow", "deny", "limit", "max", "timeout",
    "auth", "tls", "ssl", "csrf", "xsrf", "origin", "trust",
]


def _is_security_name(name: str) -> bool:
    if len(name) < 4:
        return False
    return any(
        any(w.startswith(p) for p in SECURITY_SETTING_PREFIXES)
        and not (w.startswith("author") and not w.startswith("authoriz") and not w.startswith("authoris"))
        for w in _words(name)
    )


# Identifier classes for loose matching.
MATCH_CLASSES = [
    ("host", {"host", "hostname", "origin", "domain", "referer", "referrer"}),
    ("url", {"redirect", "url", "uri"}),
    ("claim", {"scope", "audience", "aud", "issuer", "iss", "role", "subject"}),
    ("path", {"path"}),
]


def _match_class(ident: str) -> str:
    """The class of an identifier, or "" when it names no security value or names a collection."""
    ws = _words(ident)
    if not ws:
        return ""
    last = ws[-1]
    for cls, names in MATCH_CLASSES:
        if last in names:
            return cls
    return ""


_LAST_IDENT_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*(\(\s*\))?\s*$", A)


def _last_ident(expr: str) -> str:
    """The last identifier in an expression: `r.URL.Path` -> `Path`, `u.Hostname()` -> `Hostname`."""
    m = _LAST_IDENT_RE.search(expr)
    return m.group(1) if m else ""


def _named_pass_phrase(kind: str, cls: str, n: str) -> str | None:
    """A passing example with the real needle from the line: names the
    specific value that would slip past the check at this line."""
    key = f"{kind}:{cls}"
    if key == "prefix:host":
        return f"a value starting with {n}, e.g. {n}.evil.com, also passes"
    if key == "prefix:url":
        return f"a value starting with {n}, e.g. {n}.evil.com or {n}@evil.com, also passes"
    if key == "prefix:claim":
        return f"a value starting with {n}, e.g. {n}-x, also passes"
    if key == "prefix:path":
        return f"a value starting with {n}, e.g. {n}-sibling or {n}/../secret, also passes"
    if key == "suffix:host":
        return f"a value ending in {n} with no dot boundary, e.g. evil{n}, also passes"
    if key == "suffix:url":
        return f"a value ending in {n}, e.g. https://evil.com/?x={n}, also passes"
    if key == "suffix:claim":
        return f"a value merely ending in {n} also passes"
    if key == "suffix:path":
        return f"a value merely ending in {n}, from another directory, also passes"
    if key == "contains:host":
        return f"a value merely containing {n}, e.g. attacker.{n}.evil.com, also passes"
    if key == "contains:url":
        return f"a value merely containing {n}, e.g. https://evil.com/?r={n}, also passes"
    if key == "contains:claim":
        return f"a value merely containing {n} also passes"
    if key == "contains:path":
        return f"a value merely containing {n} also passes"
    return None  # case folding: no single value to name


# Fallback when the needle is not a literal, or is a bare symbol with no letters (e.g. "/").
GENERIC_PASS_PHRASE = {
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
}


def _loose_phrase(kind: str, cls: str, lit: str | None) -> str | None:
    """The passing-example phrase for this kind/class, grounded in the real needle when it names a concrete value."""
    if lit and _LETTER_RE.search(lit):
        dyn = _named_pass_phrase(kind, cls, lit)
        if dyn:
            return dyn
    return GENERIC_PASS_PHRASE.get(f"{kind}:{cls}")


LOOSE_WEIGHT = {"host": 4, "url": 4, "claim": 4, "path": 2}

OP_KIND = {
    "HasPrefix": "prefix", "HasSuffix": "suffix", "Contains": "contains", "EqualFold": "fold",
    "startswith": "prefix", "endswith": "suffix", "in": "contains",
    "startsWith": "prefix", "endsWith": "suffix", "includes": "contains", "indexOf": "contains",
    "contains": "contains", "equalsIgnoreCase": "fold",
    "start_with?": "prefix", "end_with?": "suffix", "include?": "contains",
}

# A literal that is only a scheme ("https://"): a scheme check, not a trust decision.
SCHEME_LITERAL = re.compile(r"[\"'`](https?|wss?|file|ftp|data|javascript|mailto):(//)?[\"'`]", A | re.I)

# ── Per-line rules ───────────────────────────────────────────────────

GO_LOOSE = re.compile(r"\b(?:strings|bytes)\.(HasPrefix|HasSuffix|Contains|EqualFold)\(\s*([^,]+?)\s*,\s*([^)]*)", A)
PY_LOOSE = re.compile(r"([A-Za-z_][\w.]*(?:\(\s*\))?)\.(startswith|endswith)\(([^)]*)", A)
PY_IN = re.compile(r"(?:^|[\s(,=])(\"\"|[A-Za-z_][\w.]*)\s+(?:not\s+)?in\s+([A-Za-z_][\w.]*(?:\(\s*\))?)(?=\s*(?:$|[:),]|and\b|or\b|if\b|else\b))", A)
JS_LOOSE = re.compile(r"([A-Za-z_$][\w$.]*(?:\(\s*\))?)\.(startsWith|endsWith|includes|indexOf)\(([^)]*)", A)
JAVA_LOOSE = re.compile(r"([A-Za-z_$][\w$.]*(?:\(\s*\))?)\.(startsWith|endsWith|contains|equalsIgnoreCase)\(([^)]*)", A)
RB_LOOSE = re.compile(r"([A-Za-z_][\w.]*)\.(start_with\?|end_with\?|include\?)\(([^)]*)", A)
_FOR_RE = re.compile(r"\bfor\b", A)

RAW_LITERAL = re.compile(r'"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'|`((?:\\.|[^`\\])*)`', A)
_ESCAPE_RE = re.compile(r"\\.", A)
_LETTER_RE = re.compile(r"[A-Za-z]", A)
_EXTENSION_RE = re.compile(r"^\.[A-Za-z0-9]{1,5}$", A)


def _raw_literals(raw: str) -> list[str]:
    out = []
    for m in RAW_LITERAL.finditer(raw):
        g = m.group(1)
        if g is None:
            g = m.group(2)
        if g is None:
            g = m.group(3)
        out.append(g or "")
    return out


def _literal_noise(kind: str, cls: str, needle: str, raw: str, lit_index: int) -> bool:
    """A literal needle with no letters tests for a character; a ".py" suffix on a path tests an extension."""
    # A redirect that only has to start with "/" also accepts //evil.com.
    if needle.strip() != '""' or (kind == "prefix" and cls == "url"):
        return False
    # The code view replaced each literal with "", in order, so the count of "" before the needle indexes the raw literals.
    all_lits = _raw_literals(raw)
    lits = [all_lits[lit_index]] if 0 <= lit_index < len(all_lits) else all_lits
    if all(not _LETTER_RE.search(_ESCAPE_RE.sub("", lit)) for lit in lits):
        return True
    return kind == "suffix" and cls == "path" and all(_EXTENSION_RE.search(lit) for lit in lits)


def _literal_index(code: str, pos: int) -> int:
    """How many literals precede offset ``pos`` of the code view (-1: unknown)."""
    return -1 if pos < 0 else code[:pos].count('""')


def _raw_needle(needle: str, raw: str, lit_index: int) -> str | None:
    """The raw literal text the needle stands for, or None when it is not a literal at all."""
    if needle.strip() != '""':
        return None
    lits = _raw_literals(raw)
    return lits[lit_index] if 0 <= lit_index < len(lits) else None


def _loose_hit(op: str, ident: str, needle: str, raw: str, lit_index: int):
    cls = _match_class(ident)
    if not cls:
        return None
    kind = OP_KIND[op]
    if _literal_noise(kind, cls, needle, raw, lit_index):
        return None
    phrase = _loose_phrase(kind, cls, _raw_needle(needle, raw, lit_index))
    if not phrase:
        return None  # case folding a host, origin or domain is correct
    op_label = "`in`" if op == "in" else op
    return ("loose-match", LOOSE_WEIGHT[cls], f"{op_label} on {ident}: {phrase}; is that intended?")


def _loose_matches(lang: str, code: str, raw: str) -> list:
    hits: list = []
    if SCHEME_LITERAL.search(raw):
        return hits
    if lang == "go":
        for m in GO_LOOSE.finditer(code):
            ident = _last_ident(m.group(2))
            needle = m.group(3)
            pos = m.end() - len(m.group(3))
            if m.group(1) == "EqualFold" and not _match_class(ident):
                ident = _last_ident(m.group(3))
                needle = m.group(2)
                pos = -1
            h = _loose_hit(m.group(1), ident, needle, raw, _literal_index(code, pos))
            if h:
                hits.append(h)
        return hits
    if lang == "python":
        # `for x in path` iterates; it does not match.
        if not _FOR_RE.search(code):
            for m in PY_IN.finditer(code):
                pos = m.start() + m.group(0).find(m.group(1))
                h = _loose_hit("in", _last_ident(m.group(2)), m.group(1), raw, _literal_index(code, pos))
                if h:
                    hits.append(h)
    rx = {
        "python": PY_LOOSE, "java": JAVA_LOOSE, "ruby": RB_LOOSE,
        "javascript": JS_LOOSE, "typescript": JS_LOOSE,
    }.get(lang)
    if rx is None:
        return hits
    for m in rx.finditer(code):
        h = _loose_hit(m.group(2), _last_ident(m.group(1)), m.group(3), raw, _literal_index(code, m.end() - len(m.group(3))))
        if h:
            hits.append(h)
    return hits


Q_TLS_OFF = "certificate verification is off here, so a network attacker can impersonate the peer; is that intended?"

NEG_SETTING = r"(?:[A-Za-z_]\w*)?(?:[Ii]nsecure|[Ss]kip_?[Vv]erify|SKIP_VERIFY|[Nn]o_?[Vv]erify|NO_VERIFY|[Dd]isable_?(?:[Tt]ls|TLS|[Ss]sl|SSL)|DISABLE_(?:TLS|SSL)|INSECURE)\w*"


# (langs, regex, rule, weight, question(m), match the raw line)
LINE_RULES = [
    # TLS verification turned off by a literal.
    (("go",), re.compile(r"\bInsecureSkipVerify\s*(?::|=)\s*true\b", A), "tls-verify-off", 5,
     lambda m: f"InsecureSkipVerify is true: {Q_TLS_OFF}", False),
    (("python",), re.compile(r"\b(verify|verify_ssl|ssl_verify|verify_certs|verify_tls|tls_verify|validate_certs)\s*=\s*False\b", A), "tls-verify-off", 5,
     lambda m: f"{m.group(1)}=False: {Q_TLS_OFF}", False),
    (("python",), re.compile(r"\b(CERT_NONE|_create_unverified_context)\b", A), "tls-verify-off", 5,
     lambda m: f"{m.group(1)}: {Q_TLS_OFF}", False),
    (("python",), re.compile(r"\bcheck_hostname\s*=\s*False\b", A), "tls-verify-off", 5,
     lambda m: "check_hostname=False: any valid certificate is accepted for any host; is that intended?", False),
    (("javascript", "typescript"), re.compile(r"\b(rejectUnauthorized|strictSSL)\s*:\s*false\b", A), "tls-verify-off", 5,
     lambda m: f"{m.group(1)}: false: {Q_TLS_OFF}", False),
    (("javascript", "typescript"), re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\D*[\"'`]?0[\"'`]?", A), "tls-verify-off", 5,
     lambda m: f"NODE_TLS_REJECT_UNAUTHORIZED=0: {Q_TLS_OFF}", True),
    (("java",), re.compile(r"\b(NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy|InsecureTrustManagerFactory)\b", A), "tls-verify-off", 5,
     lambda m: f"{m.group(1)}: {Q_TLS_OFF}", False),
    (("ruby",), re.compile(r"\bVERIFY_NONE\b", A), "tls-verify-off", 5,
     lambda m: f"VERIFY_NONE: {Q_TLS_OFF}", False),
    # TLS verification taken from a value: where does it come from?
    (("go",), re.compile(r"\bInsecureSkipVerify\s*(?::|=)\s*(?!true\b|false\b)(!?[A-Za-z_][\w.]*(?:\(\s*\))?)", A), "tls-verify-config", 4,
     lambda m: f"InsecureSkipVerify is set from {m.group(1)} here, not fixed, so this path can disable verification; is that intended?", False),
    (("javascript", "typescript"), re.compile(r"\brejectUnauthorized\s*:\s*(?!true\b|false\b)(!?[A-Za-z_$][\w$.]*)", A), "tls-verify-config", 4,
     lambda m: f"rejectUnauthorized is set from {m.group(1)} here, not fixed, so this path can disable verification; is that intended?", False),
    # A negatively named option ("insecure", "skip verify") that defaults to on.
    (("go",), re.compile(r"\bflag\.Bool(?:Var)?\([^)]*?[\"'`]([\w-]*(?:insecure|skip-verify|skip_verify|no-verify|disable-tls|disable-ssl)[\w-]*)[\"'`]\s*,\s*true\b", A), "insecure-default", 4,
     lambda m: f"flag {m.group(1)} defaults to true: every deployment that does not override it skips verification; is that intended?", True),
    (("go", "python", "javascript", "typescript", "ruby"), re.compile(r"\b(" + NEG_SETTING + r")\s*(?::\s*bool\s*)?(?:=|:)\s*(true|True)\b", A), "insecure-default", 4,
     lambda m: f"{m.group(1)} is {m.group(2)}: if that is the default, every deployment that does not override it skips the check; is that intended?", False),
]

# Lines scanned on each side of a ClientAuth line for a configured CA pool: the
# same window used elsewhere for "nearby" context, not a true struct-literal
# or function boundary.
CLIENT_CA_WINDOW = 15
GO_CLIENT_AUTH = re.compile(r"\bClientAuth\s*(?::|=)\s*tls\.(RequestClientCert|RequireAnyClientCert|VerifyClientCertIfGiven)\b", A)
GO_CLIENT_CA_SET = re.compile(r"\bClientCAs\s*(?::|=)", A)


def _client_cert_hit(lang: str, code: list[str], i: int):
    """Client certificates requested but not verified: weight and wording depend on whether a CA pool is configured nearby."""
    if lang != "go":
        return None
    m = GO_CLIENT_AUTH.search(code[i])
    if not m:
        return None
    mode = m.group(1)
    given = mode == "VerifyClientCertIfGiven"
    has_ca = False
    for j in range(max(0, i - CLIENT_CA_WINDOW), min(len(code), i + CLIENT_CA_WINDOW + 1)):
        if GO_CLIENT_CA_SET.search(code[j]):
            has_ca = True
            break
    if has_ca:
        risk = "lets a client skip presenting one" if given else "does not verify certificates against them"
        return ("client-cert-unverified", 6, f"client CAs are configured here, but ClientAuth={mode} {risk}; is that intended?")
    risk = "lets a client connect with no certificate at all" if given else "accepts a client certificate without verifying it against any CA"
    return ("client-cert-unverified", 5, f"ClientAuth={mode} {risk}; is that intended?")

# A limit set to a value that usually means "unlimited", where it is a
# setting rather than a local: a key, a keyword default, an attribute or a
# constant. Not a Go `:=` local.
LIMIT_SET = re.compile(r"(^|[\s(,{.])([A-Za-z_]\w*)\s*(:=|=(?!=)|:)\s*(-1|Infinity|Number\.POSITIVE_INFINITY|math\.Inf\(1\)|float\(\"\"\)|math\.inf)(?![\w.])", A)
_CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]*$", A)


def _limit_hit(code: str):
    m = LIMIT_SET.search(code)
    if not m:
        return None
    name = m.group(2)
    if not any(w == "limit" or w == "max" or w.startswith("maxi") for w in _words(name)):
        return None
    setting = m.group(3) == ":" or m.group(1) in ("(", ",", ".") or bool(_CONST_RE.search(name))
    if not setting:
        return None
    v = "infinite" if m.group(4) == 'float("")' else f"{m.group(4)} (unlimited)"
    return ("limit-disabled", 2, f"{name} is {v}: a client can exhaust memory or time through it; is that intended?")


# Go: io.ReadAll / ioutil.ReadAll / json.NewDecoder on a request or response body.
GO_BODY_READ = re.compile(r"\b(io|ioutil)\.ReadAll\(\s*([A-Za-z_][\w.]*\.)?(Body|body)\s*\)|\bjson\.NewDecoder\(\s*([A-Za-z_][\w.]*\.)?Body\s*\)", A)
GO_LIMIT_NEAR = re.compile(r"LimitReader|MaxBytesReader|LimitedReader|MaxBytes", A)
# Python: .read() with no size on a request, stream or socket file.
PY_BODY_READ = re.compile(r"\b([A-Za-z_][\w.]*\.)?(request|req|rfile|stream|body|wsgi_input|input_stream)\.read\(\s*\)", A)
JS_DATA_EVENT = re.compile(r"\.on\(\s*\"\"\s*,", A)
JS_DATA_RAW = re.compile(r"\.on\(\s*[\"'`]data[\"'`]", A)
JS_SIZE_NEAR = re.compile(r"length|size|limit|max|byteLength", A | re.I)
_REQUEST_RECV = re.compile(r"^(r|req|request)\.$", A)
LIMIT_WINDOW = 15


def _body_read_hit(lang: str, code: list[str], raw: list[str], i: int):
    line = code[i]
    if lang == "go":
        m = GO_BODY_READ.search(line)
        if not m:
            return None
        for j in range(max(0, i - LIMIT_WINDOW), i + 1):
            if GO_LIMIT_NEAR.search(code[j]):
                return None
        recv = (m.group(2) or "") if m.group(1) else (m.group(4) or "")
        expr = f"{m.group(1)}.ReadAll({recv}{m.group(3)})" if m.group(1) else f"json.NewDecoder({recv}Body)"
        # A request body comes from the client; a response body from a server this code chose to call.
        is_request = bool(_REQUEST_RECV.search(recv))
        weight = 3 if is_request else 2
        who = "a client" if is_request else "the called server"
        return ("unbounded-read", weight, f"{expr} reads the whole body with no size limit: {who} can send a body of any size here; is that intended?")
    if lang == "python":
        m = PY_BODY_READ.search(line)
        if not m:
            return None
        return ("unbounded-read", 3, f"{m.group(1) or ''}{m.group(2)}.read() has no size limit: a client can send a body of any size here; is that intended?")
    if lang in ("javascript", "typescript"):
        if not JS_DATA_EVENT.search(line) or not JS_DATA_RAW.search(raw[i]):
            return None
        for j in range(i, min(len(code), i + 8)):
            if JS_SIZE_NEAR.search(code[j]):
                return None
        return ("unbounded-read", 3, "chunks from a 'data' event are collected with no size check: a client can send a body of any size here; is that intended?")
    return None


# ── Declarations of security-named settings ──────────────────────────

GO_STRUCT_OPEN = re.compile(r"^\s*type\s+[A-Za-z_]\w*\s+struct\s*\{\s*$", A)
GO_FIELD = re.compile(r"^\s+([A-Za-z_]\w*)\s+[*\[\]]*[A-Za-z_][\w.]*(\s+\"\")?\s*$", A)
PY_CLASS_FIELD = re.compile(r"^\s+([A-Za-z_]\w*)\s*:\s*[A-Za-z_][\w\[\], .|]*(=.*)?$", A)
PY_SELF_ASSIGN = re.compile(r"^\s+self\.([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)", A)
PY_SETTING = re.compile(r"^([A-Z][A-Z0-9_]*)\s*=(?!=)", A)
PY_CLASS = re.compile(r"^\s*class\s+[A-Za-z_]\w*", A)
PY_STATEMENT = re.compile(r"^\s*(def|class|return|if|for|while|with|elif|else|try|except|lambda)\b", A)
TS_FIELD = re.compile(r"^\s+(?:readonly\s+)?([A-Za-z_]\w*)\??\s*:\s*(?:boolean|number|string|string\[\]|RegExp)\s*;?\s*$", A)
JS_THIS_ASSIGN = re.compile(r"^\s+this\.([A-Za-z_]\w*)\s*=(?!=)", A)
JAVA_FIELD = re.compile(r"^\s+(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*(?:=[^;]*)?;\s*$", A)

# Go: a positively named bool (`VerifyHostname bool`) whose zero value, false, is the insecure one.
GO_POSITIVE_BOOL = re.compile(r"^\s+([A-Za-z_]\w*)\s+bool(\s+\"\")?\s*$", A)
POSITIVE_WORDS = {"verify", "secure", "strict", "require", "enforce", "validate", "check"}
NEGATING_WORDS = {"insecure", "skip", "disable", "disabled", "no", "not", "allow", "ignore", "optional", "without", "unsafe", "lax"}
PEER_WORDS = {"tls", "ssl", "cert", "certs", "certificate", "certificates", "hostname", "host", "peer", "signature", "https", "verify", "verification"}


def _go_positive_bool(name: str) -> bool:
    ws = _words(name)
    if any(w in NEGATING_WORDS for w in ws):
        return False
    if not any(w in POSITIVE_WORDS or w.startswith("verif") for w in ws):
        return False
    # Only checks of a peer or a protocol, not "Strict" mode of a parser.
    return any(w in PEER_WORDS for w in ws)


# ── Scan one file ────────────────────────────────────────────────────


def scan_leads(state: dict, rel: str, lang: str, raw: list[str], path_weight: int) -> None:
    """Collect the leads of one file into ``state``."""
    pre = blank_triple_quoted(raw) if lang == "python" else raw
    code = ["" if len(line) > MAX_LINE else _code_of(line, lang) for line in pre]
    state["files"].append((rel, pre))
    per_rule: dict[str, int] = {}
    bonus = 1 if path_weight > 0 else 0
    leads = state["leads"]

    def add(i: int, h) -> None:
        rule, weight, question = h
        n = per_rule.get(rule, 0)
        if n >= MAX_PER_FILE_RULE:
            return
        per_rule[rule] = n + 1
        leads.append({
            "file": rel, "line": i + 1, "rule": rule, "weight": weight + bonus,
            "question": question, "snippet": _snippet(raw[i]),
        })

    go_struct_depth = 0
    py_class_indent = -1
    py_body_indent = -1
    for i, c in enumerate(code):
        if c.strip() == "":
            continue
        # One lead per line: the heaviest hit, the first on a tie.
        best = None

        def offer(h) -> None:
            nonlocal best
            if h and (best is None or h[1] > best[1]):
                best = h

        for langs, rx, rule, weight, q, use_raw in LINE_RULES:
            if lang not in langs:
                continue
            m = rx.search(pre[i] if use_raw else c)
            if m:
                offer((rule, weight, q(m)))
        offer(_client_cert_hit(lang, code, i))
        offer(_body_read_hit(lang, code, pre, i))
        offer(_limit_hit(c))
        for h in _loose_matches(lang, c, pre[i]):
            offer(h)
        if best:
            add(i, best)

        # Declarations.
        decl = ""
        if lang == "go":
            if go_struct_depth > 0:
                if go_struct_depth == 1:
                    m = GO_FIELD.search(c)
                    if m:
                        decl = m.group(1)
                        pb = GO_POSITIVE_BOOL.search(c)
                        if pb and _go_positive_bool(pb.group(1)):
                            add(i, ("insecure-default", 3, f"{pb.group(1)} defaults to false (the zero value), so any config that does not set it skips the check; is that intended?"))
                for ch in c:
                    if ch == "{":
                        go_struct_depth += 1
                    elif ch == "}":
                        go_struct_depth -= 1
            elif GO_STRUCT_OPEN.search(c):
                go_struct_depth = 1
        elif lang == "python":
            ind = len(c) - len(c.lstrip())
            if PY_CLASS.search(c):
                py_class_indent = ind
                py_body_indent = -1
            elif py_class_indent >= 0 and ind <= py_class_indent:
                py_class_indent = -1
            elif py_class_indent >= 0 and py_body_indent < 0:
                py_body_indent = ind
            m = PY_SETTING.search(c)
            if m:
                decl = m.group(1)
            else:
                m = PY_SELF_ASSIGN.search(c)
                if m:
                    decl = m.group(1)
                elif py_class_indent >= 0 and ind == py_body_indent:
                    m = PY_CLASS_FIELD.search(c)
                    if m and not PY_STATEMENT.search(c):
                        decl = m.group(1)
        elif lang in ("typescript", "javascript"):
            m = TS_FIELD.search(c) if lang == "typescript" else None
            if m:
                decl = m.group(1)
            else:
                m = JS_THIS_ASSIGN.search(c)
                if m:
                    decl = m.group(1)
        elif lang == "java":
            m = JAVA_FIELD.search(c)
            if m:
                decl = m.group(1)
        if decl and _is_security_name(decl) and len(state["candidates"]) < MAX_CANDIDATES:
            state["candidates"].append({
                "name": decl, "file": rel, "line": i + 1, "weight": 3 + bonus, "snippet": _snippet(raw[i]),
            })


# ── Finish: settings never read, ranking, caps ───────────────────────

# After an occurrence: an assignment or a key, so it sets the value rather than reads it.
SET_AFTER = re.compile(r"^\s*(?:=(?![=>~])|:=|:(?![:=]))", A)
_COND_COLON = re.compile(r"^\s*:(?![:=])\s*(#.*)?$", A)
_ADDRESS_BEFORE = re.compile(r"&[\w.]*$", A)


def _read_names(state: dict, names: list[str]) -> set[str]:
    """The candidate names that are read somewhere.

    A read is an occurrence that is not a declaration line, not an
    assignment target or key, not an address taken to set it (`&cfg.Name`),
    and not the right-hand side of a pass-through (`self.name = name`).
    """
    read: set[str] = set()
    if not names:
        return read
    decl_at = {(c["file"], c["line"], c["name"]) for c in state["candidates"]}
    alt = "|".join(sorted(names, key=lambda n: (-len(n), n)))
    rx = re.compile(r"(?<![\w$])(" + alt + r")(?![\w$])", A)
    passthrough: dict[str, re.Pattern] = {}
    for rel, lines in state["files"]:
        for i, line in enumerate(lines):
            if len(line) > MAX_LINE:
                continue
            for m in rx.finditer(line):
                name = m.group(1)
                if name in read or (rel, i + 1, name) in decl_at:
                    continue
                after = line[m.end():]
                before = line[:m.start()]
                # `x.name:` ends a Python condition; only a bare `name:` is a key or annotation.
                if SET_AFTER.search(after) and not (before.endswith(".") and _COND_COLON.search(after)):
                    continue
                if _ADDRESS_BEFORE.search(before):
                    continue
                p = passthrough.get(name)
                if p is None:
                    p = passthrough[name] = re.compile(r"\." + name + r"\s*=\s*$", A)
                if p.search(before):
                    continue
                read.add(name)
    return read


def finish_leads(state: dict) -> tuple[list[dict], int]:
    # Repeated declarations in one file (`self.x = ...` in two methods) are one setting.
    decl_files: dict[str, set[str]] = {}
    for c in state["candidates"]:
        decl_files.setdefault(c["name"], set()).add(c["file"])
    first: set[str] = set()
    unique = []
    for c in state["candidates"]:
        if len(decl_files[c["name"]]) != 1 or c["name"] in first:
            continue
        first.add(c["name"])
        unique.append(c)
    read = _read_names(state, [c["name"] for c in unique])
    unread = sorted((c for c in unique if c["name"] not in read), key=lambda c: (-c["weight"], c["file"], c["line"]))
    leads = list(state["leads"])
    for c in unread[:MAX_CONFIG_UNREAD]:
        leads.append({
            "file": c["file"], "line": c["line"], "rule": "config-unread", "weight": c["weight"],
            "question": f"{c['name']} is set in config but nothing reads it: the check it names never runs.",
            "snippet": c["snippet"],
        })
    leads.sort(key=lambda lead: (-lead["weight"], lead["file"], lead["line"], lead["rule"]))
    return leads[:MAX_LEADS_JSON], len(leads)
