# CWE Top 25 — Language-Keyed Checklist

MITRE's CWE Top 25 is weakness-level, not risk-level. Use this for CLI tools, libraries, IaC, and anything where OWASP's web/API framing doesn't fit. Pick the language section; pair with language-specific linters.

## How to use

- Grep the patterns below against the diff. Each hit is a question, not a verdict.
- Cross-reference with `rafter run` — the backend catches many of these via SAST; this doc covers the ones that take context to judge.

---

## Cross-language (applies everywhere)

- **CWE-79 XSS / CWE-89 SQLi / CWE-78 OS Command Injection** — any user input reaching a query language, shell, or HTML sink. Fix at the sink: parameterize, array-exec, autoescape.
- **CWE-22 Path Traversal** — any `open(path)`, `fs.readFile(path)`, `os.path.join(base, user_input)`. Canonicalize (`realpath` / `filepath.Abs`) and verify the result stays under an allow-root.
- **CWE-352 CSRF** — state-changing endpoints: is there a token check? SameSite cookies are necessary but not sufficient for cross-site POSTs in older browsers / API clients.
- **CWE-287 Improper Authentication / CWE-862 Missing Authorization** — covered in web-app.md / api.md.
- **CWE-798 Hardcoded Credentials** — `rafter scan local .` catches literal secrets; manually check env-var defaults (`API_KEY = os.environ.get("KEY", "dev-fallback-abc123")` ships the fallback).
- **CWE-918 SSRF** — any user-supplied URL fetched server-side. See web-app.md A10.

---

## Python

- **CWE-502 Insecure Deserialization** — `pickle.load`, `pickle.loads`, `yaml.load` without `SafeLoader`, `shelve`, `marshal`. Any of these on untrusted bytes is RCE.
- **CWE-78 / Subprocess** — `subprocess.run(..., shell=True)` with user input. Use list form: `subprocess.run(["cmd", arg])`, never `shell=True` with interpolated input.
- **CWE-94 Code Injection** — `eval`, `exec`, `compile`, `__import__` with user input. Also `pd.eval`, `numexpr.evaluate`.
- **CWE-611 XXE** — `xml.etree.ElementTree` is safe by default in 3.7+, but `lxml.etree.parse` with `resolve_entities=True` is not. Prefer `defusedxml`.
- **CWE-327 Weak Crypto** — `hashlib.md5` / `sha1` on passwords; `random` (not `secrets`) for tokens; `Crypto.Cipher.DES`, `AES.MODE_ECB`.
- **CWE-20 Input Validation** — type coercion pitfalls: `int(x)` raises, `int(x, 16)` accepts leading `0x`, `float("inf")`.

## JavaScript / TypeScript

- **CWE-1321 Prototype Pollution** — `_.merge`, `Object.assign` with user-controlled source, recursive deep-merge on user JSON. Node: affects the whole process.
- **CWE-79 XSS** — `innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `$sce.trustAsHtml`. React's default is safe; anything that bypasses it is the finding.
- **CWE-94 Code Injection** — `eval`, `new Function(str)`, `setTimeout(str, ...)`, `setInterval(str, ...)`, `vm.runInThisContext` with user input.
- **CWE-22 Path Traversal** — `path.join(base, userInput)` does not protect. Must resolve and verify containment.
- **CWE-400 Regex DoS (ReDoS)** — catastrophic backtracking patterns: `(a+)+`, `(.*)*`. Especially user-provided regexes.
- **CWE-346 Origin Validation** — `postMessage` handlers that don't check `event.origin`. `addEventListener("message", ...)` without origin check is the bug.

## Go

- **CWE-369 Divide-by-Zero / CWE-190 Integer Overflow** — Go doesn't panic on overflow, it wraps. Slice indexing with computed sizes: `make([]byte, headerLen)` where `headerLen` is attacker-controlled.
- **CWE-362 Race Conditions** — map writes without mutex; goroutines sharing non-channel state; `context.Value` for mutable data. Run `go test -race`.
- **CWE-74 Injection / CWE-78** — `exec.Command(name, args...)` is safe; `sh -c <string>` is not. Check `exec.Command("sh", "-c", userInput)`.
- **CWE-295 Improper Certificate Validation** — `tls.Config{InsecureSkipVerify: true}` outside tests.
- **CWE-400 Resource Consumption** — `io.ReadAll` on untrusted streams with no `io.LimitReader`. Goroutine leaks: for every `go f()`, how does it exit?
- **CWE-665 Improper Initialization** — zero-value structs used as "valid" config; `sync.Mutex` copied by value.

## Rust

- **CWE-119 Buffer Issues** — `unsafe` blocks. Every `unsafe` needs a comment explaining the invariant; missing comments are findings.
- **CWE-362 Race Conditions** — despite borrow checker, `Arc<Mutex<T>>` misuse (holding across `.await`), `RefCell` in multi-threaded code (→ `RwLock`).
- **CWE-674 Uncontrolled Recursion** — `serde` with deeply nested JSON, manual recursive parsers without depth limit.
- **CWE-400 Resource Consumption** — `.collect::<Vec<_>>()` on untrusted iterator; `Bytes::from` without length cap.
- **CWE-704 Incorrect Type Conversion** — `as` casts that truncate silently (`u64 as u32`). Prefer `try_into()`.

## Java / Kotlin

- **CWE-502 Insecure Deserialization** — `ObjectInputStream.readObject` on untrusted bytes; XMLDecoder; Jackson with default typing (`@JsonTypeInfo(use = Id.CLASS)` + polymorphic).
- **CWE-611 XXE** — `DocumentBuilderFactory` / `SAXParserFactory` without disabling external entities. Default is unsafe in older Java.
- **CWE-22 Path Traversal** — `Paths.get(base, userInput)` doesn't check containment; use `toRealPath().startsWith(base)`.
- **CWE-917 Expression Language Injection** — SpEL, OGNL, MVEL with user input (classic Struts-style RCE).

## IaC (Terraform / CloudFormation / Kubernetes)

- **CWE-284 Improper Access Control** — security groups with `0.0.0.0/0` on admin ports (22, 3389, db ports); S3 buckets public; IAM policies with `Resource: "*"` + `Action: "*"`.
- **CWE-732 Incorrect Permissions** — file modes `0777`, world-writable volumes, ConfigMaps holding secrets.
- **CWE-319 Cleartext Transmission** — ELB listeners on port 80 without redirect; storage without encryption at rest; TLS versions < 1.2.
- **CWE-798 Hardcoded Credentials** — secrets in `*.tf`, `*.yaml` environment, `docker-compose.yml`.
- **CWE-1104 Unmaintained 3rd-Party** — Docker base images pinned to `latest` or unpinned digests; Helm charts from unreviewed repos.

---

## Exit criteria

- For each language in the diff, walked the relevant section. For each hit, either a file:line citation showing it's safe, or a finding filed.
- Run language-specific linters in CI (`bandit`, `semgrep`, `golangci-lint`, `cargo clippy`, `spotbugs`) — this skill complements, doesn't replace them.
