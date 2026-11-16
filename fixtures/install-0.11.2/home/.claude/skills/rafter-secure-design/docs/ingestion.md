# Ingestion — Design Questions

Every byte crossing your trust boundary is a question: "who says this is safe, and how?" Most of the OWASP Top 10 lives at ingestion — parsers, decoders, fetchers, uploaders.

## Trust boundaries — name them

- Draw the boundary: external (internet, partner API, user upload) → your edge → your internal services → your storage.
- Each boundary crossing is a *validation point*. Validation means: shape check (schema), size check (bytes / fields), semantic check (does this make sense here?).
- Validation at the edge is necessary but not sufficient — internal services that re-read the data need to re-validate if the trust delta matters (e.g., a cached input re-used later as a filename).
- Parsers *are* the boundary for complex formats. A "validated JSON blob" that contains an eval-able code path is still a hole.

## Input schemas — declare, don't hand-parse

- Have a typed schema for every external input: JSON Schema, Zod, Pydantic, protobuf, OpenAPI-generated types. Reject unknown fields (`additionalProperties: false`).
- Accepting unknown fields is how mass-assignment bugs enter — the attacker ships `is_admin: true` and the schema silently accepts it.
- Length / size / range bounds on every field. Strings have max lengths, numbers have ranges, arrays have max sizes, nesting has max depth. Unbounded = DoS shape.
- Regex validation: anchor with `^` and `$`. Fear catastrophic backtracking — test with a regex-safety linter or prefer RE2-backed engines.

## Size limits — everywhere, early

- Request body size cap at the edge (reverse proxy / API gateway). Don't rely on the framework to cap — it parses first, rejects second.
- Per-field limits inside the body.
- Upload size limits, file-count limits, total-request-size limits.
- Decoder limits: JSON depth, XML entity count, zip expansion ratio (zip bomb). The default parser often has no cap — configure it explicitly.

## Parser selection — safe default, not fast default

- JSON: language-standard parser with strict mode. Reject duplicate keys (behavior varies across parsers — pick one that matches what your schema validator sees).
- YAML: `yaml.safe_load` in Python, `js-yaml` with `safeLoad` / schema, `serde_yaml` with explicit types. **Never `yaml.load` without `SafeLoader`.**
- XML: disable external entity resolution (XXE). `defusedxml` in Python, libraries with XXE off by default. If your design needs XML, flag this explicitly and pick the right library.
- CSV: beware formula injection (`=CMD(...)` in a field opened by Excel). Prefix fields starting with `= + - @ \t \r` when exporting.
- Protobuf / Thrift / MessagePack: safe-by-construction for schema violations, but size limits still needed.
- Regex-heavy parsers: ReDoS risk. Prefer PEG / EBNF grammars for untrusted input where possible.
- HTML / Markdown: never innerHTML raw; always sanitize (DOMPurify, bleach). Markdown renderers have inline-HTML modes — disable them for untrusted content.

## Deserialization — the silent RCE

- Any of `pickle.loads`, `yaml.load` (default), Java `ObjectInputStream`, PHP `unserialize`, .NET `BinaryFormatter`, `Marshal.load` — on untrusted bytes — is RCE-shaped.
- If you *need* cross-language serialization: JSON, Protobuf, MessagePack, Avro. If you *need* native: sign the payload (HMAC) so only your own emitters are accepted, and still validate after deserialization.
- Node `JSON.parse` + object assignment: prototype pollution via `__proto__` / `constructor` / `prototype` keys. Use `Object.create(null)` for dictionaries or a library that filters.

## File uploads

- What file types are accepted? Allowlist by **content sniff + declared MIME + extension**, not any one of them alone.
- Storage: write under a random name (UUID) — never preserve the client-supplied filename in the path. Preserving it enables path traversal and overwrite attacks.
- Scanner: for user-to-user content, run an AV / malware scan. For images, re-encode to strip EXIF + polyglot tricks.
- Serving: serve from a different origin / subdomain than your app (so a rendered SVG or HTML can't steal same-origin cookies). Set `Content-Disposition: attachment` for anything that isn't trusted media.
- Size: per-file and per-user/per-day quotas. Unbounded upload = cheap DoS + storage bomb.

## Server-side fetchers — SSRF-shaped

If any part of the design does "take a URL from user, fetch it":

- Is there a concrete business reason? Image proxy, webhook configurer, PDF-from-URL, OAuth metadata fetch — each is a known SSRF vector.
- Allowlist the destination **after** DNS resolution. `https://attacker.com` that DNS-resolves to `127.0.0.1` is the rebinding attack — resolve first, then decide.
- Deny: RFC1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16), loopback (127/8, ::1), cloud metadata (169.254.169.254, metadata.google.internal, fd00:ec2::254), IPv6 equivalents, and any internal CIDR you own.
- Redirects are fresh SSRF checks per hop. Disable redirects or re-validate each one.
- Timeouts + max-response-size: unbounded fetches = DoS.
- Response parsing: the fetched content is *still untrusted*. Don't eval it, don't template it, don't copy it to storage unsanitized.

## Content rendering — templates, markdown, rich text

- Which template engine? Autoescape on by default for HTML (`{{ user }}` escapes). The unsafe marker is `|safe` (Jinja), `{!!  !!}` (Blade), `dangerouslySetInnerHTML` (React), `v-html` (Vue). Every use of the unsafe marker is a review point.
- Markdown: does the renderer allow inline HTML? For untrusted authors, disable it or sanitize post-render with a DOMPurify-equivalent.
- Rich text (TinyMCE, Quill, Slate): sanitize the HTML output *server-side* before storing. Client-side sanitization is advisory, not authoritative.
- SVG: SVGs can embed scripts. Re-render to PNG server-side, or sanitize with a tool that strips `<script>`, event handlers, and external references.

## Search inputs

- Full-text search: user input goes into a query parser (Lucene syntax, etc.). Is there an injection risk (`field:*` to bypass scoping)? Sanitize or use parameterized search API.
- Sort / filter parameters: if user-controlled, allowlist the column names. `ORDER BY {user_input}` is SQL injection even if the rest of the query is parameterized.

## Imports (batch data)

- CSV / XLS / JSON imports are trust-boundary crossings at scale. Same rules — schema, size, field limits — applied per row.
- Streaming vs. load-all: streaming is kinder to memory and enables early rejection. Load-all with a 1GB file = OOM.
- Partial-failure semantics: if row 500 is bad, does the import roll back rows 1-499? Either answer can be right, but it must be *decided*, not accidental.

## Refuse-list

- `yaml.load` / `pickle.loads` / `Marshal.load` on any externally-sourced bytes.
- XML parsers with external entity resolution enabled.
- Uploads stored under client-supplied filenames.
- Server-side URL fetchers without an allowlist + post-DNS IP denylist.
- Schemas that accept unknown fields (`additionalProperties: true` by default).
- Unbounded sizes: no request body cap, no per-field length, no decoder depth limit.
- Markdown / HTML rendering of untrusted content without server-side sanitization.
- Regex patterns without anchors or on backtracking engines with untrusted input.

---

## Exit criteria

- Every external input has a named schema and a size/shape limit.
- Parser choices are listed with the safe variant selected.
- If any fetcher is in the design, its allowlist + IP denylist + redirect policy is specified.
- File upload flow names the content-sniff library, the storage-naming scheme, and the serving origin.
- The design identifies every "untrusted bytes → executable context" path and closes it.
