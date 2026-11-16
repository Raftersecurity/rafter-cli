# LLM-Integrated Code Review — OWASP LLM Top 10 (2025)

For any code that sends prompts to a model, exposes tool calls, retrieves context (RAG), or ships model output to a downstream system. Walk as questions. Cite file:line.

## LLM01 — Prompt Injection

Assume every string that reaches the prompt — user input, retrieved documents, tool output, file contents, web pages — is adversarial.

- Trace the prompt build. Concatenation of user input into the system prompt? String interpolation of retrieved chunks? Find every `system + user` join site.
- Are there *structural* defenses? (Delimiters the model is trained to respect, role separation, XML tags, instruction hierarchies.) Note: none are airtight — defense is layered, not singular.
- Indirect injection: is retrieved content (web page, email, PDF, repo file) ever fed to the model? Treat it as untrusted input, same as the user's message.
- Output gating: is the model's output used to decide authz, invoke tools, or send messages? If yes — LLM01 merges with LLM06 (Excessive Agency).

## LLM02 — Sensitive Information Disclosure

- What goes into the prompt? Grep for prompts that include: PII, internal URLs, database rows, credentials, full request objects. "Just pass context" is the failure mode.
- Is there a redaction step between "application data" and "prompt"? Can it be turned off by flag?
- Does the model provider retain logs? Which tenant's data is crossing into the provider? Is that contractually allowed?
- Model output: before returning to the user, is it scanned for data the caller shouldn't see (e.g. other tenants' data leaked from the context)?

## LLM03 — Supply Chain

- Model source: where does the model come from? Provider API (which account?) or self-hosted? If self-hosted, from which registry? Is the weights file checksummed?
- Embedding model: same questions. Many RAG pipelines have *two* models; both are supply chain.
- Prompt templates: if loaded from a shared registry (LangChain Hub, custom store), pinned and verified? Or pulled by name?
- Plugins / tools / MCP servers registered with the agent — are they audited (see `rafter agent audit`) before install?

## LLM04 — Data & Model Poisoning

- Training / fine-tuning data: where from, how reviewed, who can write to the source? Can a user of the system influence future training (feedback loops)?
- RAG corpus: same question. Can a user add documents to the retrieval index? If yes — those documents can issue instructions via LLM01.
- Vector store: who can write? Who can update metadata (which drives filtering)? Metadata poisoning can bypass the retrieval filter.

## LLM05 — Improper Output Handling

Treat model output as untrusted input to whatever consumes it.

- Markdown → HTML rendering: is the markdown sanitized? `![img](javascript:...)`, `<script>` in allowed tags, `<img onerror=>`?
- Model output as code: passed to `eval`, `exec`, `Function()`, compiled and run, written as a shell script? That's RCE by way of prompt.
- Model output as URL: used to fetch, redirect, or render? Same SSRF/XSS questions as elsewhere — plus: the model happily generates `javascript:` URLs.
- Model output as SQL / shell / XPath: if the model writes queries, is the result parameterized / sandboxed / approved before execution?
- Tool-call arguments from the model: validate shape, types, and values against a schema. Do not trust the model to stay in bounds.

## LLM06 — Excessive Agency

Tools + untrusted prompts = agent exfiltration / damage.

- For each tool the agent can call, ask: (a) does it need to exist, (b) what's its blast radius, (c) is there a human-in-the-loop gate for irreversible actions?
- Permissions scope: does the agent run with the calling user's permissions, or with service-account permissions that exceed any one user?
- Destructive actions (send email, charge card, delete, write file, run shell): any of these reachable from a prompt? Use Rafter's command guardrails (`rafter agent exec`) as a pattern.
- Chained calls: can tool A's output become tool B's input with no validation? Multi-step attacks live here.

## LLM07 — System Prompt Leakage

- Don't put secrets in system prompts. Grep the system prompt for API keys, customer-specific config, internal URLs.
- Assume the system prompt is recoverable. The prompt is for *behavior*, not for *authz*. If the code relies on the user not knowing the prompt to enforce a policy — the policy is broken.
- Different tenants / roles: different prompts, loaded server-side keyed by the *authenticated* principal, never from the request.

## LLM08 — Vector & Embedding Weaknesses

- Embedding-time injection: user content embedded without sanitization can be weaponized when retrieved.
- Access control on retrieval: is the query filtered by tenant / user before the vector search, or filtered *after*? "After" often leaks via re-ranker.
- Embedding collisions / adversarial embeddings: high-stakes retrieval (medical, legal) — is there a confidence floor on the similarity score before acting?

## LLM09 — Misinformation & Overreliance

A design question, but reviewable:

- Does the UI make it clear the output is model-generated? Is there a confidence indicator where warranted?
- For advice domains (medical, legal, financial), is there a disclaimer *and* a hard gate on actions?
- Does the code treat model output as ground truth anywhere? Summaries, extractions, classifications used downstream should have a human review step or a fallback.

## LLM10 — Unbounded Consumption

- Token budgets per request, per user, per tenant, per day?
- Max tokens on *output* (not just input) — unbounded generation is the classic DoS/cost footgun.
- Streaming responses: timeout per chunk? Total timeout?
- Parallel requests: queue depth, concurrency caps? Fan-out from a single user request to N model calls (RAG, ReAct loops) — bounded?

---

## Exit criteria

- For every tool the agent can call: documented purpose, scope, and human-gate story.
- For every retrieval/RAG path: write-access audit, injection defenses, tenant isolation.
- For every model output sink: treated as untrusted, specific sanitization / validation cited.
- Run `rafter agent audit` on any bundled skills/plugins. Pair with `rafter run` for SAST.
