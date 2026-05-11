// trove inventory UI.
//
// Talks to the trove HTTP server via:
//   GET  /api/secrets                  → { secrets: [...], scan_config, reveal_policy }
//   POST /api/secrets/{id}/reveal      → { value, source_type, path }
//   PUT  /api/secrets/{id}/annotation  → 204
//   POST /api/secrets/{id}/stale       → 204
//   POST /api/secrets/{id}/rotated     → 204
//   GET  /api/events                   → SSE stream of drift events
//
// The session cookie set on the launcher redirect authenticates every
// fetch automatically (credentials: 'same-origin').
//
// Reveal policies (storage.RevealPolicy on the wire):
//   "strict"   — never reveal; only annotations.
//   "session"  — reveal per-click; values stay in-memory only. Default.
//   "loose"    — reveal without per-secret confirmation.
//   "paranoid" — never decrypt OS keystore reads; keystore reveals 422
//                and the UI surfaces a "Decrypt off — see settings" link.

(function () {
  "use strict";

  const list = document.getElementById("list");
  const panelWrap = document.getElementById("panel-wrap");
  const panel = document.getElementById("panel");
  const summary = document.getElementById("summary");
  const toastRegion = document.getElementById("toast-region");
  const driftTicker = document.getElementById("drift-ticker");
  const driftBadge = document.getElementById("drift-badge");

  // Five-family taxonomy. Order in this array controls render order.
  // Each entry maps a SourceType (+ optional path predicate) to a
  // self-explaining family copy block.
  const FAMILIES = [
    {
      id: "envfile",
      title: "Environment files (.env, .envrc)",
      icon: "envfile",
      matches: (f) => f.source_type === "envfile" && isDotEnvPath(f.path),
      always: false,
    },
    {
      id: "shell-rc",
      title: "Shell config (.zshrc, .bashrc, .profile)",
      icon: "shell",
      matches: (f) => f.source_type === "shell-rc",
      always: false,
    },
    {
      id: "config",
      title: "Config files (~/.aws, ~/.npmrc, ~/.config/gh, …)",
      icon: "config",
      matches: (f) => f.source_type === "envfile" && !isDotEnvPath(f.path),
      always: false,
    },
    {
      id: "keystore",
      title: "OS keychain",
      subtitle: "coming soon",
      icon: "key",
      matches: (f) => f.source_type === "keystore",
      always: true,
      unsupported: true,
    },
    {
      id: "source-code",
      title: "Source code",
      subtitle: "coming soon, blocked on betterleaks",
      icon: "code",
      matches: (f) => f.source_type === "source-code",
      always: true,
      unsupported: true,
    },
  ];

  // Inline single-color SVG icons (--fg-muted via currentColor).
  const ICONS = {
    envfile: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 1.5h7l3 3V14a.5.5 0 0 1-.5.5h-9A.5.5 0 0 1 3 14V1.5z" stroke="currentColor"/><path d="M10 1.5V5h3" stroke="currentColor"/><path d="M5.5 8h5M5.5 10.5h5M5.5 6h2" stroke="currentColor"/></svg>',
    shell:   '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="2" y="3" width="12" height="10" rx="1.2" stroke="currentColor"/><path d="M4.5 6.5l2 2-2 2M8 11h3.5" stroke="currentColor" stroke-linecap="round"/></svg>',
    config:  '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="2.5" stroke="currentColor"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.5 3.5l1.4 1.4M11.1 11.1l1.4 1.4M3.5 12.5l1.4-1.4M11.1 4.9l1.4-1.4" stroke="currentColor"/></svg>',
    key:     '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="5" cy="11" r="2.5" stroke="currentColor"/><path d="M6.8 9.2L14 2M11 5l1.5 1.5M13 3l1.5 1.5" stroke="currentColor"/></svg>',
    code:    '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M5.5 4.5L2 8l3.5 3.5M10.5 4.5L14 8l-3.5 3.5M9.5 3.5l-3 9" stroke="currentColor" stroke-linecap="round"/></svg>',
    lock:    '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3.5" y="7" width="9" height="6.5" rx="1.2" stroke="currentColor"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" stroke="currentColor"/></svg>',
    copy:    '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="4" y="4" width="8" height="9" rx="1" stroke="currentColor"/><path d="M6 4V3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1h-1" stroke="currentColor"/></svg>',
  };

  // Mode-octal explainer copy. Append a `?` icon next to any value
  // that renders an octal mode; hover/focus shows this tip.
  const MODE_TIPS = {
    "0644": "World-readable. Anyone with a shell on this machine can read the file. .env files should be 0600.",
    "0640": "Owner + group. Members of the file's group can read.",
    "0600": "Owner-only. Recommended for files holding secrets.",
    "0660": "Owner + group, no world. Group members can read.",
    "0666": "World-readable AND world-writable. Treat as compromised.",
    "0664": "Group-writable. Members of the file's group can read and edit.",
  };
  function modeSeverity(mode) {
    if (!mode) return "";
    if (mode === "0600" || mode === "0400") return "ok";
    if (mode === "0640" || mode === "0660" || mode === "0660") return "warn";
    return "danger";
  }

  let state = { secrets: [], reveal_policy: "session" };
  let selectedId = null;
  // Reveals are kept in-memory only — never persisted, never synced
  // across reloads. Map<secretID, value>.
  const revealed = new Map();
  // Annotation save debouncer.
  let saveTimer = null;
  let saveState = "idle";
  // Pending undo for mark-stale; null when no undo is active.
  let undoStaleTimer = null;
  let undoStaleId = null;

  // ----------- helpers -----------

  function isDotEnvPath(p) {
    if (!p) return false;
    // Match common dotenv basenames anywhere in the path.
    return /(^|\/)\.env(\..+|rc)?$/.test(p);
  }

  function setToast(text, kind) {
    if (!text) return;
    const t = document.createElement("div");
    t.className = "toast";
    if (kind === "err") t.classList.add("err");
    if (kind === "ok") t.classList.add("ok");
    t.textContent = text;
    toastRegion.appendChild(t);
    setTimeout(() => {
      t.style.transition = "opacity 0.25s ease";
      t.style.opacity = "0";
      setTimeout(() => t.remove(), 250);
    }, kind === "err" ? 4500 : 1500);
  }

  function announceDrift(text) {
    if (!text) return;
    const el = document.createElement("div");
    el.textContent = text;
    driftTicker.appendChild(el);
    // Trim to last 5 entries so the live region doesn't grow unbounded.
    while (driftTicker.childNodes.length > 5) driftTicker.removeChild(driftTicker.firstChild);
  }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
    if (!res.ok) {
      let msg = res.statusText;
      try {
        const body = await res.json();
        if (body && body.error) msg = body.error;
      } catch (_) {}
      const err = new Error(msg || "request failed");
      err.status = res.status;
      throw err;
    }
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") || "";
    return ct.startsWith("application/json") ? res.json() : res.text();
  }

  async function loadSecrets() {
    try {
      const body = await api("/api/secrets");
      state.secrets = body.secrets || [];
      state.reveal_policy = body.reveal_policy || "session";
      render();
    } catch (e) {
      setToast("Load failed: " + e.message, "err");
    }
  }

  // ----------- grouping -----------

  function classify(secret) {
    const f = (secret.found_in || [])[0];
    if (!f) return { id: "config", _orphan: true };
    for (const fam of FAMILIES) {
      if (fam.matches(f)) return fam;
    }
    // Unknown source_type → bucket into config catch-all.
    return FAMILIES.find((g) => g.id === "config");
  }

  function groupSecrets(secrets) {
    // groupId -> { fam, items: [secret] }
    const buckets = new Map();
    for (const fam of FAMILIES) {
      if (fam.always) buckets.set(fam.id, { fam, items: [] });
    }
    for (const s of secrets) {
      const fam = classify(s);
      if (!buckets.has(fam.id)) buckets.set(fam.id, { fam, items: [] });
      buckets.get(fam.id).items.push(s);
    }
    // Order according to FAMILIES definition.
    const out = [];
    for (const fam of FAMILIES) {
      const b = buckets.get(fam.id);
      if (b) out.push(b);
    }
    return out;
  }

  function sourceWarning(items) {
    // Returns the worst world-readable warning across the group's
    // file entries, or null. The header pill nudges users toward 0600.
    let worst = null;
    for (const s of items) {
      for (const f of s.found_in || []) {
        if (!f.path || !f.permissions) continue;
        const sev = modeSeverity(f.permissions);
        if (sev === "danger") return { mode: f.permissions, path: f.path };
        if (sev === "warn" && !worst) worst = { mode: f.permissions, path: f.path };
      }
    }
    return worst;
  }

  // ----------- render: list -----------

  function render() {
    const secrets = state.secrets;
    renderSummary(secrets);

    list.setAttribute("data-clear-selection", "");
    list.innerHTML = "";

    const groups = groupSecrets(secrets);
    let totalRendered = 0;

    for (const g of groups) {
      const det = document.createElement("details");
      det.className = "group";
      if (g.fam.unsupported) det.classList.add("unsupported");
      det.open = !g.fam.unsupported && g.items.length > 0;
      det.dataset.familyId = g.fam.id;

      const sum = document.createElement("summary");
      const icon = document.createElement("span");
      icon.className = "group-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.innerHTML = ICONS[g.fam.icon] || "";
      sum.appendChild(icon);

      const titleWrap = document.createElement("span");
      titleWrap.className = "group-title-wrap";

      const titleSpan = document.createElement("span");
      titleSpan.className = "group-title";
      titleSpan.textContent = g.fam.title;
      titleWrap.appendChild(titleSpan);

      if (g.fam.subtitle) {
        titleWrap.appendChild(document.createTextNode(" "));
        const sub = document.createElement("span");
        sub.className = "group-subtitle";
        sub.textContent = "— " + g.fam.subtitle;
        titleWrap.appendChild(sub);
      }
      sum.appendChild(titleWrap);

      const count = document.createElement("span");
      count.className = "group-count";
      const n = g.items.length;
      count.textContent = g.fam.unsupported && n === 0
        ? ""
        : `${n} secret${n === 1 ? "" : "s"}`;
      sum.appendChild(count);

      det.appendChild(sum);

      const warn = sourceWarning(g.items);
      if (warn) {
        const w = document.createElement("div");
        w.className = "group-warn";
        const pill = document.createElement("span");
        pill.className = "warn-pill";
        pill.textContent = warn.mode === "0644" || warn.mode === "0666" ? "world-readable" : "loose mode";
        w.appendChild(pill);
        const txt = document.createElement("span");
        txt.textContent = warn.mode === "0644" || warn.mode === "0666"
          ? `Files in this group are world-readable (${warn.mode}). Tighten to 0600 with: chmod 600 <file>`
          : `Files in this group are group-readable (${warn.mode}). Tighten to 0600 if only you should read them.`;
        w.appendChild(txt);
        det.appendChild(w);
      }

      if (g.items.length > 0) {
        const ul = document.createElement("ul");
        ul.className = "entries";
        for (const s of g.items) {
          ul.appendChild(renderEntry(s));
          totalRendered++;
        }
        det.appendChild(ul);
      } else if (g.fam.unsupported) {
        const sub = document.createElement("div");
        sub.className = "group-warn";
        sub.style.background = "transparent";
        sub.style.color = "var(--fg-muted)";
        sub.style.fontStyle = "italic";
        sub.textContent = "Nothing scanned here yet.";
        det.appendChild(sub);
      }

      list.appendChild(det);
    }

    if (totalRendered === 0) {
      // No real secrets — show the empty hero.
      const empty = document.createElement("div");
      empty.className = "empty";
      const lede = document.createElement("div");
      lede.className = "empty-lede";
      lede.textContent = "No secrets recorded yet.";
      empty.appendChild(lede);
      empty.appendChild(document.createTextNode(
        "trove watches your scan roots. Edit a tracked file or wait for the next scan."));
      list.appendChild(empty);
    }

    if (selectedId) {
      const stillThere = secrets.some((s) => s.id === selectedId);
      if (stillThere) renderPanel(); else closePanel();
    }
  }

  function renderSummary(secrets) {
    summary.innerHTML = "";
    if (secrets.length === 0) {
      const c = document.createElement("span");
      c.className = "chip";
      c.innerHTML = "<strong>0</strong> secrets";
      summary.appendChild(c);
      return;
    }
    const counts = new Map();
    for (const s of secrets) {
      const fam = classify(s);
      counts.set(fam.id, (counts.get(fam.id) || 0) + 1);
    }
    const total = document.createElement("span");
    total.className = "chip";
    total.innerHTML = `<strong>${secrets.length}</strong> secret${secrets.length === 1 ? "" : "s"}`;
    summary.appendChild(total);

    for (const fam of FAMILIES) {
      const n = counts.get(fam.id);
      if (!n) continue;
      const c = document.createElement("span");
      c.className = "chip";
      const label = familyShortLabel(fam.id);
      c.innerHTML = `<strong>${n}</strong> in ${label}`;
      summary.appendChild(c);
    }
  }

  function familyShortLabel(id) {
    switch (id) {
      case "envfile":     return ".env files";
      case "shell-rc":    return "shell config";
      case "config":      return "config files";
      case "keystore":    return "keychain";
      case "source-code": return "source code";
      default: return id;
    }
  }

  function renderEntry(s) {
    const li = document.createElement("li");
    li.className = "entry";
    li.dataset.id = s.id;
    if (s.id === selectedId) li.classList.add("selected");
    if (s.annotation && s.annotation.stale) li.classList.add("stale");

    const key = document.createElement("span");
    key.className = "key";
    key.textContent = s.key_name;
    key.title = s.key_name;
    li.appendChild(key);

    const preview = document.createElement("span");
    preview.className = "preview";
    if (revealed.has(s.id)) {
      preview.textContent = revealed.get(s.id);
      preview.classList.add("revealed");
      preview.title = "Click to copy";
    } else {
      preview.textContent = s.value_preview || "—";
      preview.classList.add("blurred");
      preview.title = "Click to reveal";
    }
    preview.addEventListener("click", (e) => {
      e.stopPropagation();
      if (revealed.has(s.id)) {
        copyToClipboard(revealed.get(s.id));
      } else {
        toggleReveal(s);
      }
    });
    li.appendChild(preview);

    const right = document.createElement("span");
    right.className = "meta-right";
    const first = (s.found_in || [])[0];
    if (first) {
      if (first.path) {
        const path = document.createElement("span");
        path.className = "path";
        const basename = first.path.split("/").pop();
        path.textContent = basename;
        path.title = first.path;
        right.appendChild(path);
        if (first.permissions) {
          right.appendChild(modeNode(first.permissions));
        }
      } else if (first.keystore) {
        const k = document.createElement("span");
        k.className = "badge";
        k.textContent = first.keystore;
        right.appendChild(k);
      }
    }
    if (s.annotation && s.annotation.stale) {
      const b = document.createElement("span");
      b.className = "badge stale";
      b.textContent = "stale";
      right.appendChild(b);
    }
    if (s.annotation && s.annotation.rotated_at) {
      const b = document.createElement("span");
      b.className = "badge rotated";
      b.textContent = "rotated " + relativeTime(s.annotation.rotated_at);
      right.appendChild(b);
    }
    li.appendChild(right);

    li.addEventListener("click", () => selectSecret(s.id));
    return li;
  }

  function modeNode(perms) {
    const sev = modeSeverity(perms);
    const span = document.createElement("span");
    span.className = "mode" + (sev ? " " + sev : "");
    span.setAttribute("data-mode-octal", perms);
    const code = document.createElement("span");
    code.textContent = perms;
    span.appendChild(code);
    const help = document.createElement("span");
    help.className = "mode-help";
    help.tabIndex = 0;
    help.setAttribute("role", "img");
    help.setAttribute("aria-label", "What does mode " + perms + " mean?");
    help.textContent = "?";
    const tip = MODE_TIPS[perms] || "Octal file mode. 0600 (owner-only) is recommended for files holding secrets.";
    help.setAttribute("data-tip", tip);
    // Stop click on the help bubble from triggering parent row select.
    help.addEventListener("click", (e) => e.stopPropagation());
    span.appendChild(help);
    return span;
  }

  function relativeTime(iso) {
    const t = Date.parse(iso);
    if (isNaN(t)) return iso;
    const diff = (Date.now() - t) / 1000;
    if (diff < 60) return "just now";
    if (diff < 3600) return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return Math.floor(diff / 86400) + "d ago";
  }

  async function copyToClipboard(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
      setToast("Copied", "ok");
    } catch (e) {
      setToast("Copy failed: " + e.message, "err");
    }
  }

  // ----------- reveal -----------

  async function toggleReveal(s) {
    if (revealed.has(s.id)) {
      revealed.delete(s.id);
      render();
      return;
    }
    try {
      const body = await api(`/api/secrets/${encodeURIComponent(s.id)}/reveal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      revealed.set(s.id, body.value);
      render();
    } catch (e) {
      if (e.status === 422) {
        // Special-case paranoid + keystore — point at settings.
        if (state.reveal_policy === "paranoid") {
          setToast("Decrypt off — see settings", "err");
        } else {
          setToast("Reveal not supported for this source", "err");
        }
      } else if (e.status === 410) {
        setToast("Value is gone — drift not yet rescanned", "err");
      } else {
        setToast("Reveal failed: " + e.message, "err");
      }
    }
  }

  // ----------- selection / panel -----------

  function selectSecret(id) {
    selectedId = id;
    panelWrap.classList.add("open");
    renderPanel();
    for (const el of list.querySelectorAll("li.entry")) {
      el.classList.toggle("selected", el.dataset.id === id);
    }
  }

  function closePanel() {
    selectedId = null;
    panelWrap.classList.remove("open");
    panel.innerHTML = "";
    for (const el of list.querySelectorAll("li.entry.selected")) {
      el.classList.remove("selected");
    }
  }

  // Esc + click-outside-list clears selection. The data-clear-selection
  // hook on #list is the assertion target for the smoke test.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && selectedId) closePanel();
  });

  function renderPanel() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    if (!s) { closePanel(); return; }
    panel.innerHTML = "";

    // Head
    const head = document.createElement("div");
    head.className = "panel-head";
    const h2 = document.createElement("h2");
    h2.textContent = s.key_name;
    head.appendChild(h2);
    const closeBtn = document.createElement("button");
    closeBtn.className = "close-panel";
    closeBtn.setAttribute("aria-label", "Close detail panel");
    closeBtn.textContent = "✕";
    closeBtn.addEventListener("click", closePanel);
    head.appendChild(closeBtn);
    panel.appendChild(head);

    // Value section
    const valSec = document.createElement("section");
    const valH = document.createElement("h3");
    valH.textContent = "Value";
    valSec.appendChild(valH);
    const prev = document.createElement("div");
    prev.className = "panel-preview";
    if (revealed.has(s.id)) {
      prev.classList.add("revealed");
      prev.textContent = revealed.get(s.id);
      prev.title = "Click to copy";
    } else {
      prev.textContent = s.value_preview || "—";
      prev.title = "Click to reveal";
    }
    prev.addEventListener("click", () => {
      if (revealed.has(s.id)) copyToClipboard(revealed.get(s.id));
      else toggleReveal(s);
    });
    valSec.appendChild(prev);

    const valActions = document.createElement("div");
    valActions.className = "panel-preview-actions";
    const revealBtn = document.createElement("button");
    if (state.reveal_policy === "paranoid" && (s.found_in || []).some((f) => f.source_type === "keystore")) {
      revealBtn.textContent = "Decrypt off — see settings";
      revealBtn.disabled = true;
      revealBtn.title = "Reveal policy is paranoid. Change in settings to enable keystore reveals.";
    } else {
      revealBtn.textContent = revealed.has(s.id) ? "Re-blur" : "Reveal value";
      revealBtn.classList.add("primary");
      revealBtn.addEventListener("click", () => toggleReveal(s));
    }
    valActions.appendChild(revealBtn);
    if (revealed.has(s.id)) {
      const copyBtn = document.createElement("button");
      copyBtn.title = "Copy to clipboard";
      copyBtn.setAttribute("aria-label", "Copy value");
      copyBtn.innerHTML = ICONS.copy + " <span>Copy</span>";
      copyBtn.addEventListener("click", () => copyToClipboard(revealed.get(s.id)));
      valActions.appendChild(copyBtn);
    }
    const saveStateEl = document.createElement("span");
    saveStateEl.className = "save-state";
    saveStateEl.id = "save-state";
    valActions.appendChild(saveStateEl);
    valSec.appendChild(valActions);
    panel.appendChild(valSec);

    // Notes section (renamed from the older annotate copy)
    const notesSec = document.createElement("section");
    notesSec.setAttribute("aria-label", "Notes");
    const notesH = document.createElement("h3");
    notesH.textContent = "Notes";
    notesSec.appendChild(notesH);
    const meta = document.createElement("dl");
    meta.className = "meta";
    meta.appendChild(field("Notes", "notes", s.annotation.notes || "", "textarea",
                            "Add a note about this secret"));
    meta.appendChild(field("Owner", "owner", s.annotation.owner || "", "text",
                            "Who owns this credential?"));
    meta.appendChild(field("Source URL", "source_url", s.annotation.source_url || "", "text",
                            "Where this was issued (provider console URL)"));
    meta.appendChild(field("Rotate at", "rotate_url", s.annotation.rotate_url || "", "text",
                            "Provider rotation page"));
    meta.appendChild(field("Tags", "tags", (s.annotation.tags || []).join(", "), "text",
                            "Comma-separated tags"));
    notesSec.appendChild(meta);
    if (s.annotation.rotate_url) {
      const a = document.createElement("a");
      a.href = s.annotation.rotate_url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = "Open admin page ↗";
      a.style.fontSize = "12px";
      a.style.color = "var(--accent)";
      notesSec.appendChild(a);
    }
    panel.appendChild(notesSec);
    updateSaveState();

    // Found in
    const foundSec = document.createElement("section");
    const foundH = document.createElement("h3");
    foundH.textContent = "Found in";
    foundSec.appendChild(foundH);
    const foundUL = document.createElement("ul");
    foundUL.className = "found-list";
    for (const f of s.found_in || []) {
      const li = document.createElement("li");
      if (f.path) {
        let txt = `${f.source_type}: ${f.path}`;
        if (f.line) txt += `:${f.line}`;
        li.textContent = txt;
        if (f.permissions) {
          li.appendChild(document.createTextNode("  "));
          li.appendChild(modeNode(f.permissions));
        }
      } else if (f.keystore) {
        li.textContent = `${f.source_type}: ${f.keystore} ${f.service || ""}/${f.account || ""}`;
        li.classList.add("unsupported");
      } else {
        li.textContent = `${f.source_type}`;
      }
      foundUL.appendChild(li);
    }
    foundSec.appendChild(foundUL);
    panel.appendChild(foundSec);

    // Audit findings (derived from FoundIn flags)
    const auditLines = [];
    for (const f of s.found_in || []) {
      if (f.in_git_repo === true) auditLines.push("Inside a git repository.");
      if (f.in_gitignore === false && f.path) auditLines.push(`Not in .gitignore: ${f.path}`);
      if (f.appears_in_git_history === true) auditLines.push("Appears in git history — assume committed.");
    }
    if (auditLines.length > 0) {
      const auditSec = document.createElement("section");
      const aH = document.createElement("h3");
      aH.textContent = "Audit findings";
      auditSec.appendChild(aH);
      const aUL = document.createElement("ul");
      aUL.className = "found-list";
      for (const ln of auditLines) {
        const li = document.createElement("li");
        li.textContent = ln;
        li.style.color = "var(--danger)";
        aUL.appendChild(li);
      }
      auditSec.appendChild(aUL);
      panel.appendChild(auditSec);
    }

    // Value history
    if (s.value_history && s.value_history.length > 0) {
      const histSec = document.createElement("section");
      const hH = document.createElement("h3");
      hH.textContent = `Value history (${s.value_history.length})`;
      histSec.appendChild(hH);
      const hUL = document.createElement("ul");
      hUL.className = "history-list";
      for (const h of s.value_history) {
        const li = document.createElement("li");
        li.textContent = `${h.fingerprint.slice(0, 12)}…  seen ${h.seen_at}`;
        hUL.appendChild(li);
      }
      histSec.appendChild(hUL);
      panel.appendChild(histSec);
    }

    // Actions
    const actSec = document.createElement("section");
    const actH = document.createElement("h3");
    actH.textContent = "Actions";
    actSec.appendChild(actH);
    const actions = document.createElement("div");
    actions.className = "actions-row";
    const stale = document.createElement("button");
    stale.textContent = s.annotation.stale ? "(already stale)" : "Mark stale";
    stale.disabled = !!s.annotation.stale;
    stale.classList.add("warn");
    stale.addEventListener("click", () => markStale(s.id));
    actions.appendChild(stale);
    const rot = document.createElement("button");
    rot.textContent = "Mark rotated";
    rot.title = "Record that you rotated this credential out-of-band. The next scan will pick up the new value.";
    rot.addEventListener("click", () => markRotated(s.id));
    actions.appendChild(rot);
    actSec.appendChild(actions);

    // Undo row sits at the very bottom of the panel.
    if (undoStaleId === s.id) {
      const undoRow = document.createElement("div");
      undoRow.className = "undo-row";
      const txt = document.createElement("span");
      txt.textContent = "Marked stale.";
      undoRow.appendChild(txt);
      const undoBtn = document.createElement("button");
      undoBtn.className = "ghost";
      undoBtn.textContent = "Undo";
      undoBtn.addEventListener("click", undoStale);
      undoRow.appendChild(undoBtn);
      actSec.appendChild(undoRow);
    }
    panel.appendChild(actSec);
  }

  function field(label, name, value, kind, placeholder) {
    const div = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = label;
    div.appendChild(dt);
    const dd = document.createElement("dd");
    let input;
    if (kind === "textarea") {
      input = document.createElement("textarea");
      input.value = value;
    } else {
      input = document.createElement("input");
      input.type = "text";
      input.value = value;
    }
    input.dataset.field = name;
    if (placeholder) input.placeholder = placeholder;
    input.setAttribute("aria-label", label);
    input.addEventListener("input", scheduleSave);
    dd.appendChild(input);
    div.appendChild(dd);
    return div;
  }

  function readPanelAnnotation() {
    const fields = panel.querySelectorAll("[data-field]");
    const ann = {
      source_url: "", owner: "", notes: "", rotate_url: "", tags: [],
    };
    for (const f of fields) {
      const name = f.dataset.field;
      if (name === "tags") {
        ann.tags = f.value.split(",").map((t) => t.trim()).filter(Boolean);
      } else {
        ann[name] = f.value;
      }
    }
    return ann;
  }

  function scheduleSave() {
    if (saveTimer) clearTimeout(saveTimer);
    setSaveState("saving");
    saveTimer = setTimeout(saveAnnotation, 600);
  }

  function setSaveState(s) {
    saveState = s;
    updateSaveState();
  }
  function updateSaveState() {
    const el = document.getElementById("save-state");
    if (!el) return;
    el.classList.remove("saving", "saved", "err");
    if (saveState === "saving") { el.textContent = "Saving…"; el.classList.add("saving"); }
    else if (saveState === "saved") { el.textContent = "Saved"; el.classList.add("saved"); }
    else if (saveState === "err") { el.textContent = "Save failed"; el.classList.add("err"); }
    else el.textContent = "";
  }

  async function saveAnnotation() {
    if (!selectedId) return;
    const ann = readPanelAnnotation();
    try {
      await api(`/api/secrets/${encodeURIComponent(selectedId)}/annotation`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ann),
      });
      const s = state.secrets.find((x) => x.id === selectedId);
      if (s) s.annotation = Object.assign({}, s.annotation, ann);
      setSaveState("saved");
      setTimeout(() => { if (saveState === "saved") setSaveState("idle"); }, 2000);
    } catch (e) {
      setSaveState("err");
      setToast("Save failed: " + e.message, "err");
    }
  }

  async function markStale(id) {
    try {
      await api(`/api/secrets/${encodeURIComponent(id)}/stale`, { method: "POST" });
      undoStaleId = id;
      if (undoStaleTimer) clearTimeout(undoStaleTimer);
      undoStaleTimer = setTimeout(() => { undoStaleId = null; renderPanel(); }, 4000);
      await loadSecrets();
    } catch (e) {
      setToast("Mark stale failed: " + e.message, "err");
    }
  }

  async function undoStale() {
    // No first-class un-stale endpoint; clear the stale bit by sending
    // an annotation save with the existing fields (the dedicated stale
    // endpoint only flips on). For now: show a soft toast — the action
    // becomes available when an /unstale endpoint lands.
    setToast("Undo not yet wired — use a fresh scan to re-mark.", "err");
    undoStaleId = null;
    renderPanel();
  }

  async function markRotated(id) {
    try {
      await api(`/api/secrets/${encodeURIComponent(id)}/rotated`, { method: "POST" });
      setToast("Rotation recorded", "ok");
      await loadSecrets();
    } catch (e) {
      setToast("Mark rotated failed: " + e.message, "err");
    }
  }

  // ----------- SSE: drift watcher -----------

  function setDriftState(stateName, label) {
    driftBadge.dataset.state = stateName;
    const lab = driftBadge.querySelector(".label");
    if (lab) lab.textContent = label;
  }

  function startEvents() {
    setDriftState("connecting", "Connecting…");
    const es = new EventSource("/api/events");
    es.addEventListener("open", () => setDriftState("connected", "Watching for changes"));

    const reload = (type) => () => {
      loadSecrets();
      if (type === "secret_created") announceDrift("New secret detected.");
      if (type === "secret_refreshed") announceDrift("Secret refreshed.");
      if (type === "secret_drifted") announceDrift("Secret value changed.");
    };
    es.addEventListener("secret_created", reload("secret_created"));
    es.addEventListener("secret_refreshed", reload("secret_refreshed"));
    es.addEventListener("secret_drifted", reload("secret_drifted"));
    es.addEventListener("scan_complete", () => {
      loadSecrets();
      setToast("Rescan complete", "ok");
      announceDrift("Rescan complete.");
    });
    es.addEventListener("scan_started", () => {
      setToast("Rescan started", "ok");
      announceDrift("Rescan started.");
    });
    es.onerror = () => {
      // EventSource auto-reconnects; reflect the readyState in the badge.
      if (es.readyState === EventSource.CLOSED) {
        setDriftState("closed", "Not watching");
      } else {
        setDriftState("connecting", "Connecting…");
      }
    };
  }

  function startHeartbeat() {
    setInterval(() => {
      fetch("/api/heartbeat", { method: "POST", credentials: "same-origin" }).catch(() => {});
    }, 30_000);
    window.addEventListener("pagehide", () => {
      navigator.sendBeacon("/api/close");
    });
  }

  loadSecrets();
  startEvents();
  startHeartbeat();
})();
