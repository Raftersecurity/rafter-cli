// trove inventory UI.
//
// Talks to the trove HTTP server via:
//   GET  /api/secrets                  → { secrets: [...], scan_config, reveal_policy }
//   POST /api/secrets/{id}/reveal      → { value, source_type, path }
//   PUT  /api/secrets/{id}/annotation  → 204
//   POST /api/secrets/{id}/stale       → 204
//   POST /api/secrets/{id}/rotated     → 204
//   POST /api/sources/chmod600         → { path, permissions, no_op }
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
//
// P14 layout: file-primary. Secrets are grouped first by source-family
// section, then by file path within each section. The dashboard up top
// summarises risk across all files.

(function () {
  "use strict";

  const list = document.getElementById("list");
  const panelWrap = document.getElementById("panel-wrap");
  const panel = document.getElementById("panel");
  const toastRegion = document.getElementById("toast-region");
  const driftTicker = document.getElementById("drift-ticker");
  const driftBadge = document.getElementById("drift-badge");
  const rescanBtn = document.getElementById("rescan-btn");

  // Source-family sections. Order controls render order.
  // envfile splits into "Environment files" (.env / .envrc basenames) and
  // "Config files" (other envfile-shaped paths). Source code + keychain
  // are placeholders; they show up greyed even with zero items.
  const SECTIONS = [
    {
      id: "envfile",
      title: "Environment files",
      subtitle: ".env, .envrc",
      matches: (f) => f.source_type === "envfile" && isDotEnvPath(f.path),
    },
    {
      id: "shell-rc",
      title: "Shell config",
      subtitle: ".zshrc, .bashrc, .profile",
      matches: (f) => f.source_type === "shell-rc",
    },
    {
      id: "config",
      title: "Config files",
      subtitle: "~/.aws, ~/.npmrc, ~/.config/gh, …",
      matches: (f) => f.source_type === "envfile" && !isDotEnvPath(f.path),
    },
    {
      id: "keystore",
      title: "OS keychain",
      subtitle: "coming soon",
      matches: (f) => f.source_type === "keystore",
      always: true,
      unsupported: true,
    },
    {
      id: "source-code",
      title: "Source code",
      subtitle: "coming soon, blocked on betterleaks",
      matches: (f) => f.source_type === "source-code",
      always: true,
      unsupported: true,
    },
  ];

  // Mode-octal explainer copy. The "?" icon attached to every mode chip
  // shows this text on hover/focus.
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
    if (mode === "0640" || mode === "0660") return "warn";
    return "danger";
  }
  function modeIsLoose(mode) {
    // "Loose" = anything more permissive than owner-only.
    if (!mode) return false;
    return mode !== "0600" && mode !== "0400";
  }
  function modeIsWorldReadable(mode) {
    return mode === "0644" || mode === "0666" || mode === "0664";
  }

  let state = { secrets: [], reveal_policy: "session" };
  let selectedId = null;
  const expandedFiles = new Set(); // path keys for expanded file-rows
  // Reveals are kept in-memory only — never persisted, never synced
  // across reloads. Map<secretID, value>.
  const revealed = new Map();
  // Annotation save debouncer.
  let saveTimer = null;
  let saveState = "idle";
  // Pending undo for mark-stale; null when no undo is active.
  let undoStaleTimer = null;
  let undoStaleId = null;
  // Tile filter: when a tile is "active", restrict file rows to those
  // that match the tile predicate.
  let activeFilter = null;

  // ----------- helpers -----------

  function isDotEnvPath(p) {
    if (!p) return false;
    return /(^|\/)\.env(\..+|rc)?$/.test(p);
  }

  function homePrefix() {
    return state.home_dir || "";
  }

  function displayPath(p) {
    if (!p) return "";
    const h = homePrefix();
    if (h && p.startsWith(h)) return "~" + p.slice(h.length);
    return p;
  }

  function setToast(text, kind) {
    if (!text) return;
    const t = document.createElement("div");
    t.className = "toast";
    if (kind) t.classList.add(kind);
    t.textContent = text;
    toastRegion.appendChild(t);
    setTimeout(() => {
      t.style.transition = "opacity 0.25s ease";
      t.style.opacity = "0";
      setTimeout(() => t.remove(), 250);
    }, kind === "err" ? 4500 : 1800);
  }

  function announceDrift(text) {
    if (!text) return;
    const el = document.createElement("div");
    el.textContent = text;
    driftTicker.appendChild(el);
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
      state.home_dir = body.home_dir || state.home_dir;
      render();
    } catch (e) {
      setToast("Load failed: " + e.message, "err");
    }
  }

  // ----------- grouping: file-primary -----------

  // Walks all secrets and builds, per section:
  //   files: Map<path, { found: FoundIn (first-seen), secrets: [Secret], section }>
  // Each file row consolidates the first FoundIn we saw for that path
  // (paths with multiple permissions/mode shouldn't happen, but we
  // pick the most-permissive entry to be safe with the warning chip).
  function buildFileIndex() {
    // section.id -> Map<path, FileGroup>
    const perSection = new Map();
    for (const sec of SECTIONS) perSection.set(sec.id, new Map());

    for (const s of state.secrets) {
      for (const f of s.found_in || []) {
        const sec = SECTIONS.find((sx) => sx.matches(f));
        if (!sec) continue;
        const key = f.path || `${f.keystore || ""}:${f.service || ""}:${f.account || ""}`;
        const sectMap = perSection.get(sec.id);
        if (!sectMap.has(key)) {
          sectMap.set(key, { key, found: f, secrets: [], section: sec });
        }
        const group = sectMap.get(key);
        // Prefer the worst-perm FoundIn for the chip displayed on the row.
        if (modeSeverity(f.permissions) === "danger" || (group.found && modeSeverity(group.found.permissions) === "ok" && modeSeverity(f.permissions) === "warn")) {
          group.found = f;
        }
        // De-dup secret entries (a secret can have multiple FoundIn at the same path).
        if (!group.secrets.some((x) => x.id === s.id)) {
          group.secrets.push(s);
        }
      }
    }
    return perSection;
  }

  function computeDashboard(perSection) {
    let totalFiles = 0;
    let loosePerms = 0;
    let envInGit = 0;
    const distinctSecrets = new Set();
    const filesPerType = new Map();

    for (const sec of SECTIONS) {
      const m = perSection.get(sec.id);
      if (!m) continue;
      for (const [, group] of m) {
        if (sec.unsupported) continue;
        totalFiles++;
        filesPerType.set(sec.id, (filesPerType.get(sec.id) || 0) + 1);
        const perms = group.found && group.found.permissions;
        if (modeIsLoose(perms)) loosePerms++;
        if (
          sec.id === "envfile" &&
          group.found &&
          group.found.in_git_repo === true &&
          group.secrets.length > 0
        ) {
          envInGit++;
        }
        for (const s of group.secrets) distinctSecrets.add(s.id);
      }
    }
    return { totalFiles, loosePerms, envInGit, totalSecrets: distinctSecrets.size, filesPerType };
  }

  // ----------- render: dashboard tiles -----------

  function setTile(name, value, severity, tip) {
    const num = list.parentElement.querySelector(`[data-num="${name}"]`);
    if (!num) return;
    num.textContent = value;
    const tile = num.closest(".tile");
    if (tile) {
      tile.dataset.severity = severity;
      if (tip) {
        const tipEl = tile.querySelector(".tip");
        if (tipEl) tipEl.setAttribute("data-tip", tip);
      }
    }
  }

  function renderDashboard(d) {
    setTile("files-scanned", d.totalFiles, d.totalFiles === 0 ? "zero" : "ok");
    setTile(
      "loose-perms",
      d.loosePerms,
      d.loosePerms === 0 ? "zero" : "warn"
    );
    setTile("env-in-git", d.envInGit, d.envInGit === 0 ? "zero" : "danger");
    setTile("total-secrets", d.totalSecrets, d.totalSecrets === 0 ? "zero" : "ok");

    // Files-scanned tip lists the per-type breakdown.
    const breakdown = [];
    const labelFor = { envfile: ".env", "shell-rc": "shell config", config: "config files" };
    for (const sec of SECTIONS) {
      if (sec.unsupported) continue;
      const n = d.filesPerType.get(sec.id) || 0;
      if (n > 0) breakdown.push(`${n} ${labelFor[sec.id] || sec.id}`);
    }
    const tilesScanned = document.querySelector('.tile[data-tile="files-scanned"] .tip');
    if (tilesScanned) {
      tilesScanned.setAttribute(
        "data-tip",
        breakdown.length
          ? `Distinct files where trove found at least one secret. Breakdown: ${breakdown.join(", ")}.`
          : "Distinct files where trove found at least one secret. Run a scan to populate this."
      );
    }
  }

  // ----------- render: sections + file rows -----------

  function render() {
    const perSection = buildFileIndex();
    const dash = computeDashboard(perSection);
    renderDashboard(dash);

    list.setAttribute("data-clear-selection", "");
    list.innerHTML = "";

    let totalRendered = 0;

    for (const sec of SECTIONS) {
      const m = perSection.get(sec.id);
      const fileGroups = m ? Array.from(m.values()) : [];
      // Hide non-placeholder sections that have no files.
      if (!sec.always && fileGroups.length === 0) continue;
      const det = document.createElement("details");
      det.className = "section";
      if (sec.unsupported) det.classList.add("unsupported");
      det.open = !sec.unsupported && fileGroups.length > 0;
      det.dataset.sectionId = sec.id;

      const sum = document.createElement("summary");
      const tw = document.createElement("span");
      tw.className = "section-title";
      tw.textContent = sec.title;
      sum.appendChild(tw);
      if (sec.subtitle) {
        sum.appendChild(document.createTextNode(" "));
        const sub = document.createElement("span");
        sub.className = "section-subtitle";
        sub.textContent = "(" + sec.subtitle + ")";
        sum.appendChild(sub);
      }
      const count = document.createElement("span");
      count.className = "section-count";
      const totalSecretsInSection = fileGroups.reduce((acc, g) => acc + g.secrets.length, 0);
      count.textContent = sec.unsupported && fileGroups.length === 0
        ? "—"
        : `${totalSecretsInSection}`;
      sum.appendChild(count);
      det.appendChild(sum);

      if (fileGroups.length === 0 && sec.unsupported) {
        const ph = document.createElement("div");
        ph.className = "coming-soon";
        ph.textContent = "Nothing scanned here yet.";
        det.appendChild(ph);
      } else {
        const ul = document.createElement("ul");
        ul.className = "files";

        // Sort: danger first, then warn, then alpha.
        fileGroups.sort((a, b) => {
          const sa = rowSeverity(a);
          const sb = rowSeverity(b);
          const rank = { danger: 0, warn: 1, ok: 2, "": 3 };
          if (rank[sa] !== rank[sb]) return rank[sa] - rank[sb];
          return (a.found.path || a.key).localeCompare(b.found.path || b.key);
        });

        for (const group of fileGroups) {
          if (activeFilter && !activeFilter(group)) continue;
          ul.appendChild(renderFileRow(group));
          totalRendered++;
        }
        det.appendChild(ul);
      }

      list.appendChild(det);
    }

    if (totalRendered === 0 && state.secrets.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty";
      const lede = document.createElement("div");
      lede.className = "empty-lede";
      lede.textContent = "No secrets recorded yet.";
      empty.appendChild(lede);
      empty.appendChild(document.createTextNode(
        "trove watches your scan roots for changes. Edit a tracked file or trigger a fresh scan."));
      const actions = document.createElement("div");
      actions.className = "empty-actions";
      const rescan = document.createElement("button");
      rescan.className = "primary";
      rescan.textContent = "Re-scan";
      rescan.addEventListener("click", triggerRescan);
      actions.appendChild(rescan);
      empty.appendChild(actions);
      list.appendChild(empty);
    } else if (totalRendered === 0 && activeFilter) {
      const empty = document.createElement("div");
      empty.className = "empty";
      const lede = document.createElement("div");
      lede.className = "empty-lede";
      lede.textContent = "No files match this filter.";
      empty.appendChild(lede);
      const actions = document.createElement("div");
      actions.className = "empty-actions";
      const clear = document.createElement("button");
      clear.textContent = "Clear filter";
      clear.addEventListener("click", () => { clearFilter(); render(); });
      actions.appendChild(clear);
      empty.appendChild(actions);
      list.appendChild(empty);
    }

    if (selectedId) {
      const stillThere = state.secrets.some((s) => s.id === selectedId);
      if (stillThere) renderPanel(); else closePanel();
    }
  }

  function rowSeverity(group) {
    const f = group.found || {};
    if (sec_envfile(group.section) && f.in_git_repo === true && group.secrets.length > 0) return "danger";
    if (f.appears_in_git_history === true) return "danger";
    if (modeIsWorldReadable(f.permissions)) return "warn";
    if (modeIsLoose(f.permissions)) return "warn";
    return "ok";
  }
  function sec_envfile(s) { return s && s.id === "envfile"; }

  function renderFileRow(group) {
    const li = document.createElement("li");
    li.className = "file-row";
    const sev = rowSeverity(group);
    if (sev === "danger" || sev === "warn") li.dataset.highlight = sev;
    const expanded = expandedFiles.has(group.key);
    if (expanded) li.classList.add("expanded");

    const head = document.createElement("div");
    head.className = "file-head";

    const path = document.createElement("span");
    path.className = "path";
    const shown = displayPath(group.found.path || group.key);
    // bdi wrap so ellipsis truncates the MIDDLE-ish under RTL trick.
    const bdi = document.createElement("bdi");
    bdi.textContent = shown;
    path.appendChild(bdi);
    path.title = group.found.path || group.key;
    head.appendChild(path);

    const count = document.createElement("span");
    count.className = "count";
    const n = group.secrets.length;
    count.textContent = `${n} secret${n === 1 ? "" : "s"}`;
    head.appendChild(count);

    const chips = document.createElement("span");
    chips.className = "chips";
    if (group.found.permissions) {
      chips.appendChild(modeChip(group.found.permissions));
    }
    if (group.found.in_git_repo === true) {
      const c = document.createElement("span");
      c.className = "chip in-git";
      c.textContent = "in git";
      c.title = "This file lives inside a git working tree.";
      chips.appendChild(c);
    }
    if (group.found.appears_in_git_history === true) {
      const c = document.createElement("span");
      c.className = "chip in-history";
      c.textContent = "in history";
      c.title = "This file appears in git history — assume committed.";
      chips.appendChild(c);
    }
    // Tighten button when world-readable + has secrets + in git repo (or just world-readable).
    if (modeIsWorldReadable(group.found.permissions) && group.secrets.length > 0 && group.found.path) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "chmod-btn";
      btn.textContent = "Tighten to 0600";
      const basename = (group.found.path || "").split("/").pop();
      btn.setAttribute("aria-label", `Tighten ${basename} to 0600`);
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        btn.disabled = true;
        btn.textContent = "Tightening…";
        try {
          await api("/api/sources/chmod600", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path: group.found.path }),
          });
          setToast(`Permissions tightened on ${basename}`, "ok");
          await loadSecrets();
        } catch (err) {
          btn.disabled = false;
          btn.textContent = "Tighten to 0600";
          setToast(`${basename}: ${err.message || err}`, "err");
        }
      });
      chips.appendChild(btn);
    }
    head.appendChild(chips);

    head.addEventListener("click", () => {
      if (expandedFiles.has(group.key)) expandedFiles.delete(group.key);
      else expandedFiles.add(group.key);
      render();
    });

    li.appendChild(head);

    const body = document.createElement("div");
    body.className = "file-body";
    const secrets = document.createElement("ul");
    secrets.className = "secrets-in-file";
    for (const s of group.secrets) {
      secrets.appendChild(renderSecretRow(s, group));
    }
    body.appendChild(secrets);
    li.appendChild(body);

    return li;
  }

  function modeChip(perms) {
    const sev = modeSeverity(perms); // ok | warn | danger
    const span = document.createElement("span");
    span.className = "chip mode-" + (sev || "ok");
    span.setAttribute("data-mode-octal", perms);
    span.appendChild(document.createTextNode(perms));
    const help = document.createElement("span");
    help.className = "mode-help";
    help.tabIndex = 0;
    help.setAttribute("role", "img");
    help.setAttribute("aria-label", "What does mode " + perms + " mean?");
    help.textContent = "?";
    const tip = MODE_TIPS[perms] || "Octal file mode. 0600 (owner-only) is recommended for files holding secrets.";
    help.setAttribute("data-tip", tip);
    help.addEventListener("click", (e) => e.stopPropagation());
    span.appendChild(help);
    return span;
  }

  function renderSecretRow(s, fileGroup) {
    const li = document.createElement("li");
    li.className = "secret";
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
      if (revealed.has(s.id)) copyToClipboard(revealed.get(s.id));
      else toggleReveal(s);
    });
    li.appendChild(preview);

    const right = document.createElement("span");
    right.className = "meta-right";
    if (s.annotation && s.annotation.stale) {
      const b = document.createElement("span");
      b.className = "badge";
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
    for (const el of list.querySelectorAll("li.secret")) {
      el.classList.toggle("selected", el.dataset.id === id);
    }
  }

  function closePanel() {
    selectedId = null;
    panelWrap.classList.remove("open");
    panel.innerHTML = "";
    for (const el of list.querySelectorAll("li.secret.selected")) {
      el.classList.remove("selected");
    }
  }

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && selectedId) closePanel();
  });

  function renderPanel() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    if (!s) { closePanel(); return; }
    panel.innerHTML = "";

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
      copyBtn.textContent = "Copy";
      copyBtn.addEventListener("click", () => copyToClipboard(revealed.get(s.id)));
      valActions.appendChild(copyBtn);
    }
    const saveStateEl = document.createElement("span");
    saveStateEl.className = "save-state";
    saveStateEl.id = "save-state";
    valActions.appendChild(saveStateEl);
    valSec.appendChild(valActions);
    panel.appendChild(valSec);

    // Notes (renamed from the older annotate copy)
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
      a.className = "rotate-link";
      a.textContent = "Open admin page ↗";
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
        let txt = `${f.source_type}: ${displayPath(f.path)}`;
        if (f.line) txt += `:${f.line}`;
        li.textContent = txt;
        if (f.permissions) {
          li.appendChild(document.createTextNode("  "));
          li.appendChild(modeChip(f.permissions));
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

    // Audit findings
    const auditLines = [];
    for (const f of s.found_in || []) {
      if (f.in_git_repo === true) auditLines.push("Inside a git repository.");
      if (f.in_gitignore === false && f.path) auditLines.push(`Not in .gitignore: ${displayPath(f.path)}`);
      if (f.appears_in_git_history === true) auditLines.push("Appears in git history — assume committed.");
    }
    if (auditLines.length > 0) {
      const auditSec = document.createElement("section");
      auditSec.classList.add("audit");
      const aH = document.createElement("h3");
      aH.textContent = "Audit findings";
      auditSec.appendChild(aH);
      const aUL = document.createElement("ul");
      aUL.className = "found-list";
      for (const ln of auditLines) {
        const li = document.createElement("li");
        li.textContent = ln;
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
    rot.title = "Record that you rotated this credential out-of-band.";
    rot.addEventListener("click", () => markRotated(s.id));
    actions.appendChild(rot);
    actSec.appendChild(actions);

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
    const ann = { source_url: "", owner: "", notes: "", rotate_url: "", tags: [] };
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

  function setSaveState(s) { saveState = s; updateSaveState(); }
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

  // ----------- tile filters -----------

  function setFilter(name) {
    clearFilter();
    if (name === "loose-perms") {
      activeFilter = (g) => modeIsLoose(g.found && g.found.permissions);
    } else if (name === "env-in-git") {
      activeFilter = (g) =>
        g.section.id === "envfile" &&
        g.found && g.found.in_git_repo === true &&
        g.secrets.length > 0;
    } else {
      activeFilter = null;
    }
    if (activeFilter) {
      // Mark the active tile.
      document.querySelectorAll(".tile").forEach((t) => {
        t.classList.toggle("active", t.dataset.tile === name);
      });
    }
  }
  function clearFilter() {
    activeFilter = null;
    document.querySelectorAll(".tile.active").forEach((t) => t.classList.remove("active"));
  }

  function bindTileClicks() {
    document.querySelectorAll(".tile").forEach((tile) => {
      tile.addEventListener("click", (e) => {
        // Don't trigger when clicking the "?" help bubble.
        if (e.target.closest(".tip")) return;
        const name = tile.dataset.tile;
        if (name === "files-scanned" || name === "total-secrets") return;
        if (activeFilter && tile.classList.contains("active")) {
          clearFilter();
        } else {
          setFilter(name);
        }
        render();
      });
      tile.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          tile.click();
        }
      });
    });
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
      if (type === "secret_created") {
        setToast("New secret detected", "drift");
        announceDrift("New secret detected.");
      }
      if (type === "secret_refreshed") {
        setToast("Secret refreshed", "drift");
        announceDrift("Secret refreshed.");
      }
      if (type === "secret_drifted") {
        setToast("Secret value changed", "drift");
        announceDrift("Secret value changed.");
      }
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
      if (es.readyState === EventSource.CLOSED) setDriftState("closed", "Not watching");
      else setDriftState("connecting", "Connecting…");
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

  // The backend has no manual /api/rescan endpoint yet — the watcher
  // handles drift automatically. Re-scan refreshes the snapshot the
  // page is showing; a real scan is triggered by file mutations on the
  // watcher side.
  async function triggerRescan() {
    await loadSecrets();
    setToast("Refreshed", "ok");
  }
  if (rescanBtn) {
    rescanBtn.addEventListener("click", triggerRescan);
  }

  bindTileClicks();
  loadSecrets();
  startEvents();
  startHeartbeat();
})();
