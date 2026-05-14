// trove inventory UI.
//
// Reveal policies (storage.RevealPolicy on the wire — keep the taxonomy
// stable; static_smoke_test.go pins these four strings):
//   "strict"   — never reveal; only annotations.
//   "session"  — reveal per-click; values stay in-memory only. Default.
//   "loose"    — reveal without per-secret confirmation.
//   "paranoid" — never decrypt OS keystore reads; keystore reveals 422
//                and the UI surfaces a "Decrypt off — see settings" link.
const REVEAL_POLICIES = ["strict", "session", "loose", "paranoid"];

//
// File-primary layout matching docs/design-refs/01 _ Vault Inspector.png:
//   - Top bar with metrics strip (files / secrets / overdue / due soon / perm flag)
//   - Three columns: watched-paths sidebar | selected-file detail | rotation rail
//   - One perms-warning card per selected file with a real Fix-now button
//   - Refresh-scan pill in top right; auto-rescan setting in the gear drawer
//
// Talks to the trove HTTP server via:
//   GET  /api/secrets                  → { secrets, scan_config, reveal_policy, home_dir }
//   POST /api/secrets/{id}/reveal      → { value, source_type, path }
//   POST /api/sources/chmod600         → { path, permissions, no_op }
//   POST /api/rescan                   → 202 { started_at, accepted: true } | 409 { ..., accepted: false }
//   GET  /api/events                   → SSE stream (scan_started / scan_complete / secret_*)
//   GET  /api/status                   → { name, version, watch_events_dropped? }

(function () {
  "use strict";

  // ----- DOM handles -----
  const driftBadge   = document.getElementById("drift-badge");
  const driftLabel   = document.getElementById("drift-label");
  const driftTicker  = document.getElementById("drift-ticker");
  const refreshBtn   = document.getElementById("refresh-btn");
  const lastScanEl   = document.getElementById("last-scan");
  const settingsBtn  = document.getElementById("settings-btn");
  const drawer       = document.getElementById("drawer");
  const drawerClose  = document.getElementById("drawer-close");
  const scrim        = document.getElementById("scrim");
  const versionLine  = document.getElementById("version-line");
  const watchedList  = document.getElementById("watched-list");
  const allowList    = document.getElementById("allowlist-list");
  const middleEl     = document.getElementById("middle");
  const middleEmpty  = document.getElementById("middle-empty");
  const toastRegion  = document.getElementById("toast-region");
  const hostLeaf     = document.getElementById("host-leaf");

  const mFiles   = document.getElementById("m-files");
  const mSecrets = document.getElementById("m-secrets");
  const mOverdue = document.getElementById("m-overdue");
  const mSoon    = document.getElementById("m-soon");
  const mPerm    = document.getElementById("m-perm");

  // ----- state -----
  let state = {
    secrets: [],
    home_dir: "",
    scan_config: { roots: [], excludes: [] },
    reveal_policy: "session",
  };
  let files = [];               // sorted FileGroup[]
  let selectedPath = null;
  const revealed = new Map();   // secretId -> { value, expires? }
  let lastScanAt = null;        // Date
  let autoRescanSec = 300;
  let autoRescanTimer = null;
  let rescanInflight = false;

  // ----- utils -----
  const DAY = 86400_000;

  function homeShort(p) {
    if (!p) return "";
    const h = state.home_dir;
    if (h && (p === h || p.startsWith(h + "/"))) return "~" + p.slice(h.length);
    return p;
  }
  function basename(p) { return p ? p.split("/").pop() : ""; }
  function relativeTime(t) {
    if (!t) return "—";
    const d = (Date.now() - new Date(t).getTime()) / 1000;
    if (d < 5) return "just now";
    if (d < 60) return `${Math.floor(d)}s ago`;
    if (d < 3600) return `${Math.floor(d / 60)}m ago`;
    if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
    if (d < 86400 * 365) return `${Math.floor(d / 86400)}d ago`;
    return `${Math.floor(d / (86400 * 365))}y ago`;
  }
  function setToast(text, kind) {
    if (!text) return;
    const t = document.createElement("div");
    t.className = "toast";
    if (kind === "err") t.classList.add("err");
    if (kind === "info") t.classList.add("info");
    t.textContent = text;
    toastRegion.appendChild(t);
    setTimeout(() => {
      t.style.transition = "opacity 0.2s ease";
      t.style.opacity = "0";
      setTimeout(() => t.remove(), 250);
    }, kind === "err" ? 4500 : 2200);
  }
  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
    if (!res.ok) {
      let msg = res.statusText;
      try {
        const j = await res.json();
        if (j && j.error) msg = j.error;
      } catch (_) {}
      const e = new Error(msg || "request failed");
      e.status = res.status;
      e.response = res;
      throw e;
    }
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") || "";
    return ct.startsWith("application/json") ? res.json() : res.text();
  }

  // Mode -> severity tag for the chip + warning callout.
  function modeSev(mode) {
    if (!mode) return null;
    if (mode === "0600" || mode === "0400") return "ok";
    if (mode === "0666" || mode === "0644") return "danger";
    return "warn";
  }
  function modeIsLoose(mode) {
    return !!mode && mode !== "0600" && mode !== "0400";
  }
  function modeTip(mode) {
    return ({
      "0600": "Owner-only. Recommended for files holding secrets.",
      "0400": "Owner read-only. Also fine for secrets.",
      "0640": "Owner + group. Members of the file's group can read.",
      "0660": "Owner + group, no world. Group members can read & write.",
      "0644": "World-readable. Anyone with a shell on this machine can read the file. Tighten to 0600.",
      "0664": "Group-writable. Members of the file's group can read and edit.",
      "0666": "World-readable AND writable. Treat as compromised; rotate every secret in it.",
    }[mode]) || "Octal file mode. 0600 (owner-only) is recommended.";
  }

  // Heuristic type label for a key name (no real provider DB on the wire yet).
  function inferType(keyName) {
    const k = (keyName || "").toUpperCase();
    if (k.includes("STRIPE")) return "Stripe";
    if (k.includes("ANTHROPIC") || k.includes("CLAUDE")) return "Anthropic";
    if (k.includes("OPENAI")) return "OpenAI";
    if (k.includes("SENDGRID")) return "SendGrid";
    if (k.includes("RESEND")) return "Resend";
    if (k.includes("TWILIO")) return "Twilio";
    if (k.includes("DATABASE") || k.includes("POSTGRES") || k.endsWith("_URL")) return "Postgres";
    if (k.includes("REDIS")) return "Redis";
    if (k.includes("AWS") || k.startsWith("AWS_") || k.includes("S3")) return "AWS";
    if (k.includes("GITHUB") || k.includes("GH_PAT") || k.includes("GITHUB_TOKEN")) return "GitHub";
    if (k.includes("JWT") || k.includes("SIGNING")) return "JWT";
    if (k.includes("API_KEY") || k.includes("TOKEN")) return "Token";
    return "—";
  }

  // Status pill from value_history age.
  function rotationStatus(secret) {
    const hist = secret.value_history || [];
    if (hist.length === 0) return null; // unknown
    const newest = hist[hist.length - 1];
    const t = new Date(newest.seen_at || newest.SeenAt || Date.now()).getTime();
    const ageDays = (Date.now() - t) / DAY;
    if (ageDays > 180) return "overdue";
    if (ageDays > 90)  return "soon";
    return "fresh";
  }
  function lastRotatedLabel(secret) {
    const hist = secret.value_history || [];
    if (hist.length === 0) return "—";
    return relativeTime(hist[hist.length - 1].seen_at || hist[hist.length - 1].SeenAt);
  }

  // Group secrets by their first file-source path. Each FileGroup is
  // the renderable unit in the inventory list.
  function buildFileIndex() {
    const map = new Map(); // path -> { path, found, secrets }
    for (const s of state.secrets) {
      for (const f of s.found_in || []) {
        if (!f.path) continue;
        let g = map.get(f.path);
        if (!g) {
          g = { path: f.path, found: f, secrets: [] };
          map.set(f.path, g);
        }
        g.secrets.push(s);
      }
    }
    files = Array.from(map.values()).sort((a, b) => {
      // Loose-perms files first; within loose, prefer in-git; then
      // prefer more secrets (drives selection to the busy / risky file
      // like `.env.production` in the reference); then by path.
      const aL = modeIsLoose(a.found.permissions) ? 0 : 1;
      const bL = modeIsLoose(b.found.permissions) ? 0 : 1;
      if (aL !== bL) return aL - bL;
      const aG = a.found.in_git_repo === true ? 0 : 1;
      const bG = b.found.in_git_repo === true ? 0 : 1;
      if (aG !== bG) return aG - bG;
      if (a.secrets.length !== b.secrets.length) return b.secrets.length - a.secrets.length;
      return a.path.localeCompare(b.path);
    });
  }

  function fileSeverity(g) {
    if (modeSev(g.found.permissions) === "danger") return "danger";
    if (g.found.in_git_repo === true) return "warn";
    if (modeSev(g.found.permissions) === "ok") return "ok";
    return "warn";
  }

  // ----- rendering: sidebar -----
  function renderWatched() {
    watchedList.innerHTML = "";
    if (files.length === 0) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = "no files found yet";
      watchedList.appendChild(li);
      return;
    }
    for (const g of files) {
      const li = document.createElement("li");
      li.dataset.path = g.path;
      li.dataset.sev = fileSeverity(g);
      if (g.path === selectedPath) li.dataset.active = "true";
      const dot = document.createElement("span");
      dot.className = "dot";
      const path = document.createElement("span");
      path.className = "path";
      path.textContent = homeShort(g.path);
      const count = document.createElement("span");
      count.className = "pcount";
      count.textContent = g.secrets.length;
      li.appendChild(dot);
      li.appendChild(path);
      li.appendChild(count);
      li.addEventListener("click", () => selectFile(g.path));
      li.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          selectFile(g.path);
        }
      });
      li.tabIndex = 0;
      watchedList.appendChild(li);
    }
  }

  function renderAllowlist() {
    allowList.innerHTML = "";
    const excludes = state.scan_config.excludes || [];
    if (excludes.length === 0) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = "no excludes";
      allowList.appendChild(li);
      return;
    }
    for (const pat of excludes) {
      const li = document.createElement("li");
      li.className = "allowlist";
      const dot = document.createElement("span");
      dot.className = "dot";
      const path = document.createElement("span");
      path.className = "path";
      path.textContent = pat;
      li.appendChild(dot);
      li.appendChild(path);
      allowList.appendChild(li);
    }
  }

  // ----- rendering: metrics -----
  function renderMetrics() {
    let secretsTotal = state.secrets.length;
    let overdue = 0, soon = 0, perm = 0;
    for (const s of state.secrets) {
      const r = rotationStatus(s);
      if (r === "overdue") overdue++;
      else if (r === "soon") soon++;
    }
    const loosePaths = new Set();
    for (const g of files) {
      if (modeIsLoose(g.found.permissions)) loosePaths.add(g.path);
    }
    perm = loosePaths.size;

    mFiles.textContent = files.length;
    mSecrets.textContent = secretsTotal;
    mOverdue.textContent = overdue;
    mSoon.textContent = soon;
    mPerm.textContent = perm;

    setSeverity("overdue", overdue, "danger");
    setSeverity("soon",    soon,    "warn");
    setSeverity("perm",    perm,    "danger");
  }
  function setSeverity(tile, n, danger) {
    const el = document.querySelector(`[data-tile="${tile}"]`);
    if (!el) return;
    if (n === 0) el.dataset.severity = "zero";
    else el.dataset.severity = danger;
  }

  // ----- rendering: middle column -----
  function selectFile(path) {
    selectedPath = path;
    renderWatched();
    renderMiddle();
  }

  function renderMiddle() {
    middleEl.innerHTML = "";
    if (!selectedPath || files.length === 0) {
      middleEl.appendChild(middleEmpty);
      return;
    }
    const g = files.find((x) => x.path === selectedPath) || files[0];
    selectedPath = g.path;

    const wrap = document.createElement("div");
    wrap.className = "file-detail";

    // ---- header ----
    const header = document.createElement("div");
    header.className = "file-header";
    const tag = document.createElement("div");
    tag.className = "file-tag";
    tag.textContent = "FILE";
    const row = document.createElement("div");
    row.className = "path-row";
    const h1 = document.createElement("h1");
    h1.textContent = homeShort(g.path);
    const actions = document.createElement("div");
    actions.className = "file-actions";
    actions.appendChild(makeBtn("Copy path", () => {
      navigator.clipboard && navigator.clipboard.writeText(g.path);
      setToast(`Copied ${basename(g.path)}`);
    }));
    actions.appendChild(makeBtn("Open folder", () => {
      setToast("Opening folders is coming soon", "info");
    }, true));
    row.appendChild(h1);
    row.appendChild(actions);
    header.appendChild(tag);
    header.appendChild(row);

    // chips
    const chips = document.createElement("div");
    chips.className = "file-chips";
    if (g.found.permissions) {
      const mc = document.createElement("span");
      mc.className = "chip mode";
      mc.dataset.sev = modeSev(g.found.permissions);
      mc.dataset.tip = modeTip(g.found.permissions);
      mc.tabIndex = 0;
      mc.textContent = g.found.permissions;
      chips.appendChild(mc);
    }
    if (g.found.in_git_repo === true) {
      const gc = document.createElement("span");
      gc.className = "chip in-git";
      gc.dataset.tip = "This file lives inside a git working tree. If staged it could be committed; double-check .gitignore.";
      gc.tabIndex = 0;
      gc.textContent = "in git";
      chips.appendChild(gc);
    }
    if (g.found.appears_in_git_history === true) {
      const ghc = document.createElement("span");
      ghc.className = "chip in-git";
      ghc.textContent = "in git history";
      ghc.dataset.tip = "trove found this file's path in past git commits — values may already be on a remote.";
      ghc.tabIndex = 0;
      chips.appendChild(ghc);
    }
    const sc = document.createElement("span");
    sc.className = "chip muted";
    sc.textContent = `${g.secrets.length} secret${g.secrets.length === 1 ? "" : "s"}`;
    chips.appendChild(sc);
    header.appendChild(chips);

    wrap.appendChild(header);

    // ---- perms warning ----
    if (modeIsLoose(g.found.permissions)) {
      const sev = modeSev(g.found.permissions) === "danger" ? "danger" : "warn";
      const w = document.createElement("div");
      w.className = "perms-warning";
      w.dataset.sev = sev;
      const icon = document.createElement("span");
      icon.className = "icon";
      icon.innerHTML = '<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 1l7 14H1L8 1zm0 3.5L3.6 13h8.8L8 4.5zM8 7v3.5h.01V7H8zm0 4.5h.01V12H8v-.5z"/></svg>';
      const body = document.createElement("div");
      body.className = "body";
      const head = document.createElement("div");
      head.className = "head";
      head.textContent = sev === "danger"
        ? "Permissions are too loose for a secrets file."
        : "Permissions could be tighter for a secrets file.";
      const sub = document.createElement("div");
      sub.className = "sub";
      const desc = sev === "danger"
        ? `current: ${g.found.permissions} (group + world readable) — recommended: 0600`
        : `current: ${g.found.permissions} (group readable) — recommended: 0600`;
      sub.textContent = desc;
      const cmd = document.createElement("div");
      cmd.className = "cmd";
      cmd.textContent = `$ chmod 600 ${homeShort(g.path)}`;
      body.appendChild(head);
      body.appendChild(sub);
      body.appendChild(cmd);
      const btn = document.createElement("button");
      btn.className = "fix-btn";
      btn.type = "button";
      btn.textContent = "Fix now";
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        btn.textContent = "Tightening…";
        try {
          await api("/api/sources/chmod600", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path: g.path }),
          });
          setToast(`Permissions tightened on ${basename(g.path)}`);
          await loadSecrets();
        } catch (e) {
          btn.disabled = false;
          btn.textContent = "Fix now";
          setToast(`${basename(g.path)}: ${e.message || e}`, "err");
        }
      });
      w.appendChild(icon);
      w.appendChild(body);
      w.appendChild(btn);
      wrap.appendChild(w);
    }

    // ---- secrets table ----
    const sh = document.createElement("div");
    sh.className = "section-head";
    const sht = document.createElement("span");
    sht.className = "title";
    sht.textContent = "Detected secrets";
    const shc = document.createElement("span");
    shc.className = "count";
    shc.textContent = `· ${g.secrets.length}`;
    sh.appendChild(sht);
    sh.appendChild(shc);
    wrap.appendChild(sh);

    const table = document.createElement("table");
    table.className = "secrets";
    const thead = document.createElement("thead");
    thead.innerHTML = "<tr><th>Key</th><th>Type</th><th>Last rotated</th><th>Value</th><th></th></tr>";
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    for (const s of g.secrets) {
      const tr = document.createElement("tr");
      const key = document.createElement("td");
      key.className = "key";
      key.textContent = s.key_name;
      const type = document.createElement("td");
      type.className = "type";
      type.textContent = inferType(s.key_name);
      const rot = document.createElement("td");
      rot.className = "rotated";
      rot.textContent = lastRotatedLabel(s);
      const val = document.createElement("td");
      val.className = "score";
      val.appendChild(makeRevealCell(s));
      const status = document.createElement("td");
      status.className = "status";
      const rs = rotationStatus(s);
      if (rs) {
        const pill = document.createElement("span");
        pill.className = `status-pill ${rs}`;
        pill.textContent = rs === "soon" ? "rotate soon" : rs;
        status.appendChild(pill);
      }
      tr.appendChild(key);
      tr.appendChild(type);
      tr.appendChild(rot);
      tr.appendChild(val);
      tr.appendChild(status);
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);

    middleEl.appendChild(wrap);
  }

  function makeBtn(label, onClick, disabled) {
    const b = document.createElement("button");
    b.className = "btn";
    b.type = "button";
    b.textContent = label;
    b.disabled = !!disabled;
    if (onClick) b.addEventListener("click", onClick);
    return b;
  }

  function makeRevealCell(secret) {
    const wrap = document.createElement("span");
    if (revealed.has(secret.id)) {
      const v = document.createElement("span");
      v.className = "revealed-value";
      v.textContent = revealed.get(secret.id);
      v.title = "Click to copy";
      v.addEventListener("click", () => {
        navigator.clipboard && navigator.clipboard.writeText(revealed.get(secret.id));
        setToast("Copied");
      });
      wrap.appendChild(v);
      return wrap;
    }
    const prev = document.createElement("span");
    prev.className = "mono";
    prev.style.color = "var(--fg-dim)";
    prev.textContent = secret.value_preview || "•••";
    const btn = document.createElement("button");
    btn.className = "reveal-btn";
    btn.type = "button";
    btn.textContent = "reveal";
    btn.style.marginLeft = "6px";
    btn.addEventListener("click", async () => {
      try {
        const j = await api(`/api/secrets/${encodeURIComponent(secret.id)}/reveal`, { method: "POST" });
        revealed.set(secret.id, j.value || "");
        renderMiddle();
      } catch (e) {
        setToast(`reveal: ${e.message || e}`, "err");
      }
    });
    wrap.appendChild(prev);
    wrap.appendChild(btn);
    return wrap;
  }

  // ----- loaders -----
  async function loadSecrets() {
    try {
      const body = await api("/api/secrets");
      state.secrets      = body.secrets || [];
      state.scan_config  = body.scan_config || { roots: [], excludes: [] };
      state.reveal_policy = body.reveal_policy || "session";
      state.home_dir     = body.home_dir || "";
      hostLeaf.textContent = state.home_dir ? state.home_dir.split("/").pop() || "localhost" : "localhost";
      buildFileIndex();
      if (!selectedPath || !files.find((g) => g.path === selectedPath)) {
        selectedPath = files.length > 0 ? files[0].path : null;
      }
      renderWatched();
      renderAllowlist();
      renderMetrics();
      renderMiddle();
    } catch (e) {
      setToast(`Load failed: ${e.message || e}`, "err");
    }
  }

  async function loadStatus() {
    try {
      const j = await api("/api/status");
      versionLine.textContent = `trove · ${j.version || "—"}`;
    } catch (_) {
      versionLine.textContent = "trove · (status unreachable)";
    }
  }

  // ----- rescan -----
  async function triggerRescan(silent) {
    if (rescanInflight) return;
    rescanInflight = true;
    refreshBtn.classList.add("busy");
    try {
      const res = await fetch("/api/rescan", { method: "POST", credentials: "same-origin" });
      if (res.status === 202) {
        if (!silent) setToast("Scan started");
      } else if (res.status === 409) {
        if (!silent) setToast("Scan already in progress", "info");
      } else {
        setToast(`Rescan: HTTP ${res.status}`, "err");
      }
    } catch (e) {
      setToast(`Rescan failed: ${e.message || e}`, "err");
    }
    // Don't drop the busy state here — it clears when scan_complete arrives
    // via SSE. Fallback in case SSE is closed: clear after 30s.
    setTimeout(() => {
      if (rescanInflight) finishRescan();
    }, 30_000);
  }
  function finishRescan() {
    rescanInflight = false;
    refreshBtn.classList.remove("busy");
    lastScanAt = new Date();
    updateLastScanLabel();
    loadSecrets();
  }
  function updateLastScanLabel() {
    lastScanEl.textContent = lastScanAt ? relativeTime(lastScanAt) : "—";
  }
  setInterval(updateLastScanLabel, 30_000);

  refreshBtn.addEventListener("click", () => triggerRescan(false));

  // Auto-rescan timer
  function applyAutoRescan() {
    if (autoRescanTimer) { clearInterval(autoRescanTimer); autoRescanTimer = null; }
    if (autoRescanSec <= 0) return;
    autoRescanTimer = setInterval(() => {
      if (document.hidden) return;
      triggerRescan(true);
    }, autoRescanSec * 1000);
  }
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && autoRescanSec > 0) {
      // pause/resume — nothing to do, the interval naturally skips
      // while hidden via the document.hidden check.
    }
  });

  // ----- SSE -----
  let driftES = null;
  function setDriftState(s, label) {
    driftBadge.dataset.state = s;
    driftLabel.textContent = label;
  }
  function openSSE() {
    setDriftState("connecting", "Connecting…");
    try {
      driftES = new EventSource("/api/events");
    } catch (e) {
      setDriftState("closed", "Not watching");
      return;
    }
    driftES.addEventListener("open", () => setDriftState("connected", "Watching for changes"));
    driftES.addEventListener("error", () => setDriftState("closed", "Not watching"));
    const announce = (t) => {
      const el = document.createElement("div");
      el.textContent = t;
      driftTicker.appendChild(el);
      while (driftTicker.childNodes.length > 6) driftTicker.removeChild(driftTicker.firstChild);
    };
    driftES.addEventListener("scan_started", () => {
      rescanInflight = true;
      refreshBtn.classList.add("busy");
    });
    driftES.addEventListener("scan_complete", () => {
      finishRescan();
    });
    ["secret_created", "secret_refreshed", "secret_drifted"].forEach((t) => {
      driftES.addEventListener(t, (e) => {
        try {
          const data = JSON.parse(e.data);
          announce(`${t}: ${data.key_name || ""}`);
        } catch (_) {}
        loadSecrets();
      });
    });
  }

  // ----- settings drawer -----
  let lastFocus = null;
  function openDrawer() {
    lastFocus = document.activeElement;
    scrim.classList.add("open");
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    drawerClose.focus();
  }
  function closeDrawer() {
    scrim.classList.remove("open");
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  settingsBtn.addEventListener("click", openDrawer);
  drawerClose.addEventListener("click", closeDrawer);
  scrim.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && drawer.classList.contains("open")) {
      e.preventDefault();
      closeDrawer();
    }
  });

  // auto-rescan radio
  drawer.querySelectorAll('input[name="autorescan"]').forEach((el) => {
    el.addEventListener("change", () => {
      autoRescanSec = parseInt(el.value, 10) || 0;
      localStorage.setItem("trove.auto_rescan", String(autoRescanSec));
      applyAutoRescan();
    });
  });
  // restore persisted setting
  (function () {
    const stored = parseInt(localStorage.getItem("trove.auto_rescan") || "300", 10);
    if (!Number.isNaN(stored)) {
      autoRescanSec = stored;
      const opt = drawer.querySelector(`input[name="autorescan"][value="${stored}"]`);
      if (opt) opt.checked = true;
    }
  })();

  // tile click -> filter (kept light — just scroll the list to top for now)
  document.querySelectorAll(".metric.clickable").forEach((el) => {
    el.addEventListener("click", () => {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  // ----- lifecycle -----
  // 30s heartbeat keeps the binary alive while the tab is open.
  setInterval(() => {
    fetch("/api/heartbeat", { method: "POST", credentials: "same-origin" }).catch(() => {});
  }, 30_000);
  // Close beacon on tab close so the binary exits promptly.
  window.addEventListener("pagehide", () => {
    navigator.sendBeacon && navigator.sendBeacon("/api/close");
  });

  // ----- boot -----
  loadStatus();
  loadSecrets().then(() => {
    lastScanAt = new Date();
    updateLastScanLabel();
  });
  openSSE();
  applyAutoRescan();
})();
