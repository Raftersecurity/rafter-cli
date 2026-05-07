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

(function () {
  "use strict";

  const list = document.getElementById("list");
  const panelWrap = document.getElementById("panel-wrap");
  const panel = document.getElementById("panel");
  const summary = document.getElementById("summary");
  const toast = document.getElementById("toast");

  let state = { secrets: [], reveal_policy: "session" };
  let selectedId = null;
  // Reveals are kept in-memory only — never persisted, never synced
  // across reloads. Map<secretID, value>.
  const revealed = new Map();
  // Annotation save debouncer.
  let saveTimer = null;
  let saveState = "idle";

  function setToast(text, isErr) {
    toast.textContent = text || "";
    toast.classList.toggle("err", !!isErr);
    if (text) {
      setTimeout(() => {
        if (toast.textContent === text) toast.textContent = "";
      }, 4000);
    }
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
      setToast("load failed: " + e.message, true);
    }
  }

  // Group secrets by their first file source path, falling back to
  // keystore service or the literal "(other)" bucket.
  function groupSecrets(secrets) {
    const groups = new Map();
    for (const s of secrets) {
      const found = s.found_in && s.found_in[0];
      let label, kind, perms;
      if (!found) {
        label = "(no source)"; kind = "unknown";
      } else if (found.path) {
        label = found.path; kind = "file"; perms = found.permissions;
      } else if (found.keystore) {
        label = `${found.keystore} keystore`; kind = "keystore";
      } else {
        label = "(other)"; kind = "unknown";
      }
      if (!groups.has(label)) groups.set(label, { label, kind, perms, items: [] });
      groups.get(label).items.push(s);
    }
    return Array.from(groups.values()).sort((a, b) => a.label.localeCompare(b.label));
  }

  function render() {
    const secrets = state.secrets;
    summary.textContent = secretsSummary(secrets);

    if (secrets.length === 0) {
      list.innerHTML = '<div class="empty">No secrets recorded yet. trove watches your scan roots; edit a tracked file or wait for the next scan.</div>';
      return;
    }

    const groups = groupSecrets(secrets);
    list.innerHTML = "";
    for (const g of groups) {
      const det = document.createElement("details");
      det.className = "group";
      det.open = true;
      const sum = document.createElement("summary");
      const labelSpan = document.createElement("span");
      labelSpan.textContent = g.label;
      sum.appendChild(labelSpan);
      const meta = document.createElement("span");
      meta.className = "source-meta";
      const parts = [`${g.items.length} secret${g.items.length === 1 ? "" : "s"}`];
      if (g.perms) parts.push(g.perms);
      meta.textContent = parts.join(" · ");
      sum.appendChild(meta);
      det.appendChild(sum);

      const warn = sourceWarning(g);
      if (warn) {
        const w = document.createElement("div");
        w.className = "group-warn";
        w.textContent = warn;
        det.appendChild(w);
      }

      const ul = document.createElement("ul");
      ul.className = "entries";
      for (const s of g.items) ul.appendChild(renderEntry(s));
      det.appendChild(ul);
      list.appendChild(det);
    }

    if (selectedId) {
      const stillThere = secrets.some((s) => s.id === selectedId);
      if (stillThere) renderPanel(); else closePanel();
    }
  }

  function secretsSummary(secrets) {
    if (secrets.length === 0) return "no secrets";
    const counts = new Map();
    for (const s of secrets) {
      for (const f of s.found_in || []) {
        counts.set(f.source_type, (counts.get(f.source_type) || 0) + 1);
      }
    }
    const parts = [`${secrets.length} secret${secrets.length === 1 ? "" : "s"}`];
    for (const [k, v] of counts) parts.push(`${v} ${k}`);
    return parts.join(" · ");
  }

  function sourceWarning(g) {
    if (g.kind !== "file" || !g.perms) return null;
    if (g.perms === "0644" || g.perms === "0666") {
      return `world-readable (${g.perms}). consider: chmod 600 "${g.label}"`;
    }
    return null;
  }

  function renderEntry(s) {
    const li = document.createElement("li");
    li.className = "entry";
    if (s.id === selectedId) li.classList.add("selected");
    if (s.annotation && s.annotation.stale) li.classList.add("stale");

    const key = document.createElement("span");
    key.className = "key";
    key.textContent = s.key_name;
    li.appendChild(key);

    const preview = document.createElement("span");
    preview.className = "preview";
    if (revealed.has(s.id)) {
      preview.textContent = revealed.get(s.id);
      preview.classList.add("revealed");
    } else {
      preview.textContent = s.value_preview || "—";
    }
    li.appendChild(preview);

    const actions = document.createElement("span");
    actions.className = "actions";
    const revealBtn = document.createElement("button");
    revealBtn.textContent = revealed.has(s.id) ? "hide" : "reveal";
    revealBtn.title = "Read the live value from disk";
    revealBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleReveal(s);
    });
    actions.appendChild(revealBtn);
    const annotateBtn = document.createElement("button");
    annotateBtn.textContent = "annotate";
    annotateBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      selectSecret(s.id);
    });
    actions.appendChild(annotateBtn);
    li.appendChild(actions);

    li.addEventListener("click", () => selectSecret(s.id));
    return li;
  }

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
        setToast("reveal not supported for this source", true);
      } else if (e.status === 410) {
        setToast("value is gone — drift not yet rescanned", true);
      } else {
        setToast("reveal failed: " + e.message, true);
      }
    }
  }

  function selectSecret(id) {
    selectedId = id;
    panelWrap.classList.add("open");
    renderPanel();
    // Refresh selected highlight without rebuilding the whole list.
    for (const el of list.querySelectorAll("li.entry")) el.classList.remove("selected");
    const match = list.querySelector(`li.entry[data-id="${cssEscape(id)}"]`);
    if (match) match.classList.add("selected");
    // Cheap and reliable: re-render so the selected class propagates.
    render();
  }

  function closePanel() {
    selectedId = null;
    panelWrap.classList.remove("open");
    panel.innerHTML = "";
  }

  function cssEscape(s) {
    return s.replace(/"/g, '\\"');
  }

  function renderPanel() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    if (!s) {
      closePanel();
      return;
    }
    panel.innerHTML = "";

    const closeBtn = document.createElement("button");
    closeBtn.className = "close-panel";
    closeBtn.textContent = "✕";
    closeBtn.title = "Close";
    closeBtn.addEventListener("click", closePanel);
    panel.appendChild(closeBtn);

    const h = document.createElement("h2");
    h.textContent = s.key_name;
    panel.appendChild(h);

    const prevDiv = document.createElement("div");
    prevDiv.className = "panel-preview";
    if (revealed.has(s.id)) {
      prevDiv.textContent = revealed.get(s.id);
      prevDiv.classList.add("revealed");
    } else {
      prevDiv.textContent = s.value_preview || "—";
    }
    panel.appendChild(prevDiv);

    const revealRow = document.createElement("div");
    revealRow.className = "actions-row";
    const rb = document.createElement("button");
    rb.textContent = revealed.has(s.id) ? "hide value" : "reveal value";
    rb.addEventListener("click", () => toggleReveal(s));
    revealRow.appendChild(rb);
    panel.appendChild(revealRow);

    const meta = document.createElement("dl");
    meta.className = "meta";
    meta.appendChild(field("source url", "source_url", s.annotation.source_url || "", "text"));
    meta.appendChild(field("owner", "owner", s.annotation.owner || "", "text"));
    meta.appendChild(field("notes", "notes", s.annotation.notes || "", "textarea"));
    meta.appendChild(field("rotate at", "rotate_url", s.annotation.rotate_url || "", "text"));
    meta.appendChild(field("tags", "tags", (s.annotation.tags || []).join(", "), "text"));
    panel.appendChild(meta);

    if (s.annotation.rotate_url) {
      const a = document.createElement("a");
      a.href = s.annotation.rotate_url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = "open admin page ↗";
      panel.appendChild(a);
    }

    const saveState = document.createElement("div");
    saveState.className = "save-state";
    saveState.id = "save-state";
    saveState.textContent = "";
    panel.appendChild(saveState);
    updateSaveState();

    const foundHeader = document.createElement("h3");
    foundHeader.textContent = "found in";
    panel.appendChild(foundHeader);
    const foundUL = document.createElement("ul");
    foundUL.className = "found-list";
    for (const f of s.found_in || []) {
      const li = document.createElement("li");
      if (f.path) {
        let txt = `${f.source_type}: ${f.path}`;
        if (f.line) txt += `:${f.line}`;
        if (f.permissions) txt += `  (${f.permissions})`;
        li.textContent = txt;
      } else if (f.keystore) {
        li.textContent = `${f.source_type}: ${f.keystore} ${f.service || ""}/${f.account || ""}`;
        li.classList.add("unsupported");
      } else {
        li.textContent = `${f.source_type}`;
      }
      foundUL.appendChild(li);
    }
    panel.appendChild(foundUL);

    if (s.value_history && s.value_history.length > 0) {
      const histH = document.createElement("h3");
      histH.textContent = `value history (${s.value_history.length})`;
      panel.appendChild(histH);
      const hUL = document.createElement("ul");
      hUL.className = "found-list";
      for (const h of s.value_history) {
        const li = document.createElement("li");
        li.textContent = `${h.fingerprint.slice(0, 12)}…  seen ${h.seen_at}`;
        hUL.appendChild(li);
      }
      panel.appendChild(hUL);
    }

    const actionsH = document.createElement("h3");
    actionsH.textContent = "actions";
    panel.appendChild(actionsH);
    const actions = document.createElement("div");
    actions.className = "actions-row";
    const stale = document.createElement("button");
    stale.textContent = s.annotation.stale ? "(already stale)" : "mark stale";
    stale.disabled = !!s.annotation.stale;
    stale.classList.add("warn");
    stale.addEventListener("click", () => markStale(s.id));
    actions.appendChild(stale);
    const rot = document.createElement("button");
    rot.textContent = "mark rotated";
    rot.title = "Record that you rotated this credential out-of-band. The next scan will pick up the new value.";
    rot.addEventListener("click", () => markRotated(s.id));
    actions.appendChild(rot);
    panel.appendChild(actions);
  }

  function field(label, name, value, kind) {
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

  function setSaveState(state) {
    saveState = state;
    updateSaveState();
  }
  function updateSaveState() {
    const el = document.getElementById("save-state");
    if (!el) return;
    el.classList.remove("saving", "saved", "err");
    if (saveState === "saving") { el.textContent = "saving…"; el.classList.add("saving"); }
    else if (saveState === "saved") { el.textContent = "saved"; el.classList.add("saved"); }
    else if (saveState === "err") { el.textContent = "save failed"; el.classList.add("err"); }
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
      // Mirror into local state so the next render sees the new
      // annotation without waiting for a refetch.
      const s = state.secrets.find((x) => x.id === selectedId);
      if (s) {
        s.annotation = Object.assign({}, s.annotation, ann);
      }
      setSaveState("saved");
      setTimeout(() => { if (saveState === "saved") setSaveState("idle"); }, 2000);
    } catch (e) {
      setSaveState("err");
      setToast("save failed: " + e.message, true);
    }
  }

  async function markStale(id) {
    try {
      await api(`/api/secrets/${encodeURIComponent(id)}/stale`, { method: "POST" });
      setToast("marked stale");
      await loadSecrets();
    } catch (e) {
      setToast("mark stale failed: " + e.message, true);
    }
  }

  async function markRotated(id) {
    try {
      await api(`/api/secrets/${encodeURIComponent(id)}/rotated`, { method: "POST" });
      setToast("rotation recorded");
      await loadSecrets();
    } catch (e) {
      setToast("mark rotated failed: " + e.message, true);
    }
  }

  function startEvents() {
    const es = new EventSource("/api/events");
    const reload = () => loadSecrets();
    ["secret_created", "secret_refreshed", "secret_drifted"].forEach((t) =>
      es.addEventListener(t, reload),
    );
    es.addEventListener("scan_complete", () => {
      reload();
      setToast("rescan complete");
    });
    es.addEventListener("scan_started", () => setToast("rescan started"));
    es.onerror = () => {
      // EventSource auto-reconnects; surface a soft warning.
      setToast("event stream interrupted; retrying", true);
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
