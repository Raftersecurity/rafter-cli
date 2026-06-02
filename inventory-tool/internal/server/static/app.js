// Rafter Secrets — inventory UI, written for people who have never opened
// a terminal.
//
// The whole job of this file is translation: the server speaks in
// fingerprints, octal permissions, and source_types; the person reading
// the screen speaks in "is this safe?" We render the second from the first.
//
// Server API (contract):
//   GET  /api/secrets                  -> { secrets:[...], scan_config, reveal_policy }
//   POST /api/secrets                  -> create a manual entry, returns the secret
//   POST /api/secrets/{id}/reveal      -> { value, source_type, path }
//   PUT  /api/secrets/{id}/annotation  -> 204
//   POST /api/secrets/{id}/stale       -> 204
//   POST /api/secrets/{id}/rotated     -> 204
//   GET  /api/events                   -> SSE drift stream
// The session cookie authenticates every request (credentials:same-origin).

(function () {
  "use strict";

  const content = document.getElementById("content");
  const panelWrap = document.getElementById("panel-wrap");
  const panel = document.getElementById("panel");
  const toast = document.getElementById("toast");
  const scanStatus = document.getElementById("scan-status");
  const scanStatusText = document.getElementById("scan-status-text");
  const modalRoot = document.getElementById("modal-root");

  let state = { secrets: [], reveal_policy: "session", scan_home: null };
  let selectedId = null;
  let view = localStorage.getItem("rafter.view") || "secret"; // secret | folder | project
  const revealed = new Map(); // id -> plaintext, in-memory only
  let saveTimer = null;
  let saveState = "idle";
  let introDismissed = localStorage.getItem("rafter.introDismissed") === "1";

  // ---- tiny DOM helpers ------------------------------------------------
  function el(tag, attrs, kids) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === "class") e.className = attrs[k];
      else if (k === "html") e.innerHTML = attrs[k];
      else if (k === "text") e.textContent = attrs[k];
      else if (k.startsWith("on") && typeof attrs[k] === "function") e.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    }
    if (kids) for (const c of [].concat(kids)) if (c != null) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    return e;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  function setToast(text, isErr) {
    toast.textContent = text || "";
    toast.classList.toggle("err", !!isErr);
    if (text) setTimeout(() => { if (toast.textContent === text) toast.textContent = ""; }, 4000);
  }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
    if (!res.ok) {
      let msg = res.statusText;
      try { const b = await res.json(); if (b && b.error) msg = b.error; } catch (_) {}
      const err = new Error(msg || "request failed");
      err.status = res.status;
      throw err;
    }
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") || "";
    return ct.startsWith("application/json") ? res.json() : res.text();
  }

  // ---- vendor / type recognition --------------------------------------
  const VENDORS = [
    [/stripe|sk_live|sk_test|rk_live/i, "Stripe", "St"],
    [/(anthropic|claude|sk-ant)/i, "Anthropic", "An"],
    [/(openai|sk-proj|sk-[A-Za-z0-9]{20})/i, "OpenAI", "Ai"],
    [/(github|gh_|ghp_|gho_|^gh_pat)/i, "GitHub", "Gh"],
    [/(aws|akia|secret_access_key|aws_access)/i, "AWS", "Aw"],
    [/(google|gcp|gcloud|firebase)/i, "Google", "Go"],
    [/sendgrid|sg\./i, "SendGrid", "Sg"],
    [/twilio/i, "Twilio", "Tw"],
    [/slack|xox[baprs]/i, "Slack", "Sl"],
    [/(postgres|psql|database_url|db_url|mysql|mongo)/i, "Database", "Db"],
    [/jwt|signing/i, "JWT / signing key", "Jw"],
    [/resend/i, "Resend", "Re"],
    [/vercel/i, "Vercel", "Ve"],
    [/supabase/i, "Supabase", "Sb"],
    [/(npm|registry)/i, "npm", "Np"],
    [/docker/i, "Docker", "Dk"],
    [/(secret|token|key|password|passwd|pat|api)/i, "Credential", "Key"],
  ];
  function vendorFor(keyName) {
    const k = keyName || "";
    for (const [re, name, chip] of VENDORS) if (re.test(k)) return { name, chip };
    return { name: "Saved value", chip: (k.slice(0, 2) || "··").toUpperCase() };
  }

  // ---- risk model ------------------------------------------------------
  function parsePerm(p) {
    if (!p) return null;
    const m = /(\d{3,4})$/.exec(p);
    if (!m) return null;
    const oct = m[1].slice(-3);
    return { group: (parseInt(oct[1], 8) & 4) !== 0, other: (parseInt(oct[2], 8) & 4) !== 0, raw: p };
  }
  function isManual(s) { return typeof s.id === "string" && s.id.indexOf("manual:") === 0; }
  function fileLocations(s) { return (s.found_in || []).filter((f) => f.path && f.source_type !== "manual"); }
  function exposure(s) {
    let worst = null;
    for (const f of fileLocations(s)) {
      const pm = parsePerm(f.permissions);
      if (!pm) continue;
      if (pm.other) return { level: "other", perm: pm, path: f.path };
      if (pm.group && !worst) worst = { level: "group", perm: pm, path: f.path };
    }
    return worst;
  }
  function isDuplicated(s) { return fileLocations(s).length > 1; }
  function isStale(s) { return !!(s.annotation && s.annotation.stale); }
  function projectsOf(s) { return (s.annotation && s.annotation.tags) || []; }
  function needsAttention(s) {
    if (isStale(s)) return false;
    return !!exposure(s) || isDuplicated(s);
  }

  // ---- data load -------------------------------------------------------
  async function loadSecrets() {
    try {
      const body = await api("/api/secrets");
      state.secrets = body.secrets || [];
      state.reveal_policy = body.reveal_policy || "session";
      const roots = (body.scan_config && body.scan_config.roots) || [];
      state.scan_home = roots.slice().sort((a, b) => a.length - b.length)[0] || null;
      render();
    } catch (e) {
      clear(content);
      content.appendChild(el("div", { class: "empty" }, [
        el("div", { class: "big", text: "⚠️" }),
        el("h3", { text: "Couldn't reach Rafter Secrets" }),
        el("p", { text: e.message + ". Try reloading this page." }),
      ]));
    }
  }

  // ---- render ----------------------------------------------------------
  function render() {
    clear(content);
    if (!introDismissed && state.secrets.length > 0) content.appendChild(renderIntro());

    if (state.secrets.length === 0) { content.appendChild(renderEmpty()); return; }

    content.appendChild(renderStats());

    const attn = state.secrets.filter(needsAttention);
    if (attn.length > 0 && view !== "folder") {
      content.appendChild(sectionHeader("Worth a look", attn.length, "attn"));
      content.appendChild(renderSecretList(attn));
    }

    if (view === "folder") {
      content.appendChild(sectionHeader("Where your secrets live", null, ""));
      content.appendChild(renderFolderTree(state.secrets));
    } else if (view === "project") {
      content.appendChild(renderProjectView(state.secrets));
    } else {
      content.appendChild(sectionHeader("All secrets", state.secrets.length, ""));
      content.appendChild(renderSecretList(state.secrets.slice().sort(byAttention)));
    }

    if (selectedId) {
      if (state.secrets.some((s) => s.id === selectedId)) renderPanel();
      else closePanel();
    }
  }
  function byAttention(a, b) {
    return (needsAttention(b) ? 1 : 0) - (needsAttention(a) ? 1 : 0) || (a.key_name || "").localeCompare(b.key_name || "");
  }

  function renderIntro() {
    return el("div", { class: "intro" }, [
      el("div", { class: "ico", text: "🔎" }),
      el("div", {}, [
        el("h2", { text: "The passwords and keys saved on this computer." }),
        el("p", { html: "These are the secrets apps and tools store in plain files — API keys, database passwords, access tokens. Anything saved in plain text here can be read by other programs you run, <b style=\"color:var(--text-dim)\">including AI coding agents</b>. Rafter Secrets gathered them so you can see what's here, tag them by project, and keep notes. <b style=\"color:var(--text-dim)\">Nothing is changed or uploaded.</b>" }),
      ]),
      el("button", { class: "x", title: "Dismiss", onclick: () => { introDismissed = true; localStorage.setItem("rafter.introDismissed", "1"); render(); }, text: "×" }),
    ]);
  }

  function renderEmpty() {
    return el("div", { class: "empty" }, [
      el("div", { class: "big", text: "✨" }),
      el("h3", { text: "Nothing saved in the open yet." }),
      el("p", { html: "Rafter Secrets didn't find any passwords or keys sitting in plain files. It keeps watching — and you can <b style=\"color:var(--text-dim)\">add one yourself</b> with the button up top to start tracking it." }),
      el("div", { style: "margin-top:18px" }, [ el("button", { class: "primary", onclick: openAddSecret, text: "+ Add a secret" }) ]),
    ]);
  }

  function renderStats() {
    const secrets = state.secrets.filter((s) => !isStale(s));
    const exposed = secrets.filter((s) => exposure(s)).length;
    const dup = secrets.filter(isDuplicated).length;
    const locs = new Set();
    for (const s of secrets) for (const f of fileLocations(s)) locs.add(f.path);
    const wrap = el("div", { class: "stats" });
    wrap.appendChild(statCard(secrets.length, "secrets tracked", "passwords, keys & tokens", "calm"));
    wrap.appendChild(statCard(locs.size, locs.size === 1 ? "file" : "files", "where they're stored", ""));
    wrap.appendChild(statCard(exposed, "readable by apps & agents", "any program on this computer — including AI agents", exposed > 0 ? "danger" : "calm"));
    wrap.appendChild(statCard(dup, "stored in 2+ places", "easy to lose track of", dup > 0 ? "attn" : "calm"));
    return wrap;
  }
  function statCard(n, lbl, sub, cls) {
    return el("div", { class: "stat " + (cls || "") }, [
      el("div", { class: "n", text: String(n) }),
      el("div", { class: "lbl", text: lbl }),
      el("div", { class: "sub", text: sub }),
    ]);
  }
  function sectionHeader(label, count, cls) {
    return el("div", { class: "section-h " + (cls || "") }, [
      el("span", { text: label }),
      count != null ? el("span", { class: "count", text: count }) : null,
    ]);
  }

  // ---- secret-level list (default) ------------------------------------
  function renderSecretList(secrets) {
    const ul = el("ul", { class: "entries", style: "border:1px solid var(--border);border-radius:12px;background:var(--panel-2);overflow:hidden;" });
    secrets.forEach((s, i) => { const li = renderEntry(s); if (i === 0) li.style.borderTop = "none"; ul.appendChild(li); });
    return ul;
  }

  function renderEntry(s) {
    const v = vendorFor(s.key_name);
    const li = el("li", { class: "entry" + (s.id === selectedId ? " selected" : "") + (isStale(s) ? " stale" : ""), "data-id": s.id });
    li.appendChild(el("span", { class: "type-chip", text: v.chip, title: v.name }));

    const mid = el("div", { style: "min-width:0;" }, [
      el("div", { class: "key", text: s.key_name, title: s.key_name }),
    ]);
    const projects = projectsOf(s);
    if (projects.length) {
      const chips = el("div", { class: "chips" });
      for (const p of projects) chips.appendChild(el("span", { class: "chip", text: p }));
      mid.appendChild(chips);
    }
    li.appendChild(mid);

    // location summary
    const locs = fileLocations(s);
    let locText;
    if (isManual(s)) locText = "added by you";
    else if (locs.length === 0) locText = "—";
    else if (locs.length === 1) locText = splitPath(locs[0].path).base;
    else locText = locs.length + " places";
    li.appendChild(el("span", { class: "val", text: locText, title: locs.map((f) => prettyPath(f.path)).join("\n") }));

    const right = el("span", { class: "right" });
    if (isManual(s)) right.appendChild(el("span", { class: "badge-manual", text: "yours" }));
    right.appendChild(entryPill(s));
    li.appendChild(right);

    li.addEventListener("click", () => selectSecret(s.id));
    return li;
  }

  function entryPill(s) {
    if (isStale(s)) return statusPill("", "not in use");
    const ex = exposure(s);
    if (ex && ex.level === "other") return statusPill("danger", "readable by agents");
    if (ex && ex.level === "group") return statusPill("warn", "readable by your group");
    if (isDuplicated(s)) return statusPill("info", "in " + fileLocations(s).length + " places");
    if (isManual(s)) return statusPill("", "tracked");
    return statusPill("ok", "looks fine");
  }
  function statusPill(cls, text) {
    return el("span", { class: "pill " + (cls || "") }, [ cls ? el("span", { class: "pd" }) : null, document.createTextNode(text) ]);
  }

  // ---- folder hierarchy view ------------------------------------------
  function renderFolderTree(secrets) {
    const root = { name: "", dirs: new Map(), items: [] };
    for (const s of secrets) {
      for (const f of fileLocations(s)) {
        const rel = prettyPath(dirOf(f.path));
        const segs = rel.split("/").filter(Boolean);
        let node = root;
        for (const seg of segs) {
          if (!node.dirs.has(seg)) node.dirs.set(seg, { name: seg, dirs: new Map(), items: [] });
          node = node.dirs.get(seg);
        }
        node.items.push({ secret: s, file: f });
      }
    }
    const wrap = el("div", { class: "tree" });
    const anyManual = secrets.some(isManual);
    renderTreeNode(root, "", 0, wrap, true);
    if (wrap.childElementCount === 0) {
      wrap.appendChild(el("div", { class: "tree-row", text: anyManual ? "Your manually-added secrets have no folder — see the By secret view." : "No file-based secrets found." }));
    }
    return wrap;
  }
  // Render a node, path-compressing single-child dir chains for readability.
  function renderTreeNode(node, prefix, depth, out, isRoot) {
    let name = node.name;
    // compress: while exactly one child dir and no items here, fold names.
    let n = node;
    while (!isRoot && n.dirs.size === 1 && n.items.length === 0) {
      const only = n.dirs.values().next().value;
      name = name + "/" + only.name;
      n = only;
    }
    if (!isRoot) {
      const exposedHere = n.items.some((it) => parsePermOther(it.file));
      const row = el("div", { class: "tree-row dir" + (exposedHere ? " outlier" : ""), style: "padding-left:" + (14 + depth * 16) + "px" }, [
        el("span", { class: "dir-ico", html: ICON.folder }),
        el("span", { text: name + "/" }),
        el("span", { class: "dir-count", text: exposedHere ? "readable by agents" : (n.items.length ? n.items.length + (n.items.length === 1 ? " secret" : " secrets") : "") }),
      ]);
      out.appendChild(row);
    }
    const childDepth = isRoot ? 0 : depth + 1;
    // secrets directly in this dir
    for (const it of n.items.sort((a, b) => (a.secret.key_name || "").localeCompare(b.secret.key_name || ""))) {
      const s = it.secret;
      const exposed = parsePermOther(it.file);
      const row = el("div", { class: "tree-row secret" + (s.id === selectedId ? " selected" : "") + (isStale(s) ? " stale" : ""), "data-id": s.id, style: "padding-left:" + (14 + childDepth * 16) + "px" }, [
        el("span", { class: "twig", text: "└" }),
        el("span", { class: "type-chip", text: vendorFor(s.key_name).chip, style: "width:20px;height:20px;font-size:9px" }),
        el("span", { class: "k", text: s.key_name }),
        el("span", { class: "dir-count" }, [ exposed ? statusPill("danger", "readable by agents") : (isStale(s) ? statusPill("", "not in use") : null) ]),
      ]);
      row.addEventListener("click", () => selectSecret(s.id));
      out.appendChild(row);
    }
    // child dirs, sorted with exposed ones first to surface outliers
    const kids = Array.from(n.dirs.values()).sort((a, b) => a.name.localeCompare(b.name));
    for (const kid of kids) renderTreeNode(kid, "", childDepth, out, false);
  }
  function parsePermOther(file) { const pm = parsePerm(file.permissions); return !!(pm && pm.other); }

  // ---- project view ---------------------------------------------------
  function renderProjectView(secrets) {
    const groups = new Map();
    const untagged = [];
    for (const s of secrets) {
      const ps = projectsOf(s);
      if (ps.length === 0) { untagged.push(s); continue; }
      for (const p of ps) { if (!groups.has(p)) groups.set(p, []); groups.get(p).push(s); }
    }
    const frag = document.createDocumentFragment();
    const names = Array.from(groups.keys()).sort();
    for (const name of names) {
      frag.appendChild(sectionHeader(name, groups.get(name).length, ""));
      frag.appendChild(renderSecretList(groups.get(name).slice().sort(byAttention)));
    }
    if (untagged.length) {
      frag.appendChild(sectionHeader("No project yet", untagged.length, ""));
      frag.appendChild(renderSecretList(untagged.slice().sort(byAttention)));
    }
    if (names.length === 0) {
      const hint = el("div", { class: "helpcard", style: "margin:12px 2px" , html: "Tag a secret with a project to group it here — open any secret and add a project under <b>Projects</b>, or set one when you add a secret." });
      frag.insertBefore(hint, frag.firstChild);
    }
    const box = el("div"); box.appendChild(frag); return box;
  }

  // ---- reveal ----------------------------------------------------------
  async function toggleReveal(s) {
    if (revealed.has(s.id)) { revealed.delete(s.id); render(); return; }
    try {
      const body = await api(`/api/secrets/${encodeURIComponent(s.id)}/reveal`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
      revealed.set(s.id, body.value);
      render();
    } catch (e) {
      if (e.status === 422) setToast("This one has no live value to show (it's keystore-, code-, or you-added).", true);
      else if (e.status === 410) setToast("That value just changed on disk — refreshing.", true);
      else setToast("Couldn't read the value: " + e.message, true);
    }
  }

  // ---- selection / panel ----------------------------------------------
  function selectSecret(id) {
    selectedId = id;
    panelWrap.classList.add("open");
    renderPanel();
    for (const e of content.querySelectorAll("[data-id]")) e.classList.toggle("selected", e.getAttribute("data-id") === id);
  }
  function closePanel() {
    selectedId = null; panelWrap.classList.remove("open"); clear(panel);
    for (const e of content.querySelectorAll(".selected")) e.classList.remove("selected");
  }

  function renderPanel() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    if (!s) { closePanel(); return; }
    const v = vendorFor(s.key_name);
    clear(panel);

    panel.appendChild(el("div", { class: "panel-top" }, [
      el("span", { class: "type-chip", text: v.chip }),
      el("div", { class: "titles" }, [
        el("h2", { text: s.key_name }),
        el("div", { class: "type-name", text: v.name + (isManual(s) ? " · added by you" : "") + (isStale(s) ? " · marked not in use" : "") }),
      ]),
      el("button", { class: "ghost close", title: "Close", onclick: closePanel, text: "×" }),
    ]));

    // value
    const isRev = revealed.has(s.id);
    if (isManual(s)) {
      panel.appendChild(el("div", { class: "value-box" }, [ el("span", { class: "v hidden", text: "added by you — no file value tracked" }) ]));
    } else {
      panel.appendChild(el("div", { class: "value-box" }, [
        el("span", { class: "v " + (isRev ? "revealed" : "hidden"), text: isRev ? revealed.get(s.id) : "••••••••••••" }),
        isRev ? el("button", { class: "sm", onclick: () => toggleReveal(s), text: "Hide" }) : null,
        isRev ? el("button", { class: "sm", onclick: () => copy(revealed.get(s.id), "Value copied"), text: "Copy" }) : null,
        !isRev ? el("button", { class: "sm", onclick: () => toggleReveal(s), text: "Show value" }) : null,
      ]));
    }

    // findings
    const findings = buildFindings(s);
    panel.appendChild(el("div", { class: "block-h", text: "What this means" }));
    if (findings.length === 0) {
      panel.appendChild(el("div", { class: "finding calm" }, [
        el("div", { class: "f-head" }, [ el("span", { html: ICON.check }), document.createTextNode(isManual(s) ? "Tracked by you." : "Nothing alarming here.") ]),
        el("p", { class: "f-body", text: isManual(s)
          ? "You added this manually, so Rafter Secrets isn't watching a file for it. Keep a note of where it lives and where to replace it below."
          : "This secret is stored in a file only you can read, and it was only found in one place. Still worth noting where it came from — below — so future-you remembers." }),
      ]));
    } else for (const f of findings) panel.appendChild(f);

    // projects (easy tagging)
    panel.appendChild(el("div", { class: "block-h", text: "Projects" }));
    panel.appendChild(renderProjectEditor(s));

    // where it lives
    if (!isManual(s) || (s.found_in || []).length) {
      panel.appendChild(el("div", { class: "block-h", text: "Where it's stored" }));
      panel.appendChild(renderLocations(s));
    }

    // history
    if (s.value_history && s.value_history.length > 1) {
      panel.appendChild(el("div", { class: "block-h", text: "History" }));
      panel.appendChild(el("p", { class: "f-body", style: "margin:0;color:var(--muted)", html: "Rafter Secrets has seen this value change <b style=\"color:var(--text-dim)\">" + (s.value_history.length - 1) + "</b> time" + (s.value_history.length - 1 === 1 ? "" : "s") + " since it started watching. Changing a key regularly is a good habit." }));
    }

    // notes
    panel.appendChild(el("div", { class: "block-h", text: "Notes" }));
    panel.appendChild(renderNotes(s));

    // actions
    panel.appendChild(el("div", { class: "panel-actions" }, [
      el("button", { class: "sm", title: "Tell Rafter Secrets you've replaced this with a new one. It keeps your notes and tracks the change.", onclick: () => markRotated(s.id), text: "I've replaced this" }),
      isStale(s) ? el("button", { class: "sm", disabled: "", text: "Marked not in use" })
        : el("button", { class: "sm", title: "Grey this out — you're not using it anymore. Nothing is deleted.", onclick: () => markStale(s.id), text: "I don't use this" }),
    ]));
  }

  function buildFindings(s) {
    const out = [];
    const ex = exposure(s);
    if (ex) {
      const sp = splitPath(ex.path);
      const danger = ex.level === "other";
      out.push(el("div", { class: "finding " + (danger ? "danger" : "warn") }, [
        el("div", { class: "f-head" }, [ el("span", { html: ICON.warn }), document.createTextNode(danger ? "Readable by any app or AI agent on this computer" : "Readable by other accounts in your group") ]),
        el("p", { class: "f-body", html:
          "The file <code>" + escapeHtml(sp.base) + "</code> is set so that " +
          (danger ? "<b>any program running as you</b> — every app you've installed, and any <b>AI coding agent</b> (Claude Code, Cursor, Copilot, …) you run" : "<b>other users in your group</b>") +
          " can open it and read this secret in plain text. On your own laptop that's usually low-risk; on a shared or work machine, or if you run AI agents with broad file access, it's worth tightening." }),
        el("div", { class: "f-actions" }, [
          el("button", { class: "sm", title: "Copies a one-line command. Paste it into a terminal (or send it to whoever set up your computer) to make the file private to you. Rafter Secrets won't run it for you.", onclick: () => copy("chmod 600 " + shQuote(ex.path), "Command copied — paste it into a terminal"), text: "Copy the fix" }),
          el("span", { class: "loc-sub", html: "makes the file readable by <b style=\"color:var(--text-dim)\">you only</b>" }),
        ]),
      ]));
    }
    if (isDuplicated(s)) {
      const n = fileLocations(s).length;
      out.push(el("div", { class: "finding warn" }, [
        el("div", { class: "f-head" }, [ el("span", { html: ICON.copy }), document.createTextNode("Stored in " + n + " different files") ]),
        el("p", { class: "f-body", html: "The same secret lives in <b>" + n + " places</b> (listed below). Not dangerous on its own, but if you ever replace this key you'll need to update it everywhere — or the apps using the old copies will break." }),
      ]));
    }
    for (const f of s.found_in || []) {
      if (f.appears_in_git_history) {
        out.push(el("div", { class: "finding danger" }, [
          el("div", { class: "f-head" }, [ el("span", { html: ICON.warn }), document.createTextNode("Saved into a project's history") ]),
          el("p", { class: "f-body", html: "This was committed to a code project's history, so it may already have been shared or uploaded. The safe move is to <b>replace it</b> with a new key — add the replace-link below so it's one click next time." }),
        ]));
        break;
      }
    }
    return out;
  }

  function renderLocations(s) {
    const ul = el("ul", { class: "locations" });
    for (const f of s.found_in || []) {
      if (f.source_type === "manual") {
        ul.appendChild(el("li", {}, [ el("span", { class: "loc-ico", html: ICON.file }), el("div", {}, [ el("div", { class: "loc-path", text: prettyPath(f.path) }), el("div", { class: "loc-sub", text: "you noted this location" }) ]) ]));
      } else if (f.path) {
        const sp = splitPath(f.path); const pm = parsePerm(f.permissions); const sub = [];
        if (f.line) sub.push("line " + f.line);
        if (pm && pm.other) sub.push("readable by apps & agents");
        else if (pm && pm.group) sub.push("readable by your group");
        else if (pm) sub.push("private to you");
        ul.appendChild(el("li", {}, [ el("span", { class: "loc-ico", html: ICON.file }), el("div", { style: "min-width:0" }, [ el("div", { class: "loc-path", text: sp.dir + sp.base, title: f.path }), sub.length ? el("div", { class: "loc-sub", text: sub.join(" · ") }) : null ]) ]));
      } else if (f.keystore) {
        ul.appendChild(el("li", { class: "soon" }, [ el("span", { class: "loc-ico", html: ICON.lock }), el("div", {}, [ el("div", { class: "loc-path", text: keystoreName(f.keystore) + (f.account ? " · " + f.account : "") }), el("div", { class: "loc-sub", text: "kept in your system vault — viewing it here is coming soon" }) ]) ]));
      }
    }
    return ul;
  }
  function keystoreName(k) {
    if (/keychain/i.test(k)) return "macOS Keychain";
    if (/secret-service|gnome|kwallet/i.test(k)) return "System keyring";
    return k + " keystore";
  }

  // ---- project chip editor (easy tagging) -----------------------------
  function renderProjectEditor(s) {
    const wrap = el("div", { class: "chips" });
    const ps = projectsOf(s);
    for (const p of ps) {
      wrap.appendChild(el("span", { class: "chip" }, [ document.createTextNode(p), el("span", { class: "x", title: "Remove", text: "×", onclick: () => setProjects(s, ps.filter((x) => x !== p)) }) ]));
    }
    const addChip = el("span", { class: "chip add", text: "+ project" });
    addChip.addEventListener("click", () => {
      const input = el("input", { type: "text", placeholder: "project name", style: "width:130px;font:inherit;font-size:12px;background:var(--panel-2);color:var(--text);border:1px solid var(--focus);border-radius:999px;padding:2px 9px" });
      wrap.replaceChild(input, addChip);
      input.focus();
      const commit = () => { const val = input.value.trim(); if (val && ps.indexOf(val) < 0) setProjects(s, ps.concat([val])); else renderPanel(); };
      input.addEventListener("keydown", (e) => { if (e.key === "Enter") commit(); if (e.key === "Escape") renderPanel(); });
      input.addEventListener("blur", commit);
    });
    wrap.appendChild(addChip);
    return wrap;
  }
  async function setProjects(s, projects) {
    const a = s.annotation || {};
    const ann = { source_url: a.source_url || "", owner: a.owner || "", notes: a.notes || "", rotate_url: a.rotate_url || "", tags: projects };
    try {
      await api(`/api/secrets/${encodeURIComponent(s.id)}/annotation`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ann) });
      s.annotation = Object.assign({}, a, ann);
      render();
    } catch (e) { setToast("Couldn't update projects: " + e.message, true); }
  }

  // ---- notes form ------------------------------------------------------
  function renderNotes(s) {
    const a = s.annotation || {};
    const form = el("div", { class: "notes-form" });
    form.appendChild(noteField("Where did this come from?", "source_url", a.source_url, "e.g. https://dashboard.stripe.com", "A link to the page where this key was created."));
    form.appendChild(noteField("Where do you replace it?", "rotate_url", a.rotate_url, "link to create a new one", "When you need a fresh key, this is where you'd go."));
    form.appendChild(noteField("Who owns it?", "owner", a.owner, "e.g. you, or a teammate", null));
    form.appendChild(noteField("Notes", "notes", a.notes, "anything future-you should know", null, true));
    form.appendChild(el("div", { class: "save-state", id: "save-state" }));
    const rotateHref = safeUrl(a.rotate_url);
    if (rotateHref) form.appendChild(el("a", { href: rotateHref, target: "_blank", rel: "noopener noreferrer", style: "display:inline-block;margin-top:4px" }, [ el("button", { class: "primary sm", text: "Go replace this key ↗" }) ]));
    return form;
  }
  function noteField(label, name, value, placeholder, help, textarea) {
    const lbl = el("div", { class: "lbl" }, [ document.createTextNode(label), help ? el("span", { class: "help", title: help, text: "?" }) : null ]);
    const input = textarea ? el("textarea", { placeholder }) : el("input", { type: "text", placeholder });
    input.value = value || ""; input.dataset.field = name;
    input.addEventListener("input", scheduleSave);
    return el("label", {}, [ lbl, input ]);
  }
  function scheduleSave() { if (saveTimer) clearTimeout(saveTimer); setSaveState("saving"); saveTimer = setTimeout(saveAnnotation, 600); }
  function setSaveState(st) { saveState = st; const e = document.getElementById("save-state"); if (!e) return; e.className = "save-state " + (st === "idle" ? "" : st); e.textContent = st === "saving" ? "saving…" : st === "saved" ? "saved ✓" : st === "err" ? "couldn't save" : ""; }
  async function saveAnnotation() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    const fields = panel.querySelectorAll("[data-field]");
    const ann = { source_url: "", owner: "", notes: "", rotate_url: "", tags: projectsOf(s) };
    for (const f of fields) ann[f.dataset.field] = f.value;
    try {
      await api(`/api/secrets/${encodeURIComponent(selectedId)}/annotation`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ann) });
      if (s) s.annotation = Object.assign({}, s.annotation, ann);
      setSaveState("saved"); setTimeout(() => { if (saveState === "saved") setSaveState("idle"); }, 1800);
    } catch (e) { setSaveState("err"); setToast("Couldn't save your notes: " + e.message, true); }
  }

  async function markStale(id) { try { await api(`/api/secrets/${encodeURIComponent(id)}/stale`, { method: "POST" }); setToast("Marked as not in use."); await loadSecrets(); } catch (e) { setToast("Couldn't update: " + e.message, true); } }
  async function markRotated(id) { try { await api(`/api/secrets/${encodeURIComponent(id)}/rotated`, { method: "POST" }); setToast("Noted — you replaced this."); await loadSecrets(); } catch (e) { setToast("Couldn't update: " + e.message, true); } }

  // ---- add a secret (manual) ------------------------------------------
  function openAddSecret() {
    const f = {};
    const field = (label, key, ph, help, textarea) => {
      const lbl = el("div", { class: "lbl" }, [ document.createTextNode(label), help ? el("span", { class: "help", title: help, text: "?" }) : null ]);
      const input = textarea ? el("textarea", { placeholder: ph }) : el("input", { type: "text", placeholder: ph });
      f[key] = input;
      return el("label", {}, [ lbl, input ]);
    };
    const body = el("div", { class: "modal" }, [
      el("h2", { text: "Add a secret to track" }),
      el("p", { class: "sub", text: "For a key you keep elsewhere (a password manager, a vendor dashboard) or want to track before Rafter Secrets scans its file." }),
      el("div", { class: "helpcard", html: "<b>Worth keeping track of:</b><ul>" +
        "<li>API keys & tokens — Stripe, OpenAI/Anthropic, GitHub, SendGrid…</li>" +
        "<li>Database & service passwords (DATABASE_URL, Redis, etc.)</li>" +
        "<li>Cloud credentials — AWS, GCP, Azure access keys</li>" +
        "<li>Signing keys & SSH keys</li></ul>" +
        "For each, the useful things to note are <b>where it came from</b>, <b>where to replace it</b>, and which <b>project</b> it belongs to." }),
      el("div", { class: "notes-form" }, [
        field("Name", "key_name", "e.g. STRIPE_LIVE_KEY or “Personal OpenAI key”", "What you'll recognise it by."),
        field("Project", "project", "e.g. naledi  (optional)", "Group it with other secrets for the same project."),
        field("Where does it live?", "path", "e.g. ~/code/app/.env  (optional)", "Just a note — Rafter Secrets won't open this path."),
        field("Where do you replace it?", "rotate_url", "https://…  (optional)", "The page where you'd generate a fresh one."),
        field("Notes", "notes", "anything future-you should know (optional)", null, true),
      ]),
      el("div", { class: "actions" }, [
        el("button", { class: "sm", onclick: closeModal, text: "Cancel" }),
        el("button", { class: "primary sm", onclick: () => submitAddSecret(f), text: "Add secret" }),
      ]),
    ]);
    const backdrop = el("div", { class: "modal-backdrop", onclick: (e) => { if (e.target === backdrop) closeModal(); } }, [ body ]);
    clear(modalRoot); modalRoot.appendChild(backdrop);
    f.key_name.focus();
  }
  function closeModal() { clear(modalRoot); }
  async function submitAddSecret(f) {
    const key_name = f.key_name.value.trim();
    if (!key_name) { f.key_name.focus(); setToast("Give the secret a name first.", true); return; }
    const project = f.project.value.trim();
    const payload = {
      key_name,
      path: f.path.value.trim(),
      annotation: { source_url: "", owner: "", notes: f.notes.value.trim(), rotate_url: f.rotate_url.value.trim(), tags: project ? [project] : [] },
    };
    try {
      const created = await api("/api/secrets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      closeModal();
      setToast("Added “" + key_name + "”.");
      await loadSecrets();
      if (created && created.id) selectSecret(created.id);
    } catch (e) { setToast("Couldn't add it: " + e.message, true); }
  }

  // ---- paths -----------------------------------------------------------
  function prettyPath(p) { if (!p) return ""; const home = state.scan_home; let s = p; if (home && s.indexOf(home) === 0) s = "~" + s.slice(home.length); return s; }
  function dirOf(p) { const i = p.lastIndexOf("/"); return i > 0 ? p.slice(0, i) : p; }
  function splitPath(p) { const pretty = prettyPath(p); const i = pretty.lastIndexOf("/"); return { dir: i >= 0 ? pretty.slice(0, i + 1) : "", base: i >= 0 ? pretty.slice(i + 1) : pretty }; }

  // ---- utils -----------------------------------------------------------
  function copy(text, msg) {
    const done = () => setToast(msg || "Copied");
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    else fallbackCopy(text, done);
  }
  function fallbackCopy(text, done) { const ta = el("textarea", { style: "position:fixed;opacity:0" }); ta.value = text; document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); done(); } catch (_) { setToast("Couldn't copy automatically", true); } document.body.removeChild(ta); }
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
  function shQuote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
  function safeUrl(u) { if (!u) return null; try { const p = new URL(u, window.location.href); return (p.protocol === "http:" || p.protocol === "https:") ? p.href : null; } catch (_) { return null; } }

  // ---- live updates ----------------------------------------------------
  function startEvents() {
    const es = new EventSource("/api/events");
    ["secret_created", "secret_refreshed", "secret_drifted"].forEach((t) => es.addEventListener(t, () => loadSecrets()));
    es.addEventListener("scan_started", () => setScanning(true));
    es.addEventListener("scan_complete", () => { setScanning(false); loadSecrets(); setToast("Re-checked — up to date."); });
    es.onerror = () => {};
  }
  function setScanning(on) { scanStatus.classList.toggle("scanning", on); scanStatusText.textContent = on ? "checking…" : "watching for changes"; }
  function startHeartbeat() {
    setInterval(() => { fetch("/api/heartbeat", { method: "POST", credentials: "same-origin" }).catch(() => {}); }, 30000);
    window.addEventListener("pagehide", () => { navigator.sendBeacon("/api/close"); });
  }

  // ---- view toggle -----------------------------------------------------
  function wireViewToggle() {
    const tg = document.getElementById("view-toggle");
    for (const btn of tg.querySelectorAll("button")) {
      btn.addEventListener("click", () => {
        view = btn.getAttribute("data-view");
        localStorage.setItem("rafter.view", view);
        for (const b of tg.querySelectorAll("button")) b.classList.toggle("active", b === btn);
        render();
      });
      btn.classList.toggle("active", btn.getAttribute("data-view") === view);
    }
  }

  // ---- icons -----------------------------------------------------------
  const ICON = {
    file: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4 1.5h5l3 3v10H4z"/><path d="M9 1.5v3h3"/></svg>',
    folder: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M1.5 4.5h4l1.5 1.5h7v8h-12z"/></svg>',
    lock: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="3" y="7" width="10" height="7" rx="1.2"/><path d="M5 7V5a3 3 0 0 1 6 0v2"/></svg>',
    warn: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2 1.5 14h13z"/><path d="M8 6.5v3.5" stroke-linecap="round"/><circle cx="8" cy="12" r=".6" fill="currentColor" stroke="none"/></svg>',
    check: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 8.5 6.5 12 13 4.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    copy: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="5" y="5" width="8" height="9" rx="1.2"/><path d="M3 11V3a1 1 0 0 1 1-1h6"/></svg>',
  };

  // ---- boot ------------------------------------------------------------
  document.getElementById("add-secret-btn").addEventListener("click", openAddSecret);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && modalRoot.firstChild) closeModal(); });
  wireViewToggle();
  loadSecrets();
  startEvents();
  startHeartbeat();
})();
