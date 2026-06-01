// trove inventory UI — written for people who have never opened a terminal.
//
// The whole job of this file is translation: the server speaks in
// fingerprints, octal permissions, and source_types; the person reading
// the screen speaks in "is this safe?" We render the second from the
// first, and we never make them learn the first.
//
// Server API (unchanged contract):
//   GET  /api/secrets                  -> { secrets:[...], scan_config, reveal_policy }
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

  let state = { secrets: [], reveal_policy: "session" };
  let selectedId = null;
  let firstLoad = true;
  const revealed = new Map(); // id -> plaintext, in-memory only
  let saveTimer = null;
  let saveState = "idle";
  let introDismissed = localStorage.getItem("trove.introDismissed") === "1";

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
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

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
  // Maps a key name to a friendly service name + 2-letter chip. Pure
  // cosmetics; nothing depends on getting it right.
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
  // The only risk signals v1 actually populates are file permissions,
  // duplication across locations, and rotation history. Git fields are
  // rendered if present but never assumed.
  function parsePerm(p) {
    if (!p) return null;
    const m = /(\d{3,4})$/.exec(p);
    if (!m) return null;
    const oct = m[1].slice(-3);
    return {
      group: (parseInt(oct[1], 8) & 4) !== 0,
      other: (parseInt(oct[2], 8) & 4) !== 0,
      raw: p,
    };
  }
  // worst readable permission across a secret's file locations.
  function exposure(s) {
    let worst = null;
    for (const f of s.found_in || []) {
      if (!f.path) continue;
      const pm = parsePerm(f.permissions);
      if (!pm) continue;
      if (pm.other) return { level: "other", perm: pm, path: f.path };
      if (pm.group && !worst) worst = { level: "group", perm: pm, path: f.path };
    }
    return worst;
  }
  function fileLocations(s) { return (s.found_in || []).filter((f) => f.path); }
  function isDuplicated(s) { return fileLocations(s).length > 1; }
  function isStale(s) { return !!(s.annotation && s.annotation.stale); }

  // A secret "needs attention" if it's readable by other users on the
  // machine, or duplicated across multiple files. Stale ones drop out.
  function needsAttention(s) {
    if (isStale(s)) return false;
    const ex = exposure(s);
    return !!ex || isDuplicated(s);
  }

  // ---- data load -------------------------------------------------------
  async function loadSecrets() {
    try {
      const body = await api("/api/secrets");
      state.secrets = body.secrets || [];
      state.reveal_policy = body.reveal_policy || "session";
      // Use the shortest configured scan root as the home prefix so paths
      // render as ~/… ; falls back to no rewrite if none configured.
      const roots = (body.scan_config && body.scan_config.roots) || [];
      state.scan_home = roots.slice().sort((a, b) => a.length - b.length)[0] || null;
      render();
    } catch (e) {
      content.innerHTML = "";
      content.appendChild(el("div", { class: "empty" }, [
        el("div", { class: "big", text: "⚠️" }),
        el("h3", { text: "Couldn't reach trove" }),
        el("p", { text: e.message + ". Try reloading this page." }),
      ]));
    }
  }

  // ---- render ----------------------------------------------------------
  function render() {
    clear(content);

    if (!introDismissed && state.secrets.length > 0) content.appendChild(renderIntro());

    if (state.secrets.length === 0) {
      content.appendChild(renderEmpty());
      firstLoad = false;
      return;
    }

    content.appendChild(renderStats());

    const attn = state.secrets.filter(needsAttention);
    if (attn.length > 0) {
      content.appendChild(sectionHeader("Worth a look", attn.length, "attn"));
      content.appendChild(renderFlatList(attn));
    }

    content.appendChild(sectionHeader("Everything trove found", state.secrets.length, ""));
    for (const g of groupByLocation(state.secrets)) content.appendChild(renderGroup(g));

    if (selectedId) {
      if (state.secrets.some((s) => s.id === selectedId)) renderPanel();
      else closePanel();
    }
    firstLoad = false;
  }

  function renderIntro() {
    return el("div", { class: "intro" }, [
      el("div", { class: "ico", text: "🔎" }),
      el("div", {}, [
        el("h2", { text: "Here are the passwords and keys saved on this computer." }),
        el("p", { html: "These are the kind of secrets apps and tools store in plain files — API keys, database passwords, access tokens. trove just gathered them in one place so you can see what's here. Click any item to understand it and, if you want, jot down notes. <b style=\"color:var(--text-dim)\">Nothing here is changed or uploaded.</b>" }),
      ]),
      el("button", { class: "x", title: "Dismiss", onclick: () => {
        introDismissed = true; localStorage.setItem("trove.introDismissed", "1"); render();
      }, text: "×" }),
    ]);
  }

  function renderEmpty() {
    return el("div", { class: "empty" }, [
      el("div", { class: "big", text: "✨" }),
      el("h3", { text: "Nothing saved in the open — nice." }),
      el("p", { html: "trove didn't find any passwords or keys sitting in plain files yet. It keeps watching: the moment a tool writes one (say, you log into a new service), it'll show up here automatically." }),
    ]);
  }

  function renderStats() {
    const secrets = state.secrets.filter((s) => !isStale(s));
    const total = secrets.length;
    const exposed = secrets.filter((s) => exposure(s)).length;
    const dup = secrets.filter(isDuplicated).length;
    const locations = new Set();
    for (const s of secrets) for (const f of fileLocations(s)) locations.add(f.path);

    const wrap = el("div", { class: "stats" });
    wrap.appendChild(statCard(total, "secrets found", "passwords, keys & tokens", "calm"));
    wrap.appendChild(statCard(locations.size, locations.size === 1 ? "file" : "files", "where they're stored", ""));
    wrap.appendChild(statCard(exposed, "readable by others", "anyone signed in to this computer", exposed > 0 ? "danger" : "calm"));
    wrap.appendChild(statCard(dup, "stored in more than one place", "easy to lose track of", dup > 0 ? "attn" : "calm"));
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
      el("span", { class: "count", text: count }),
    ]);
  }

  // ---- grouping --------------------------------------------------------
  function groupByLocation(secrets) {
    const groups = new Map();
    for (const s of secrets) {
      const f = (s.found_in || [])[0];
      let label, kind, perm;
      if (!f) { label = "Other"; kind = "unknown"; }
      else if (f.path) { label = f.path; kind = "file"; perm = f.permissions; }
      else if (f.keystore) { label = keystoreName(f.keystore); kind = "keystore"; }
      else { label = "Other"; kind = "unknown"; }
      if (!groups.has(label)) groups.set(label, { label, kind, perm, items: [] });
      groups.get(label).items.push(s);
    }
    // Files with exposed perms float to the top of the "everything" list.
    return Array.from(groups.values()).sort((a, b) => {
      const ax = a.items.some((s) => exposure(s)) ? 0 : 1;
      const bx = b.items.some((s) => exposure(s)) ? 0 : 1;
      if (ax !== bx) return ax - bx;
      return a.label.localeCompare(b.label);
    });
  }
  function keystoreName(k) {
    if (/keychain/i.test(k)) return "macOS Keychain";
    if (/secret-service|gnome|kwallet/i.test(k)) return "System keyring";
    return k + " keystore";
  }

  // ---- friendly path formatting ---------------------------------------
  function prettyPath(p) {
    if (!p) return "";
    let s = p;
    const home = state.scan_home;
    if (home && s.startsWith(home)) s = "~" + s.slice(home.length);
    return s;
  }
  function splitPath(p) {
    const pretty = prettyPath(p);
    const i = pretty.lastIndexOf("/");
    return { dir: i >= 0 ? pretty.slice(0, i + 1) : "", base: i >= 0 ? pretty.slice(i + 1) : pretty };
  }

  // ---- list rendering --------------------------------------------------
  function renderFlatList(secrets) {
    const ul = el("ul", { class: "entries", style: "border:1px solid var(--border);border-radius:12px;background:var(--panel-2);overflow:hidden;" });
    secrets.forEach((s, i) => { const li = renderEntry(s, true); if (i === 0) li.style.borderTop = "none"; ul.appendChild(li); });
    return ul;
  }

  function renderGroup(g) {
    const det = el("details", { class: "group" });
    det.open = g.items.length <= 6 || g.items.some((s) => exposure(s));
    const ex = g.kind === "file" ? parsePerm(g.perm) : null;

    const meta = el("span", { class: "src-meta" }, [
      ex && (ex.other || ex.group)
        ? statusPill(ex.other ? "danger" : "warn", ex.other ? "readable by anyone" : "readable by your group")
        : null,
      el("span", { text: g.items.length + (g.items.length === 1 ? " secret" : " secrets") }),
    ]);

    let nameNode;
    if (g.kind === "file") {
      const sp = splitPath(g.label);
      nameNode = el("span", { class: "src-name" }, [ el("span", { class: "dir", text: sp.dir }), document.createTextNode(sp.base) ]);
    } else {
      nameNode = el("span", { class: "src-name", text: g.label });
    }

    const sum = el("summary", {}, [
      el("span", { class: "chev", text: "›" }),
      el("span", { class: "src-ico", html: g.kind === "keystore" ? ICON.lock : ICON.file }),
      nameNode,
      meta,
    ]);
    det.appendChild(sum);

    const ul = el("ul", { class: "entries" });
    for (const s of g.items) ul.appendChild(renderEntry(s, false));
    det.appendChild(ul);
    return det;
  }

  function renderEntry(s, showLocation) {
    const v = vendorFor(s.key_name);
    const li = el("li", { class: "entry" + (s.id === selectedId ? " selected" : "") + (isStale(s) ? " stale" : ""), "data-id": s.id });
    li.appendChild(el("span", { class: "type-chip", text: v.chip, title: v.name }));

    const keyWrap = el("div", { style: "min-width:0;" }, [ el("div", { class: "key", text: s.key_name, title: s.key_name }) ]);
    if (showLocation) {
      const f = fileLocations(s)[0];
      if (f) keyWrap.appendChild(el("div", { class: "val", text: splitPath(f.path).base, title: prettyPath(f.path) }));
    }
    li.appendChild(keyWrap);

    const isRev = revealed.has(s.id);
    li.appendChild(el("span", { class: "val" + (isRev ? " revealed" : ""), text: isRev ? revealed.get(s.id) : maskPreview(s.value_preview) }));

    const right = el("span", { class: "right" });
    right.appendChild(entryPill(s));
    li.appendChild(right);

    li.addEventListener("click", () => selectSecret(s.id));
    return li;
  }

  // Show a dotted mask instead of the technical "sk-ant-...zRfx" preview
  // until the person chooses to reveal.
  function maskPreview() { return "••••••••"; }

  function entryPill(s) {
    if (isStale(s)) return statusPill("", "not in use");
    const ex = exposure(s);
    if (ex && ex.level === "other") return statusPill("danger", "readable by anyone");
    if (ex && ex.level === "group") return statusPill("warn", "readable by your group");
    if (isDuplicated(s)) return statusPill("info", "in " + fileLocations(s).length + " places");
    return statusPill("ok", "looks fine");
  }
  function statusPill(cls, text) {
    return el("span", { class: "pill " + (cls || "") }, [ cls ? el("span", { class: "pd" }) : null, document.createTextNode(text) ]);
  }

  // ---- reveal ----------------------------------------------------------
  async function toggleReveal(s) {
    if (revealed.has(s.id)) { revealed.delete(s.id); render(); return; }
    try {
      const body = await api(`/api/secrets/${encodeURIComponent(s.id)}/reveal`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}),
      });
      revealed.set(s.id, body.value);
      render();
    } catch (e) {
      if (e.status === 422) setToast("This kind of secret can't be shown here yet.", true);
      else if (e.status === 410) setToast("That value just changed on disk — refreshing.", true);
      else setToast("Couldn't read the value: " + e.message, true);
    }
  }

  // ---- selection / panel ----------------------------------------------
  function selectSecret(id) {
    selectedId = id;
    panelWrap.classList.add("open");
    renderPanel();
    for (const e of content.querySelectorAll("li.entry")) e.classList.toggle("selected", e.getAttribute("data-id") === id);
  }
  function closePanel() { selectedId = null; panelWrap.classList.remove("open"); clear(panel);
    for (const e of content.querySelectorAll("li.entry.selected")) e.classList.remove("selected"); }

  function renderPanel() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    if (!s) { closePanel(); return; }
    const v = vendorFor(s.key_name);
    clear(panel);

    // header
    panel.appendChild(el("div", { class: "panel-top" }, [
      el("span", { class: "type-chip", text: v.chip }),
      el("div", { class: "titles" }, [
        el("h2", { text: s.key_name }),
        el("div", { class: "type-name", text: v.name + (isStale(s) ? " · marked not in use" : "") }),
      ]),
      el("button", { class: "ghost close", title: "Close", onclick: closePanel, text: "×" }),
    ]));

    // value
    const isRev = revealed.has(s.id);
    panel.appendChild(el("div", { class: "value-box" }, [
      el("span", { class: "v " + (isRev ? "revealed" : "hidden"), text: isRev ? revealed.get(s.id) : "••••••••••••" }),
      isRev ? el("button", { class: "sm", onclick: () => toggleReveal(s), text: "Hide" }) : null,
      isRev ? el("button", { class: "sm", onclick: () => copy(revealed.get(s.id), "Value copied"), text: "Copy" }) : null,
      !isRev ? el("button", { class: "sm", onclick: () => toggleReveal(s), text: "Show value" }) : null,
    ]));

    // findings (plain-language)
    const findings = buildFindings(s);
    panel.appendChild(el("div", { class: "block-h", text: "What this means" }));
    if (findings.length === 0) {
      panel.appendChild(el("div", { class: "finding calm" }, [
        el("div", { class: "f-head" }, [ el("span", { html: ICON.check }), document.createTextNode("Nothing alarming here.") ]),
        el("p", { class: "f-body", text: "This secret is stored in a file only you can read, and trove only found it in one place. Still worth keeping a note of where it came from — below — so future-you remembers." }),
      ]));
    } else {
      for (const f of findings) panel.appendChild(f);
    }

    // where it lives
    panel.appendChild(el("div", { class: "block-h", text: "Where it's stored" }));
    panel.appendChild(renderLocations(s));

    // rotation history
    if (s.value_history && s.value_history.length > 1) {
      panel.appendChild(el("div", { class: "block-h", text: "History" }));
      panel.appendChild(el("p", { class: "f-body", style: "margin:0;color:var(--muted)",
        html: "trove has seen this value change <b style=\"color:var(--text-dim)\">" + (s.value_history.length - 1) + "</b> time" + (s.value_history.length - 1 === 1 ? "" : "s") + " since it started watching. Changing a key regularly is a good habit." }));
    }

    // notes
    panel.appendChild(el("div", { class: "block-h", text: "Your notes" }));
    panel.appendChild(renderNotes(s));

    // actions
    panel.appendChild(el("div", { class: "panel-actions" }, [
      el("button", { class: "sm", title: "Tell trove you've replaced this key with a new one. It keeps your notes and tracks the change.",
        onclick: () => markRotated(s.id), text: "I've replaced this" }),
      isStale(s)
        ? el("button", { class: "sm", disabled: "", text: "Marked not in use" })
        : el("button", { class: "sm", title: "Grey this out — you're not using it anymore. Nothing is deleted.",
            onclick: () => markStale(s.id), text: "I don't use this" }),
    ]));
  }

  // Build the human-readable finding cards from the raw data.
  function buildFindings(s) {
    const out = [];
    const ex = exposure(s);
    if (ex) {
      const sp = splitPath(ex.path);
      const danger = ex.level === "other";
      const card = el("div", { class: "finding " + (danger ? "danger" : "warn") }, [
        el("div", { class: "f-head" }, [
          el("span", { html: ICON.warn }),
          document.createTextNode(danger ? "Anyone on this computer can read it" : "Other accounts in your group can read it"),
        ]),
        el("p", { class: "f-body", html:
          "The file <code>" + escapeHtml(sp.base) + "</code> is set so that " +
          (danger ? "<b>any account signed in to this computer</b>" : "<b>other users in your group</b>") +
          " can open it and see this secret in plain text. On your own laptop that's usually low-risk, but on a shared or work machine it's worth tightening." }),
        el("div", { class: "f-actions" }, [
          el("button", { class: "sm", title: "Copies a one-line command. Paste it into a terminal (or send it to whoever set up your computer) to make the file private to you. trove won't run it for you.",
            onclick: () => copy("chmod 600 " + shQuote(ex.path), "Command copied — paste it into a terminal"), text: "Copy the fix" }),
          el("span", { class: "loc-sub", html: "makes the file readable by <b style=\"color:var(--text-dim)\">you only</b>" }),
        ]),
      ]);
      out.push(card);
    }
    if (isDuplicated(s)) {
      const n = fileLocations(s).length;
      out.push(el("div", { class: "finding warn" }, [
        el("div", { class: "f-head" }, [ el("span", { html: ICON.copy }), document.createTextNode("Stored in " + n + " different files") ]),
        el("p", { class: "f-body", html: "The same secret lives in <b>" + n + " places</b> (listed below). That's not dangerous on its own, but if you ever replace this key, remember you'll need to update it everywhere — or the apps using the old copies will stop working." }),
      ]));
    }
    // git fields, only if the scanner ever populates them.
    for (const f of s.found_in || []) {
      if (f.appears_in_git_history) {
        out.push(el("div", { class: "finding danger" }, [
          el("div", { class: "f-head" }, [ el("span", { html: ICON.warn }), document.createTextNode("Saved into a project's history") ]),
          el("p", { class: "f-body", html: "This was committed to a code project's history, which means it may already have been shared or uploaded. The safe move is to <b>replace it</b> with a new key — add the replace-link below so it's one click next time." }),
        ]));
        break;
      }
    }
    return out;
  }

  function renderLocations(s) {
    const ul = el("ul", { class: "locations" });
    for (const f of s.found_in || []) {
      if (f.path) {
        const sp = splitPath(f.path);
        const pm = parsePerm(f.permissions);
        const sub = [];
        if (f.line) sub.push("line " + f.line);
        if (pm && pm.other) sub.push("readable by anyone");
        else if (pm && pm.group) sub.push("readable by your group");
        else if (pm) sub.push("private to you");
        ul.appendChild(el("li", {}, [
          el("span", { class: "loc-ico", html: ICON.file }),
          el("div", { style: "min-width:0" }, [
            el("div", { class: "loc-path", text: sp.dir + sp.base, title: f.path }),
            sub.length ? el("div", { class: "loc-sub", text: sub.join(" · ") }) : null,
          ]),
        ]));
      } else if (f.keystore) {
        ul.appendChild(el("li", { class: "soon" }, [
          el("span", { class: "loc-ico", html: ICON.lock }),
          el("div", {}, [
            el("div", { class: "loc-path", text: keystoreName(f.keystore) + (f.account ? " · " + f.account : "") }),
            el("div", { class: "loc-sub", text: "kept in your system vault — viewing it here is coming soon" }),
          ]),
        ]));
      }
    }
    return ul;
  }

  // ---- notes form ------------------------------------------------------
  function renderNotes(s) {
    const a = s.annotation || {};
    const form = el("div", { class: "notes-form" });
    form.appendChild(noteField("Where did this come from?", "source_url", a.source_url, "e.g. https://dashboard.stripe.com", "A link to the page where this key was created."));
    form.appendChild(noteField("Where do you replace it?", "rotate_url", a.rotate_url, "link to create a new one", "When you need a fresh key, this is where you'd go."));
    form.appendChild(noteField("Who owns it?", "owner", a.owner, "e.g. you, or a teammate", null));
    form.appendChild(noteField("Notes", "notes", a.notes, "anything future-you should know", null, true));
    form.appendChild(noteField("Tags", "tags", (a.tags || []).join(", "), "personal, work, important…", "Comma-separated labels, your choice."));

    const ss = el("div", { class: "save-state", id: "save-state" });
    form.appendChild(ss);

    const rotateHref = safeUrl(a.rotate_url);
    if (rotateHref) {
      form.appendChild(el("a", { href: rotateHref, target: "_blank", rel: "noopener noreferrer", style: "display:inline-block;margin-top:4px" },
        [ el("button", { class: "primary sm", text: "Go replace this key ↗" }) ]));
    }
    return form;
  }
  function noteField(label, name, value, placeholder, help, textarea) {
    const lbl = el("div", { class: "lbl" }, [ document.createTextNode(label), help ? el("span", { class: "help", title: help, text: "?" }) : null ]);
    const input = textarea ? el("textarea", { placeholder: placeholder }) : el("input", { type: "text", placeholder: placeholder });
    input.value = value || "";
    input.dataset.field = name;
    input.addEventListener("input", scheduleSave);
    return el("label", {}, [ lbl, input ]);
  }

  function scheduleSave() {
    if (saveTimer) clearTimeout(saveTimer);
    setSaveState("saving");
    saveTimer = setTimeout(saveAnnotation, 600);
  }
  function setSaveState(st) { saveState = st; const e = document.getElementById("save-state"); if (!e) return;
    e.className = "save-state " + (st === "idle" ? "" : st);
    e.textContent = st === "saving" ? "saving…" : st === "saved" ? "saved ✓" : st === "err" ? "couldn't save" : ""; }

  async function saveAnnotation() {
    if (!selectedId) return;
    const fields = panel.querySelectorAll("[data-field]");
    const ann = { source_url: "", owner: "", notes: "", rotate_url: "", tags: [] };
    for (const f of fields) {
      if (f.dataset.field === "tags") ann.tags = f.value.split(",").map((t) => t.trim()).filter(Boolean);
      else ann[f.dataset.field] = f.value;
    }
    try {
      await api(`/api/secrets/${encodeURIComponent(selectedId)}/annotation`, {
        method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ann),
      });
      const s = state.secrets.find((x) => x.id === selectedId);
      if (s) s.annotation = Object.assign({}, s.annotation, ann);
      setSaveState("saved");
      setTimeout(() => { if (saveState === "saved") setSaveState("idle"); }, 1800);
    } catch (e) { setSaveState("err"); setToast("Couldn't save your notes: " + e.message, true); }
  }

  async function markStale(id) {
    try { await api(`/api/secrets/${encodeURIComponent(id)}/stale`, { method: "POST" }); setToast("Marked as not in use."); await loadSecrets(); }
    catch (e) { setToast("Couldn't update: " + e.message, true); }
  }
  async function markRotated(id) {
    try { await api(`/api/secrets/${encodeURIComponent(id)}/rotated`, { method: "POST" }); setToast("Got it — noted that you replaced this."); await loadSecrets(); }
    catch (e) { setToast("Couldn't update: " + e.message, true); }
  }

  function copy(text, msg) {
    const done = () => setToast(msg || "Copied");
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    else fallbackCopy(text, done);
  }
  function fallbackCopy(text, done) {
    const ta = el("textarea", { style: "position:fixed;opacity:0" }); ta.value = text;
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch (_) { setToast("Couldn't copy automatically", true); }
    document.body.removeChild(ta);
  }
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
  // POSIX single-quote a path so a scanned filename with spaces or shell
  // metacharacters (a "; rm -rf ~", $(...), backticks) can't turn the
  // copy-paste chmod command into something else when the user pastes it
  // into a terminal. Wrap in '…' and escape embedded quotes as '\''.
  function shQuote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
  // Only let http(s) links through to an href. A user could paste a
  // "javascript:" URL into the rotate-link field; this stops it from
  // ever becoming a clickable script. Returns null for anything unsafe.
  function safeUrl(u) {
    if (!u) return null;
    try {
      const parsed = new URL(u, window.location.href);
      return (parsed.protocol === "http:" || parsed.protocol === "https:") ? parsed.href : null;
    } catch (_) { return null; }
  }

  // ---- live updates ----------------------------------------------------
  function startEvents() {
    const es = new EventSource("/api/events");
    ["secret_created", "secret_refreshed", "secret_drifted"].forEach((t) => es.addEventListener(t, () => loadSecrets()));
    es.addEventListener("scan_started", () => setScanning(true));
    es.addEventListener("scan_complete", () => { setScanning(false); loadSecrets(); setToast("Re-checked — up to date."); });
    es.onerror = () => { /* EventSource auto-reconnects; stay quiet */ };
  }
  function setScanning(on) {
    scanStatus.classList.toggle("scanning", on);
    scanStatusText.textContent = on ? "checking…" : "watching for changes";
  }

  function startHeartbeat() {
    setInterval(() => { fetch("/api/heartbeat", { method: "POST", credentials: "same-origin" }).catch(() => {}); }, 30000);
    window.addEventListener("pagehide", () => { navigator.sendBeacon("/api/close"); });
  }

  // ---- inline icons (currentColor SVG) --------------------------------
  const ICON = {
    file: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4 1.5h5l3 3v10H4z"/><path d="M9 1.5v3h3"/></svg>',
    lock: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="3" y="7" width="10" height="7" rx="1.2"/><path d="M5 7V5a3 3 0 0 1 6 0v2"/></svg>',
    warn: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2 1.5 14h13z"/><path d="M8 6.5v3.5" stroke-linecap="round"/><circle cx="8" cy="12" r=".6" fill="currentColor" stroke="none"/></svg>',
    check: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 8.5 6.5 12 13 4.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    copy: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="5" y="5" width="8" height="9" rx="1.2"/><path d="M3 11V3a1 1 0 0 1 1-1h6"/></svg>',
  };

  // ---- boot ------------------------------------------------------------
  loadSecrets();
  startEvents();
  startHeartbeat();
})();
