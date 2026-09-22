// PrimeProxy — app shell: navigation, theming, i18n, page wiring, auto-save.
(async () => {
  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const on = (id, ev, fn) => { const el = $(id); if (el) el.addEventListener(ev, fn); };
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));
  const escapeHTML = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  const state = {
    settings: null,
    lang: "en",
    proxyMode: "mt",
    saveHost: "127.0.0.1",
    dnsProviders: [],
    activePreset: null,
    hostSelected: new Set(),
    hostServices: [],
    updatePoll: null,
    dnsPoisonRunning: false,
    autoSaveTimer: null,
    asScope: "app",
    pfRecommended: "",
    orCurrent: null,
    autoMode: true,
  };

  // ── diagnostics: pipe JS errors into the app log, DevTools on Shift+F1 ──
  (function installDiagnostics() {
    const recent = new Map();
    let busy = false;
    const send = (source, message) => {
      const msg = String(message == null ? "" : message).slice(0, 1500);
      if (!msg) return;
      const now = Date.now();
      if (now - (recent.get(msg) || 0) < 4000) return;
      recent.set(msg, now);
      if (recent.size > 200) recent.clear();
      if (busy) return;
      busy = true;
      try {
        const p = window.bridge && window.bridge.report_ui_error(source, msg);
        if (p && typeof p.catch === "function") p.catch(() => {});
      } catch (e) {
      } finally {
        setTimeout(() => { busy = false; }, 60);
      }
    };
    window.addEventListener("error", (e) => {
      const loc = e && e.filename ? " @ " + e.filename + ":" + (e.lineno || 0) + ":" + (e.colno || 0) : "";
      send("js", (e && e.message ? e.message : "script error") + loc);
    });
    window.addEventListener("unhandledrejection", (e) => {
      const r = e && e.reason;
      send("promise", (r && (r.stack || r.message)) || String(r));
    });
    const origError = console.error.bind(console);
    console.error = function () {
      try { origError.apply(null, arguments); } catch (e) {}
      try {
        const parts = Array.prototype.map.call(arguments, (a) => {
          if (a instanceof Error) return a.stack || a.message;
          if (a && typeof a === "object") { try { return JSON.stringify(a); } catch (_) { return String(a); } }
          return String(a);
        });
        send("console", parts.join(" "));
      } catch (e) {}
    };
    document.addEventListener("keydown", (e) => {
      if (e.shiftKey && (e.key === "F1" || e.code === "F1")) {
        e.preventDefault();
        e.stopPropagation();
        try { window.bridge && window.bridge.open_devtools(); } catch (err) {}
      }
    }, true);
  })();

  // ── icons ──────────────────────────────────────────────────────────────
  function renderIcons() {
    $$("[data-icon]").forEach((el) => {
      el.innerHTML = Icon(el.dataset.icon, el.dataset.iconSize || 18);
    });
    $$("[data-icon-inline]").forEach((el) => {
      const ic = document.createElement("span");
      ic.className = "btn-icon";
      ic.innerHTML = Icon(el.dataset.iconInline, 15);
      el.prepend(ic);
    });
  }

  function swapIcon(el, name, size) {
    el.innerHTML = Icon(name, size || 18);
  }

  // ── navigation & sidebar ────────────────────────────────────────────────
  function showPage(name) {
    $$(".page").forEach((p) => p.classList.toggle("active", p.dataset.pageView === name));
    $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === name));
    if (name === "logs") renderLogSeg();
    if (name === "profiles") renderAutopilot();
    if (name === "proxy") refreshShare();
    if (name === "updates") refreshUpdates(true);
    window.scrollTo(0, 0);
  }

  function applyCollapsed(collapsed) {
    document.body.classList.toggle("sidebar-collapsed", !!collapsed);
    swapIcon($("collapseBtn"), collapsed ? "expand" : "collapse");
  }

  async function toggleCollapse() {
    const collapsed = !document.body.classList.contains("sidebar-collapsed");
    applyCollapsed(collapsed);
    await save("app", "sidebar_collapsed", collapsed);
  }

  // ── theme ──────────────────────────────────────────────────────────────
  function applyTheme(ap) {
    ap = ap || {};
    const root = document.documentElement;
    root.classList.toggle("light", ap.mode === "light");
    root.classList.toggle("dark", ap.mode === "dark");
  }

  function setAppearance(key, value) {
    if (state.settings && state.settings.appearance) state.settings.appearance[key] = value;
    else if (state.settings) state.settings.appearance = { [key]: value };
    else state.settings = { appearance: { [key]: value } };
  }

  function themeValue() {
    const btn = $$("#themeMode button.active")[0];
    return (btn && btn.dataset.val) || "auto";
  }

  // ── i18n ───────────────────────────────────────────────────────────────
  function syncLangUi() {
    const v = ($("langValue") && $("langValue").value) || "auto";
    const opt = $$("#langMenu .lang-option").find((o) => o.dataset.val === v);
    const label = $("langLabel");
    if (label && opt) label.textContent = opt.textContent;
  }

  async function resolveAndSetLang() {
    const app = (state.settings && state.settings.app) || {};
    let cfgLang = app.language || "auto";
    if (cfgLang === "auto") cfgLang = null;
    state.lang = I18n.setLang(cfgLang);
    I18n.apply(document);
    if ($("langValue")) $("langValue").value = app.language || "auto";
    syncLangUi();
    renderIcons();
  }

  async function changeLang(lang) {
    await save("app", "language", lang, { silent: true });
    if ($("langValue")) $("langValue").value = lang;
    state.lang = I18n.setLang(lang === "auto" ? null : lang);
    I18n.apply(document);
    syncLangUi();
    renderIcons();
    renderDynamic();
  }

  // ── save helpers (auto-save) ───────────────────────────────────────────
  async function save(section, key, value, opts) {
    try {
      await bridge.set_setting(section, key, value);
      return true;
    } catch (e) {
      toast(I18n.t("toast.failed"));
      return false;
    }
  }

  function debouncedSave(section, key, getter) {
    clearTimeout(state.autoSaveTimer);
    state.autoSaveTimer = setTimeout(async () => {
      await save(section, key, getter());
    }, 450);
  }

  // ── status ─────────────────────────────────────────────────────────────
  async function refreshStatus() {
    const [mt, tg] = await Promise.all([bridge.get_proxy_status(), bridge.get_tg_proxy_status()]);
    const mb = $("dashMtBadge");
    if (mb) {
      mb.className = `status-badge ${mt && mt.running ? "ok" : "off"}`;
      mb.textContent = mt && mt.running ? I18n.t("status.mt_running") : I18n.t("status.mt_off");
    }
    const mtT = $("dashMtToggle");
    if (mtT) mtT.checked = !!(mt && mt.running);
    const tgb = $("dashSocksBadge");
    if (tgb) {
      tgb.className = `status-badge ${tg && tg.running ? "ok" : "off"}`;
      tgb.textContent = tg && tg.running ? I18n.t("status.socks_running") : I18n.t("status.socks_off");
    }
    const tgT = $("dashSocksToggle");
    if (tgT) tgT.checked = !!(tg && tg.running);
  }

  async function refreshDashDpi() {
    const [eng, st] = await Promise.all([bridge.get_zapret_engine(), bridge.get_dpi_status()]);
    if (!eng) return;
    state.dpiEngine = eng;
    const running = st && (st.state === "running" || st.state === "starting");
    state.dpiRunning = !!running;
    const tg = $("dashDpiToggle");
    if (tg) tg.checked = !!running;
    const prof = $("dashDpiProfile");
    if (prof) {
      const name = (eng.profile || "").replace(/\.txt$/, "");
      prof.textContent = name ? (eng.profile_group ? eng.profile_group + " / " : "") + name : "—";
    }
    const ds = $("dashDpiState");
    if (ds) {
      if (running) ds.textContent = I18n.t("pf.running");
      else if (st && st.state === "error") ds.textContent = I18n.t("pf.stopped") + " · " + (st.last_error || st.exit_code || "");
      else ds.textContent = I18n.t("pf.stopped");
    }
  }

  function formatUptime(secs) {
    if (secs == null) return "—";
    const s = Math.max(0, Math.floor(secs));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  async function refreshDashStats() {
    const info = state.appInfo || (await bridge.get_app_info());
    const up = $("statUptime");
    if (up) up.textContent = info && info.uptime != null ? formatUptime(info.uptime) : info && info.uptime_text ? info.uptime_text : "—";
    const checked = $("statChecked");
    if (checked) {
      try {
        const bc = await bridge.get_blockcheck_presets();
        checked.textContent = bc && bc.user_domains ? bc.user_domains.length : "—";
      } catch (e) { checked.textContent = "—"; }
    }
    const st = $("statStrategies");
    if (st) {
      try {
        const ls = await bridge.list_strategies();
        st.textContent = ls && ls.strategies ? ls.strategies.length : "—";
      } catch (e) { st.textContent = "—"; }
    }
    const hs = $("statHosts");
    if (hs) {
      try {
        const active = await bridge.get_hosts_active();
        hs.textContent = active ? Object.keys(active).length : "—";
      } catch (e) { hs.textContent = "—"; }
    }
  }

  async function refreshProxyLink() {
    const cfg = (state.settings && state.settings.proxy) || {};
    if (state.proxyMode === "socks5") {
      const tg = (state.settings && state.settings.telegram) || {};
      const host = tg.bind_host && tg.bind_host !== "0.0.0.0" ? tg.bind_host : await bridge.get_lan_ip();
      $("proxyLink").value = `${host}:${tg.port || 1353}`;
      const dc = $("dashConnect");
      if (dc) { dc.dataset.i18n = "dash.connect_socks"; dc.textContent = I18n.t("dash.connect_socks"); }
      return;
    }
    const dc = $("dashConnect");
    if (dc) { dc.dataset.i18n = "dash.connect"; dc.textContent = I18n.t("dash.connect"); }
    const link = await bridge.get_tray_proxy_link();
    if (link) $("proxyLink").value = link;
  }

  function buildProxyLink(host, cfg) {
    const port = (cfg && cfg.port) || 1443;
    const secret = (cfg && cfg.secret) || "";
    return `tg://proxy?server=${host}&port=${port}&secret=dd${secret}`;
  }

  function toast(msg, level) {
    Components.toast(msg, level);
    if (level === "error") {
      try { bridge.report_ui_error("ui", String(msg)); } catch (e) {}
    }
  }

  async function copyText(t) {
    const s = String(t == null ? "" : t);
    if (!s) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(s);
        toast(I18n.t("cmn.copied"));
        return;
      }
    } catch (e) {}
    try {
      const ta = document.createElement("textarea");
      ta.value = s;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      toast(I18n.t("cmn.copied"));
    } catch (e) {
      toast(I18n.t("toast.failed"), "error");
    }
  }

  // ── DNS ────────────────────────────────────────────────────────────────
  async function renderDns() {
    const providers = await bridge.get_dns_providers();
    if (!providers) return;
    state.dnsProviders = providers;
    await updateSystemDns();
    const grid = $("dnsProviders");
    grid.innerHTML = "";
    const s = state.settings;
    const current = (s && s.dns && s.dns.provider_id) ? s.dns.provider_id : providers[0].id;
    for (const p of providers) {
      const card = document.createElement("button");
      card.type = "button";
      card.className = `provider-card${p.id === current ? " active" : ""}`;
      card.dataset.id = p.id;
      const t = document.createElement("div");
      t.className = "provider-name";
      t.textContent = p.name;
      const d = document.createElement("div");
      d.className = "hint";
      d.textContent = `${p.category} · ${p.desc}`;
      card.append(t, d);
      card.addEventListener("click", () => {
        grid.querySelectorAll(".provider-card").forEach((c) => c.classList.toggle("active", c === card));
        save("dns", "provider_id", p.id);
      });
      grid.appendChild(card);
    }
  }

  async function updateSystemDns() {
    try {
      const sys = await bridge.get_system_dns();
      const el = $("dnsSystemServers");
      if (el) el.textContent = (sys && sys.length) ? sys.join(", ") : "—";
    } catch (e) { /* noop */ }
  }

  function parseDnsInput() {
    const raw = ($("dnsCustomInput").value || "").replace(/\s+/g, " ").trim();
    if (!raw) return null;
    const out = raw.split(",").map((s) => s.trim()).filter(Boolean);
    const ipRe = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]+)$/;
    for (const ip of out) if (!ipRe.test(ip)) return null;
    return out;
  }

  async function runDnsForce() {
    const servers = parseDnsInput();
    if (servers === null) { toast(I18n.t("dns.bad_servers")); return; }
    const r = await bridge.force_dns(servers);
    toast(I18n.t(r && r.ok ? "dns.forced" : "dns.err_admin", r && r.ok ? { servers: (r.servers || servers).join(", ") } : {}));
    await updateSystemDns();
  }

  async function runDnsRestore() {
    const r = await bridge.restore_dns();
    toast(I18n.t(r && r.ok ? "dns.restored" : "dns.err_admin"));
    await updateSystemDns();
  }

  async function runDnsCheck() {
    const id = (state.dnsProviders && state.dnsProviders[0] && state.dnsProviders[0].id) || "";
    const card = document.querySelector("#dnsProviders .provider-card.active");
    const provId = (card && card.dataset.id) || id;
    const res = document.createElement("div");
    res.style.marginTop = "12px";
    res.textContent = "…";
    $("dnsResult").replaceChildren(res);
    const r = await bridge.run_dns_check(provId);
    const lines = [I18n.t("dns.result_title", { id: provId })];
    if (r && r.servers) {
      for (const s of r.servers) {
        lines.push(`  ${s.server} — ${s.reachable ? `${I18n.t("dns.ok")} (${s.rtt_ms}ms)` : I18n.t("dns.unreach")}`);
      }
    }
    if (r && r.doh) lines.push(`  DoH — ${r.doh.rtt_ms ? `${I18n.t("dns.ok")} (${r.doh.rtt_ms}ms)` : I18n.t("dns.unreach")}`);
    const pre = document.createElement("pre");
    pre.className = "mono-block";
    pre.textContent = lines.join("\n");
    res.replaceChildren(pre);
  }

  async function renderDnsAdapters() {
    try {
      const data = await bridge.get_network_adapters();
      const el = $("dnsAdapters");
      if (!el) return;
      if (!data || !data.adapters || !data.adapters.length) {
        el.textContent = I18n.t("dns.adapters_none");
        return;
      }
      const lines = data.adapters.map((a) => {
        const conn = a.is_connected ? I18n.t("dns.conn_yes") : I18n.t("dns.conn_no");
        const dns = (a.dns_servers && a.dns_servers.length) ? a.dns_servers.join(", ") : I18n.t("dns.dns_none");
        return `${a.name} [${conn}] · ${I18n.t("dns.dns_servers")}: ${dns}`;
      });
      el.textContent = lines.join("\n");
    } catch (e) { /* noop */ }
  }

  async function runQuickDnsCheck() {
    const btn = $("dnsQuickBtn");
    if (btn) btn.disabled = true;
    try {
      const r = await bridge.run_quick_dns_check();
      const box = $("dnsQuickResult");
      const lines = [I18n.t(r && r.overall ? "dns.overall_ok" : "dns.overall_fail")];
      for (const row of (r && r.results) || []) {
        if (row.unsupported) {
          lines.push(`  ${row.name} — ${I18n.t("dns.ping_unsupported")}`);
          continue;
        }
        const st = row.ok ? I18n.t("dns.ok") : I18n.t("dns.unreach");
        const t = (row.time_ms != null) ? ` (${row.time_ms}ms)` : "";
        lines.push(`  ${row.name} (${row.host}) — ${st}${t}`);
      }
      const pre = document.createElement("pre");
      pre.className = "mono-block";
      pre.style.whiteSpace = "pre-wrap";
      pre.textContent = lines.join("\n");
      box.replaceChildren(pre);
    } catch (e) { /* noop */ } finally {
      if (btn) btn.disabled = false;
    }
  }

  let dnsPoisonTimer = null;

  async function runDnsPoisoning() {
    if (state.dnsPoisonRunning) return;
    const r = await bridge.run_dns_poisoning_check();
    if (!r || !r.ok) { toast(I18n.t("toast.err", { msg: (r && r.error) || "" })); return; }
    state.dnsPoisonRunning = true;
    $("dnsPoisonBtn").disabled = true;
    $("dnsPoisonStopBtn").disabled = false;
    const box = $("dnsPoisonResult");
    const pre = document.createElement("pre");
    pre.className = "mono-block";
    pre.style.whiteSpace = "pre-wrap";
    pre.textContent = I18n.t("dns.running") + "…";
    box.replaceChildren(pre);
    pollDnsPoisoning();
    dnsPoisonTimer = setInterval(pollDnsPoisoning, 700);
  }

  async function pollDnsPoisoning() {
    const st = await bridge.get_dns_check_status();
    if (!st) return;
    const box = $("dnsPoisonResult");
    const pre = box.querySelector("pre");
    if (pre && (st.lines || []).length) pre.textContent = st.lines.join("\n");
    if (st.status === "running") return;
    clearInterval(dnsPoisonTimer);
    dnsPoisonTimer = null;
    state.dnsPoisonRunning = false;
    $("dnsPoisonBtn").disabled = false;
    $("dnsPoisonStopBtn").disabled = true;
    if (!pre) return;
    const s = (st.result && st.result.summary) || {};
    if (!st.result) {
      pre.textContent = (pre.textContent ? pre.textContent + "\n" : "") + (st.message || st.status);
      return;
    }
    const tail = [I18n.t("dns.summary_title")];
    tail.push(`  YouTube — ${s.youtube_blocked ? I18n.t("dns.verdict_poisoned") : I18n.t("dns.verdict_clean")}`);
    tail.push(`  Discord — ${s.discord_blocked ? I18n.t("dns.verdict_poisoned") : I18n.t("dns.verdict_clean")}`);
    if (s.external_dns_blocked) tail.push(`  ${I18n.t("dns.external_blocked")}`);
    if (s.dns_poisoning_detected && s.recommended_dns) tail.push(`  ${I18n.t("dns.recommended", { dns: s.recommended_dns })}`);
    pre.textContent = (pre.textContent ? pre.textContent + "\n" : "") + tail.join("\n");
  }

  async function stopDnsPoisoning() {
    await bridge.stop_dns_poisoning_check();
    toast(I18n.t("dns.poison_stopping"));
  }

  // ── Hosts ──────────────────────────────────────────────────────────────
  async function renderHosts() {
    const [services, selected] = await Promise.all([
      bridge.get_hosts_services(),
      bridge.get_hosts_selection(),
    ]);
    if (!services) return;
    state.hostServices = services;
    for (const id of selected || []) {
      if (services.some((s) => s.id === id)) state.hostSelected.add(id);
    }
    const box = $("hostServices");
    box.innerHTML = "";
    for (const s of services) {
      const row = document.createElement("div");
      row.className = "row";
      const label = document.createElement("div");
      label.className = "label";
      label.textContent = s.name;
      const hint = document.createElement("div");
      hint.className = "hint";
      hint.textContent = `${I18n.t("hosts.cat_" + (s.category || "other"))} · ${I18n.t("hosts.domains_count", { count: s.domains.length })}`;
      label.appendChild(hint);
      const tg = Components.toggle(state.hostSelected.has(s.id), (v) => {
        if (v) state.hostSelected.add(s.id);
        else state.hostSelected.delete(s.id);
        save("hosts", "selected", Array.from(state.hostSelected));
      });
      row.append(label, tg);
      box.appendChild(row);
    }
    try {
      const active = await bridge.get_hosts_active();
      if (active) {
        const doms = Object.keys(active);
        for (const s of services) {
          if (s.domains.some((d) => doms.includes(d))) state.hostSelected.add(s.id);
        }
      }
    } catch (e) { /* noop */ }
    renderHostsSelection();
  }

  function renderHostsSelection() {
    const box = $("hostServices");
    if (!box) return;
    $$("label.toggle input[type=checkbox]", box).forEach((inp, i) => {
      const s = state.hostServices[i];
      if (s) inp.checked = state.hostSelected.has(s.id);
    });
  }

  async function applyHosts() {
    const res = await bridge.apply_hosts_services(Array.from(state.hostSelected));
    if (res && res.ok) toast(I18n.t("toast.applied") + ` · ${res.count}`);
    else toast(I18n.t("toast.err", { msg: "admin?" }));
  }

  async function clearHosts() {
    await bridge.clear_hosts();
    state.hostSelected.clear();
    renderHostsSelection();
    toast(I18n.t("toast.applied"));
  }

  // ── Presets ────────────────────────────────────────────────────────────
  async function renderPresets() {
    const [presets, active, lists] = await Promise.all([
      bridge.get_presets(),
      bridge.get_active_preset(),
      bridge.get_lists_status(),
    ]);
    state.activePreset = active;
    renderPresetList(presets || []);
    renderLists(lists);
  }

  function renderPresetList(presets) {
    const box = $("presetList");
    box.innerHTML = "";
    if (!presets.length) return;
    presets.forEach((p) => {
      const card = document.createElement("div");
      card.className = "preset-card" + (p.id === state.activePreset ? " active" : "");
      const head = document.createElement("div");
      head.className = "preset-head";
      const title = document.createElement("div");
      title.className = "preset-title";
      title.textContent = p.label;
      const badge = document.createElement("span");
      badge.className = "status-badge ok";
      badge.textContent = I18n.t("pr.active");
      badge.style.display = p.id === state.activePreset ? "inline-flex" : "none";
      head.append(title, badge);
      const del = Components.button(I18n.t("pr.delete"), "btn-ghost btn-sm", "close", async () => {
        const r = await bridge.delete_user_preset(p.id);
        if (r && r.ok) {
          toast(I18n.t("pr.deleted"));
          renderPresets();
        }
      });
      if (p.user) head.appendChild(del);
      const desc = document.createElement("div");
      desc.className = "hint";
      desc.textContent = p.description;
      const changes = document.createElement("div");
      changes.className = "preset-changes";
      const cl = document.createElement("div");
      cl.className = "hint";
      cl.textContent = I18n.t("pr.changes_title");
      changes.appendChild(cl);
      const rows = document.createElement("div");
      rows.className = "changes-row";
      (p.changes || []).forEach((c) => {
        const chip = document.createElement("span");
        chip.className = "chip";
        chip.textContent = `${c.section}.${c.key} = ${String(c.value)}`;
        rows.appendChild(chip);
      });
      changes.appendChild(rows);
      const act = document.createElement("div");
      act.className = "preset-actions";
      const btn = Components.button(I18n.t("pr.apply"), "btn-primary", "check", async () => {
        const r = await bridge.apply_preset(p.id);
        if (r && r.ok) {
          toast(I18n.t("pr.applied", { name: p.label }));
          state.activePreset = p.id;
          box.querySelectorAll(".preset-card").forEach((c) => c.classList.remove("active"));
          card.classList.add("active");
          badge.style.display = "inline-flex";
          await refreshStatus();
        } else if (r && r.error) {
          toast(I18n.t("toast.err", { msg: r.error }));
        }
      });
      act.appendChild(btn);
      card.append(head, desc, changes, act);
      box.appendChild(card);
    });
  }

  async function renderLists(lists) {
    const box = $("listStatus");
    if (!box) return;
    box.innerHTML = "";
    const info = document.createElement("div");
    info.className = "hint";
    const userCount = lists ? lists.user_count : 0;
    const finalCount = lists ? lists.final_count : 0;
    info.textContent = `${I18n.t("pr.lists_user", { count: userCount })} · ${I18n.t("pr.lists_final", { count: finalCount })}`;
    box.appendChild(info);
    const ta = $("userList");
    ta.value = lists && lists.user_text ? lists.user_text : "";
  }

  on("saveUserListBtn", "click", async () => {
    const r = await bridge.save_user_list($("userList").value);
    if (r && r.ok) {
      const st = await bridge.get_lists_status();
      if (st) {
        toast(I18n.t("pr.lists_saved", { count: st.final_count }));
        renderLists(st);
      }
    } else {
      toast(I18n.t("toast.err", { msg: (r && r.error) || "" }));
    }
  });

  on("savePresetBtn", "click", async () => {
    const name = $("presetName").value.trim();
    const desc = $("presetDesc").value.trim();
    const changes = [];
    const raw = $("presetChanges").value;
    raw.split(/\r?\n/).forEach((line) => {
      line = line.trim();
      if (!line || line.startsWith("#")) return;
      const eq = line.indexOf("=");
      if (eq < 0) return;
      const path = line.slice(0, eq).trim().split(".");
      const value = parseScalar(line.slice(eq + 1).trim());
      if (path.length >= 2 && value !== undefined) {
        changes.push({ section: path[0], key: path.slice(1).join("."), value });
      }
    });
    if (!changes.length) {
      toast(I18n.t("toast.err", { msg: I18n.t("pr.ed_bad") }), "error");
      return;
    }
    const r = await bridge.save_user_preset(name, desc, changes);
    if (r && r.ok) {
      toast(I18n.t("pr.saved_preset"));
      $("presetName").value = "";
      $("presetDesc").value = "";
      $("presetChanges").value = "";
      await renderPresets();
    } else {
      toast(I18n.t("toast.err", { msg: (r && r.error) || "" }), "error");
    }
  });

  function parseScalar(v) {
    if (/^(true|false)$/i.test(v)) return v.toLowerCase() === "true";
    if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
    const m = v.match(/^"(.*)"$/);
    return m ? m[1] : v;
  }

  // ── Zapret profiles & engine (winws) ────────────────────────────────
  const PF_TAGS = ["all", "alt", "game", "circular", "default", "youtube", "discord", "other"];
  const PF_GROUPS = ["winws1", "winws2", "strategies", "user"];
  async function renderProfiles() {
    state.pfGroup = state.pfGroup || "winws2";
    state.pfTag = state.pfTag || "all";
    let rows;
    if (state.pfGroup === "strategies") {
      const st = (await bridge.get_zapret_strategies()) || [];
      rows = st.map((s) => ({ id: s.id, file: s.title + ".txt", title: s.title, tags: ["strategy"], size: 0, text: s.text }));
    } else if (state.pfGroup === "user") {
      const up = (await bridge.get_zapret_user_profiles()) || [];
      rows = up.map((u) => ({ id: u.id, file: u.name + ".txt", title: u.name, tags: ["user"], size: u.size, text: null, user: true }));
    } else {
      rows = (await bridge.get_zapret_profiles(state.pfGroup)) || [];
    }
    state.pfAll = rows;
    const groups = $("pfGroups");
    groups.innerHTML = "";
    PF_GROUPS.forEach((g) => {
      const b = document.createElement("button");
      b.className = "chip" + (g === state.pfGroup ? " active" : "");
      b.textContent = I18n.t("pf.group_" + g);
      b.addEventListener("click", () => {
        state.pfGroup = g;
        state.pfTag = "all";
        $("pfDetailCard").style.display = "none";
        renderProfiles();
      });
      groups.appendChild(b);
    });
    const tags = $("pfTags");
    tags.innerHTML = "";
    if (state.pfGroup === "winws1" || state.pfGroup === "winws2") {
      PF_TAGS.forEach((t) => {
        const c = document.createElement("span");
        c.className = "chip" + (t === state.pfTag ? " active" : "");
        c.textContent = I18n.t("pf.tag_" + t);
        c.addEventListener("click", () => {
          state.pfTag = t;
          renderProfiles();
        });
        tags.appendChild(c);
      });
    } else if (state.pfGroup === "strategies") {
      const h = document.createElement("span");
      h.className = "hint";
      h.textContent = I18n.t("pf.strategy_hint");
      tags.appendChild(h);
    }
    const q = ($("pfSearch").value || "").toLowerCase();
    const sel = state.pfTag;
    const active = state.dpiEngine || {};
    $("pfListEditBtn").disabled = !(state.pfOpen || active.profile);
    const list = rows.filter((r) => {
      const tagsArr = r.tags || [];
      if (sel !== "all" && !tagsArr.includes(sel) && !(sel === "strategy" && tagsArr.includes("strategy"))) return false;
      if (q && !((r.title || "") + " " + (r.tags || []).join(" ")).toLowerCase().includes(q)) return false;
      return true;
    });
    const box = $("pfList");
    box.innerHTML = "";
    if (!list.length) {
      box.innerHTML = '<div class="hint" style="padding:10px 0">' + I18n.t("pf.empty") + "</div>";
      return;
    }
    list.forEach((r) => {
      const isActive = r.group === active.profile_group && r.file === active.profile && active.enabled;
      const row = document.createElement("div");
      row.className = "pf-row" + (isActive ? " active" : "");
      const left = document.createElement("div");
      const name = document.createElement("div");
      name.className = "preset-title";
      name.textContent = r.title;
      const tagsEl = document.createElement("div");
      tagsEl.className = "hint";
      tagsEl.textContent = (r.tags || []).join(" · ");
      left.append(name, tagsEl);
      const right = document.createElement("div");
      right.className = "row";
      right.style.gap = "8px";
      if (isActive) {
        const badge = document.createElement("span");
        badge.className = "status-badge ok pf-badge";
        badge.textContent = I18n.t("pf.active");
        right.appendChild(badge);
      }
      const size = document.createElement("div");
      size.className = "hint";
      size.textContent = (r.tags[0] === "strategy" || r.tags[0] === "user") ? (r.size ? Math.max(1, Math.round(r.size / 1024)) + " KB" : "") : Math.max(1, Math.round(r.size / 1024)) + " KB";
      right.appendChild(size);
      row.append(left, right);
      row.addEventListener("click", () => openProfile(r));
      box.appendChild(row);
    });
  }

  async function openProfile(r) {
    const group = r.group || state.pfGroup;
    let res;
    if (r.text) {
      res = { ok: true, text: r.text };
    } else if (group === "user") {
      res = await bridge.get_zapret_user_profile(r.file.replace(/\.txt$/, ""));
    } else {
      res = await bridge.get_zapret_profile_text(group, r.file);
    }
    if (!res || !res.ok) return;
    $("pfDetailCard").style.display = "";
    $("pfDetailTitle").textContent = r.title;
    $("pfDetailPre").textContent = res.text;
    state.pfOpen = { group: group, file: r.file, title: r.title, user: group === "user", text: res.text };
    closeProfileDrawer();
    const isStrategy = group === "strategies";
    $("pfApplyBtn").disabled = isStrategy;
    $("pfApplyBtn").title = isStrategy ? I18n.t("pf.strategy_hint") : "";
  }

  async function applyOpenProfile() {
    const o = state.pfOpen;
    if (!o || o.group === "strategies") return;
    const res = o.user && o.group === "user"
      ? await bridge.start_dpi("user", o.file.replace(/\.txt$/, ""))
      : await bridge.start_dpi(o.group, o.file);
    if (res && res.ok) {
      toast(I18n.t("pf.applied"));
      state.dpiEngine = await bridge.get_zapret_engine();
      renderDpiEngine();
      renderProfiles();
    } else {
      toast(I18n.t("pf.err_start", { msg: ((res && res.detail) || (res && res.error)) || I18n.t("pf.not_found") }), "error");
    }
  }

  function closeProfileDrawer() {
    $("pfDrawerBackdrop").classList.remove("open");
    $("pfDrawer").classList.remove("open");
    state.pfDrawer = null;
  }

  function profileErrorMsg(code) {
    const map = {
      protected_active: I18n.t("pr.protected_active"),
      protected_recommended: I18n.t("pr.protected_recommended"),
      not_found: I18n.t("pr.not_found"),
    };
    return map[code] || code || "";
  }

  function isRecommendedName(name) {
    const cur = state.pfRecommended || "";
    return !!name && name.replace(/\.txt$/, "") === cur.replace(/\.txt$/, "");
  }

  const PF_PARAM_KEYS = [
    "hostlist", "ipset", "ipset-exclude", "filter-tcp", "filter-udp",
    "out-range", "in-range", "payload", "lua-desync",
    "hostlist-local", "ipset-local", "ipset-exclude-local",
    "wf-tcp-out", "wf-tcp-in", "wf-udp-out", "wf-udp-in",
    "wf-raw-part", "blob", "lua-init",
    "ctrack-disable", "ipcache-lifetime", "ipcache-hostname",
    "fake-ttl", "fake-ncount", "fake-wait", "fake-chunk", "fake-data-length",
    "repeats", "dpi-desync", "dpi-desync-repeats", "dpi-desync-ttl", "dpi-desync-cut",
    "dpi-desync-fooling", "dpi-desync-fake-tls", "dpi-desync-fake-quic",
    "dpi-desync-cutoff", "dpi-desync-autottl",
  ];

  const PF_VALUE_OPTIONS = {
    "lua-desync": [
      "send", "syndata", "fake", "multisplit", "multidisorder",
      "hostfakesplit", "hostfakesplit_multi", "tls_multisplit_sni",
      "pktmod", "pass", "circular", "retrans"
    ],
    "dpi-desync": ["fake", "split", "multisplit", "multidisorder"],
    "dpi-desync-repeats": ["1", "2", "3", "4", "5", "6", "8"],
    "dpi-desync-cut": ["1", "2", "4", "8"],
    "dpi-desync-ttl": ["1", "2", "3", "4", "5"],
    "dpi-desync-fooling": ["md5seq", "ackseq", "otv", "presets"],
    "payload": ["tls_client_hello", "tls_server_hello", "all", "http"],
  };

  function pfParseLines(text) {
    const items = [];
    (text || "").split(/\r?\n/).forEach((raw) => {
      const line = raw.replace(/\s+$/, "");
      if (!line.trim()) { items.push({ type: "blank", raw: line }); return; }
      if (line.startsWith("#")) { items.push({ type: "comment", raw: line }); return; }
      if (line.startsWith("@")) { items.push({ type: "include", raw: line }); return; }
      if (line === "--new") { items.push({ type: "new", raw: line }); return; }
      const m = line.match(/^(--([^=]+))(?:=(.+))?$/);
      if (m) {
        const key = m[2];
        const value = m[3] ?? "";
        if (key === "name") { items.push({ type: "section", name: value, raw: line }); return; }
        let auto = false;
        let strategy = "";
        let base = value;
        const si = value.lastIndexOf(":strategy=");
        if (si !== -1) {
          auto = true;
          strategy = value.slice(si + 10);
          base = value.slice(0, si);
        }
        items.push({ type: "param", key: m[1], paramKey: key, value: value, base: base, auto: auto, strategy: strategy, raw: line });
        return;
      }
      items.push({ type: "raw", raw: line });
    });
    return items;
  }

  function pfSerialize(items) {
    return items.map((it) => {
      if (it.type === "blank") return "";
      if (it.type === "comment" || it.type === "include" || it.type === "new" || it.type === "raw") return it.raw;
      if (it.type === "section") return "--name=" + (it.name || "");
      if (it.type === "param") {
        let val = it.base || "";
        if (it.auto && it.strategy) val += ":strategy=" + it.strategy;
        return it.key + (val !== "" ? "=" + val : "");
      }
      return it.raw;
    }).join("\r\n");
  }

  function drawerParamControl(it) {
    const row = document.createElement("div");
    row.className = "pf-param-row" + (it.user ? " user" : "");
    if (it.type === "comment") {
      row.innerHTML = '<span class="pf-comment">' + escapeHTML(it.raw) + '</span>';
      const del = document.createElement("button");
      del.className = "pf-param-del";
      del.innerHTML = Icon("close", 16);
      del.title = "Delete";
      del.addEventListener("click", () => { row.remove(); syncDrawerItems(); });
      row.appendChild(del);
      return row;
    }
    if (it.type === "section") {
      row.innerHTML = '<span class="pf-section-title">' + escapeHTML("--name=" + (it.name || "")) + '</span>';
      const del = document.createElement("button");
      del.className = "pf-param-del";
      del.innerHTML = Icon("close", 16);
      del.title = "Delete";
      del.addEventListener("click", () => { row.remove(); syncDrawerItems(); });
      row.appendChild(del);
      return row;
    }
    if (it.type === "new") {
      row.innerHTML = '<span class="pf-section-title" style="flex:1;color:var(--accent-warm)">--new</span>';
      const del = document.createElement("button");
      del.className = "pf-param-del";
      del.innerHTML = Icon("close", 16);
      del.title = "Delete";
      del.addEventListener("click", () => { row.remove(); syncDrawerItems(); });
      row.appendChild(del);
      return row;
    }
    if (it.type === "raw") {
      row.innerHTML = '<span class="pf-raw-line">' + escapeHTML(it.raw) + '</span>';
      const del = document.createElement("button");
      del.className = "pf-param-del";
      del.innerHTML = Icon("close", 16);
      del.title = "Delete";
      del.addEventListener("click", () => { row.remove(); syncDrawerItems(); });
      row.appendChild(del);
      return row;
    }
    if (it.type === "param") {
      const nameEl = document.createElement("span");
      nameEl.className = "pf-param-name" + (it.auto ? " auto" : "");
      nameEl.textContent = it.paramKey;
      nameEl.dataset.key = it.paramKey;
      row.appendChild(nameEl);

      const opts = PF_VALUE_OPTIONS[it.paramKey];
      let ctrl;
      if (opts) {
        ctrl = document.createElement("select");
        ctrl.className = "pf-param-value";
        opts.forEach((o) => {
          const opt = document.createElement("option");
          opt.value = o;
          opt.textContent = o;
          ctrl.appendChild(opt);
        });
        if (it.base && !opts.includes(it.base)) {
          const custom = document.createElement("option");
          custom.value = it.base;
          custom.textContent = it.base;
          ctrl.insertBefore(custom, ctrl.firstChild);
        }
        ctrl.value = it.base || "";
      } else {
        ctrl = document.createElement("input");
        ctrl.className = "pf-param-value";
        ctrl.type = "text";
        ctrl.spellcheck = false;
        ctrl.placeholder = it.auto ? "flag (auto)" : "value";
        ctrl.value = it.base || "";
      }
      if (it.auto) ctrl.disabled = true;
      row.appendChild(ctrl);

      if (it.auto) {
        const badge = document.createElement("span");
        badge.className = "pf-param-badge";
        badge.textContent = "#" + it.strategy + " auto";
        row.appendChild(badge);
      }

      const del = document.createElement("button");
      del.className = "pf-param-del";
      del.innerHTML = Icon("close", 16);
      del.title = "Delete";
      del.addEventListener("click", () => { row.remove(); syncDrawerItems(); });
      row.appendChild(del);
      return row;
    }
    return row;
  }

  function syncDrawerItems() {
    if (!state.pfDrawer) return;
    const container = $("pfDrawerParams");
    state.pfDrawer.items = [];
    container.childNodes.forEach((row) => {
      const key = row.querySelector(".pf-param-name");
      if (key) {
        const isAuto = key.classList.contains("auto");
        const badge = row.querySelector(".pf-param-badge");
        const ctrl = row.querySelector("select, input");
        let base = "";
        let strategy = "";
        let paramKey = "";
        if (ctrl && ctrl.value) base = ctrl.value;
        if (badge) {
          const m = badge.textContent.match(/#(\d+)/);
          if (m) strategy = m[1];
        }
        if (isAuto) {
          key.textContent = (key.dataset.key || key.textContent);
        }
        paramKey = (key.dataset.key || key.textContent || "").trim();
        state.pfDrawer.items.push({
          type: "param",
          key: "--" + paramKey,
          paramKey: paramKey,
          value: "",
          base: base,
          auto: isAuto && !!strategy,
          strategy: strategy,
        });
      } else if (row.querySelector(".pf-section-title")) {
        const t = row.querySelector(".pf-section-title").textContent || "";
        if (t === "--new") {
          state.pfDrawer.items.push({ type: "new", raw: "--new" });
        } else {
          const m = t.match(/^--name=(.*)$/);
          state.pfDrawer.items.push({ type: "section", name: m ? m[1] : "", raw: t });
        }
      } else if (row.querySelector(".pf-comment")) {
        state.pfDrawer.items.push({ type: "comment", raw: row.querySelector(".pf-comment").textContent });
      } else if (row.querySelector(".pf-raw-line")) {
        state.pfDrawer.items.push({ type: "raw", raw: row.querySelector(".pf-raw-line").textContent });
      }
    });
  }

  function renderDrawer() {
    const d = state.pfDrawer;
    if (!d) return;
    const box = $("pfDrawerParams");
    box.innerHTML = "";
    d.items.forEach((it) => {
      const row = drawerParamControl(it);
      box.appendChild(row);
    });
    $("pfAddParamKey").innerHTML = "";
    PF_PARAM_KEYS.forEach((k) => {
      const opt = document.createElement("option");
      opt.value = k;
      opt.textContent = k;
      $("pfAddParamKey").appendChild(opt);
    });
    $("pfAddParamValue").value = "";
    $("pfAddParamRow").style.display = "none";
  }

  function openProfileDrawer(name, content, opts) {
    const o = opts || {};
    state.pfDrawer = { name: name || "", items: pfParseLines(content || ""), recommended: !!o.recommended, user: !!o.user };
    $("pfDrawerTitle").textContent = name || I18n.t("pf.drawer_title");
    $("pfEditorName").value = (name || "").replace(/\.txt$/, "");
    $("pfRecNote").style.display = o.recommended ? "" : "none";
    $("pfResetBtn").style.display = o.recommended ? "" : "none";
    $("pfDeleteBtn").style.display = o.user && !o.recommended ? "" : "none";
    $("pfVerdict").style.display = "none";
    $("pfVerdict").innerHTML = "";
    renderDrawer();
    $("pfDrawerBackdrop").classList.add("open");
    $("pfDrawer").classList.add("open");
  }

  function verdictLine(v, kind, titleKey) {
    const rows = (v && v[kind]) || [];
    if (!rows.length) return "";
    let html = '<div class="hint" style="margin-top:6px;font-weight:600">' + I18n.t(titleKey) + '</div><ul style="margin:4px 0 0 18px;font-size:11px;line-height:1.6">';
    rows.forEach((it) => {
      const tpl = I18n.t("pr." + it.message)
        .replace("{key}", it.key || "")
        .replace("{n}", it.line || "");
      html += "<li>" + tpl + "</li>";
    });
    return html + "</ul>";
  }

  function renderVerdict(v) {
    const el = $("pfVerdict");
    if (!v) {
      el.style.display = "none";
      el.innerHTML = "";
      return;
    }
    const badge = v.ok
      ? '<span class="status-badge ok">' + I18n.t("pr.verdict_ok", { n: v.param_count || 0 }) + "</span>"
      : '<span class="status-badge off">' + I18n.t("pr.invalid", { n: v.param_count || 0 }) + "</span>";
    let html = '<div class="row" style="gap:8px">' + badge + "</div>";
    html += verdictLine(v, "errors", "pr.errors_title");
    html += verdictLine(v, "warnings", "pr.warnings_title");
    el.innerHTML = html;
    el.style.display = "";
  }

  async function editOpenProfile() {
    let o = state.pfOpen;
    if (!o) {
      const eng = state.dpiEngine || {};
      if (eng.profile) {
        o = { group: eng.profile_group || "user", file: eng.profile, title: eng.profile, user: eng.profile_group === "user" };
      }
    }
    if (!o) {
      toast(I18n.t("pr.select_none"));
      return;
    }
    if (o.group === "strategies") {
      toast(I18n.t("pf.strategy_hint"));
      return;
    }
    let res;
    if (o.text) {
      res = { ok: true, content: o.text };
    } else if (o.user) {
      res = await bridge.get_zapret_user_profile(o.file.replace(/\.txt$/, ""));
    } else {
      res = await bridge.get_zapret_profile_text(o.group, o.file);
    }
    if (!res || !res.ok) {
      toast(I18n.t("pr.not_found"), "error");
      return;
    }
    const name = o.title.replace(/\.txt$/, "");
    openProfileDrawer(name, res.text || "", { user: !!o.user, recommended: isRecommendedName(name) });
  }

  async function renderDpiEngine() {
    const eng = await bridge.get_zapret_engine();
    const st = await bridge.get_dpi_status();
    if (!eng) return;
    state.dpiEngine = eng;
    const dot = $("dpiStateDot");
    const stateText = $("dpiStateText");
    const badge = $("dpiEngineBadge");
    const running = st && (st.state === "running" || st.state === "starting");
    state.dpiRunning = !!running;
    dot.className = "status-dot" + (running ? " ok" : (st && st.state === "error" ? " err" : ""));
    if (running) {
      stateText.textContent = I18n.t("pf.running") + (st.pid ? " · PID " + st.pid : "");
    } else if (st && st.state === "error") {
      stateText.textContent = I18n.t("pf.stopped") + " · " + (st.last_error || st.exit_code);
    } else {
      stateText.textContent = I18n.t("pf.stopped");
    }
    if (eng.ok) {
      const label = I18n.t("pf.engine_badge_on", { e: eng.mode || "auto" });
      badge.textContent = label;
      badge.className = "engine-badge";
      $("dpiNotice").style.display = "none";
      $("dpiStartBtn").disabled = false;
    } else {
      badge.textContent = I18n.t("pf.engine_badge_off");
      badge.className = "engine-badge off";
      $("dpiNotice").style.display = "";
      $("dpiNotice").textContent = I18n.t("pf.not_found");
      $("dpiStartBtn").disabled = true;
    }
    $$("#dpiModeSeg button").forEach((b) => {
      b.classList.toggle("active", b.dataset.val === (eng.mode || "auto"));
    });
    $("dpiAutostartChk").checked = !!eng.autostart;
    $("dpiStopBtn").disabled = !running;
    $("dpiRestartBtn").disabled = !running && !eng.ok;
    await loadWinwsLog();
  }

  async function loadWinwsLog() {
    const res = await bridge.get_winws_log(8000);
    const el = $("dpiLog");
    if (!el) return;
    el.textContent = res && res.ok ? res.log : "";
    if (el.scrollHeight > el.clientHeight) el.scrollTop = el.scrollHeight;
  }

  // ── Autopilot «Обход Zapret» ────────────────────────────────────────────
  const AU_PHASE_KEYS = {
    idle: "au.phase_idle",
    scanning: "au.phase_scan",
    planning: "au.phase_plan",
    dns_repair: "au.phase_dns_repair",
    applying: "au.phase_apply",
    starting: "au.phase_start",
    monitoring: "au.phase_monitor",
    error: "au.phase_error",
    stopped: "au.phase_stopped",
  };
  const AU_PHASE_WARN = { scanning: 1, planning: 1, dns_repair: 1, applying: 1, monitoring: 1 };
  const AU_ACTIVE = { scanning: 1, planning: 1, dns_repair: 1, applying: 1, starting: 1, monitoring: 1 };

  function toggleAutoMode() {
    state.autoMode = !state.autoMode;
    document.body.classList.toggle("auto-mode", state.autoMode);
    document.querySelectorAll("[data-manual-card]").forEach(el => {
      el.style.display = state.autoMode ? "none" : "";
    });
    const btn = $("autoModeBtn");
    if (btn) btn.classList.toggle("active", state.autoMode);
  }
  window._autoModeToggle = toggleAutoMode;

  function autopilotStatus(text) {
    const el = $("pfOrStatus");
    if (!el) return;
    el.style.display = "";
    el.className = "notice";
    el.textContent = text || "";
  }

  async function renderAutopilot() {
    const statusEl = $("autoStatus");
    if (!statusEl) return;
    const st = await bridge.auto_status();
    if (!st) return;
    const phase = st.phase || "idle";
    const active = !!st.active || !!AU_ACTIVE[phase];
    $("autoStartBtn").disabled = active;
    $("autoStopBtn").disabled = !active;
    $("autoResetBtn").disabled = active;

    if (phase === "idle") {
      statusEl.style.display = "none";
    } else {
      statusEl.style.display = "";
      statusEl.className = "notice" + (phase === "error" ? " error" : AU_PHASE_WARN[phase] ? " warn" : " ok");
      let txt = I18n.t(AU_PHASE_KEYS[phase] || "au.phase_idle");
      if (st.message) txt += " — " + st.message;
      if (st.last_error) txt += " (" + st.last_error + ")";
      statusEl.textContent = txt;
    }

    const meta = $("autoMeta");
    meta.innerHTML = "";
    const addMeta = (key, val) => {
      const el = document.createElement("span");
      el.className = "hint";
      el.textContent = I18n.t(key) + ": " + val;
      meta.appendChild(el);
    };
    if (st.attempt) addMeta("au.attempt", st.attempt + "/" + (st.max_attempts || 4));
    if (st.progress && st.progress.tested) addMeta("au.domains", st.progress.tested);
    if (st.progress && st.progress.blocked) addMeta("au.blocked", st.progress.blocked);
    if (st.mode) addMeta("au.engine", st.mode);
    if (st.profile) addMeta("au.profile", String(st.profile).replace(/\.txt$/, ""));
    if (st.chosen && st.chosen.strategy) addMeta("au.strategy", st.chosen.name || st.chosen.strategy);
    if (st.started_at) addMeta("au.started_at", st.started_at);

    const recBox = $("autoRecommendations");
    recBox.innerHTML = "";
    if (st.recommendations && st.recommendations.length) {
      const t = document.createElement("div");
      t.className = "card-subtitle";
      t.style.marginTop = "10px";
      t.textContent = I18n.t("au.recommendations");
      recBox.appendChild(t);
      st.recommendations.slice(0, 4).forEach((r) => recBox.appendChild(orRecommendation(r, autopilotStatus)));
    }

    const j = await bridge.auto_journal(400);
    const jEl = $("autoJournal");
    const lines = (j && j.ok && j.lines) || [];
    jEl.textContent = lines.length ? lines.map((e) => e.ts + "  " + e.text).join("\n") : I18n.t("au.journal_empty");
    jEl.scrollTop = jEl.scrollHeight;
  }

  // ── Ручной подбор стратегии (в карточке автопилота) ─────────────────────
  async function pfOrRun() {
    const text = ($("pfOrSymptoms").value || "").trim();
    const btn = $("pfOrRunBtn");
    btn.disabled = true;
    const statusEl = $("pfOrStatus");
    statusEl.className = "notice";
    statusEl.style.display = "";
    statusEl.textContent = I18n.t("bc.running_short");
    const box = $("pfOrRecommendations");
    box.innerHTML = "";
    try {
      const res = await bridge.orchestra_recommend(text);
      if (!res || !res.ok || !res.recommendations || !res.recommendations.length) {
        statusEl.textContent = (res && res.error) || I18n.t("or.no_data");
        return;
      }
      statusEl.textContent = res.source === "text" ? I18n.t("or.source_manual") : I18n.t("or.source_report");
      res.recommendations.forEach((r) => box.appendChild(orRecommendation(r, autopilotStatus)));
    } catch (e) {
      statusEl.textContent = String((e && e.message) || e);
    } finally {
      btn.disabled = false;
    }
  }

  // ── Создание профиля из шаблона ─────────────────────────────────────────
  let pfCreateTemplates = null;
  async function pfCreateTemplatesList() {
    if (pfCreateTemplates) return pfCreateTemplates;
    const tpl = [{ val: "empty", label: I18n.t("pf.create_empty") }];
    const rec = await bridge.profile_list();
    if (rec && rec.recommended) {
      tpl.push({ val: "rec", label: I18n.t("pf.based_recommended") });
    }
    const w2 = (await bridge.get_zapret_profiles("winws2")) || [];
    w2.slice(0, 12).forEach((p) => {
      tpl.push({ val: "winws2:" + p.file, label: I18n.t("pf.based_winws2") + ": " + p.title });
    });
    pfCreateTemplates = tpl;
    return tpl;
  }

  async function showPfCreate() {
    const tpls = await pfCreateTemplatesList();
    const sel = $("pfCreateTemplate");
    sel.innerHTML = "";
    tpls.forEach((t) => {
      const o = document.createElement("option");
      o.value = t.val;
      o.textContent = t.label;
      sel.appendChild(o);
    });
    $("pfCreateRow").style.display = "flex";
    $("pfCreateName").value = "";
    $("pfCreateName").focus();
  }

  async function pfCreateOk() {
    const name = $("pfCreateName").value.trim();
    if (!name || /[\\/]/.test(name)) {
      toast(I18n.t("pr.name_invalid"), "error");
      return;
    }
    const tpl = $("pfCreateTemplate").value;
    let content = "";
    try {
      if (tpl === "rec") {
        const rec = await bridge.profile_list();
        const recName = rec && rec.recommended ? rec.recommended.replace(/\.txt$/, "") : "";
        if (recName) {
          const r = await bridge.get_zapret_user_profile(recName);
          if (r && r.ok) content = r.text;
        }
      } else if (tpl.indexOf("winws2:") === 0) {
        const r = await bridge.get_zapret_profile_text("winws2", tpl.slice(7));
        if (r && r.ok) content = r.text;
      }
    } catch (e) {}
    $("pfCreateRow").style.display = "none";
    openProfileDrawer(name, content, { user: true });
  }

  // ── Autostart ─────────────────────────────────────────────────────────
  function asProviderState(prov, scope) {
    const s = (prov && prov[scope]) || {};
    return { installed: !!s.installed, running: !!s.running, details: s.details || null };
  }

  async function renderAutostart() {
    const st = await bridge.get_autostart_status();
    const listEl = $("asList");
    const hintEl = $("asHint");
    const scope = state.asScope || "app";
    const scoped = (el) => el.classList.toggle("active", el.dataset.val === scope);
    $$("#asScope button").forEach(scoped);
    if (st && st.ok === false) {
      if (hintEl) hintEl.textContent = (st && st.error) || "";
      if (listEl) listEl.innerHTML = "";
      $("asStartService").disabled = true;
      $("asStopService").disabled = true;
      return;
    }
    if (hintEl) {
      if (!st || st.unsupported) hintEl.textContent = I18n.t("as.unsupported");
      else if (!st.is_admin) hintEl.textContent = I18n.t("as.not_admin");
      else hintEl.textContent = I18n.t("as.hint");
    }
    const rows = ["nssm", "task", "shortcut"]
      .filter((p) => st && st[p])
      .map((p) => {
        const prov = st[p] || {};
        const s = asProviderState(prov, scope);
        const text = s.installed ? (s.running ? I18n.t("as.running") : I18n.t("as.stopped")) : I18n.t("as.not_installed");
        const providerKey = { nssm: "as.provider_nssm", task: "as.provider_task", shortcut: "as.provider_shortcut" }[p];
        const name = I18n.t(providerKey);
        if (p === "nssm" && !prov.present) {
          return '<div class="row" style="gap:8px"><span class="label">' + name + '</span>' +
            '<span class="hint">' + I18n.t("as.nssm_missing") + "</span></div>";
        }
        const installBtn = '<button class="btn btn-ghost btn-sm" data-act="install" data-provider="' + p + '"' + (s.installed || p === "nssm" && !prov.present ? " disabled" : "") + ">" + I18n.t("as.install") + "</button>";
        const removeBtn = '<button class="btn btn-warm btn-sm" data-act="remove" data-provider="' + p + '"' + (s.installed ? "" : " disabled") + ">" + I18n.t("as.remove") + "</button>";
        return '<div class="row" style="gap:8px;align-items:center"><span class="label">' + name + "</span>" +
          '<span class="hint">' + text + "</span>" +
          '<span style="margin-left:auto;display:flex;gap:6px">' + installBtn + removeBtn + "</span></div>";
      });
    if (listEl) listEl.innerHTML = rows.join("");
    const nssmOk = !!(st && !st.unsupported && st.nssm && st.nssm.present);
    $("asStartService").disabled = !nssmOk;
    $("asStopService").disabled = !nssmOk;
  }

  // ── Diagnostics & Windows tools ──────────────────────────────────────
  async function renderTools() {
    const st = await bridge.get_windows_tool_status();
    if (!st) return;
    const el = $("winToolsStatus");
    const admin = st.admin ? I18n.t("tl.admin_yes") : I18n.t("tl.admin_no", { app: st.app_dir });
    const driver = st.driver && st.driver.present
      ? "WinDivert ✓" + (st.driver.system ? "" : " (" + I18n.t("tl.driver_bundled") + ")")
      : "WinDivert ✗";
    const dns = (st.system_dns || []).join(", ") || "—";
    el.textContent = I18n.t("tl.win_status", { admin: admin, driver: driver, dns: dns });
    wlStatus();
  }

  // ── WinDivert card ─────────────────────────────────────────────────────
  async function renderWinDivert() {
    const el = $("winDivertStatus");
    if (!el) return;
    el.textContent = I18n.t("wh.loading");
    const st = await bridge.get_winws_health();
    if (!st) return;
    let text = st.windivert_ready
      ? "WinDivert ✓ " + I18n.t("wh.ready")
      : "WinDivert ✗ " + I18n.t("wh.not_ready");
    const driver = st.driver_present
      ? I18n.t("wh.driver_ok")
      : I18n.t("wh.driver_missing");
    text += "  ·  " + I18n.t("wh.driver_state", { driver: driver });
    if (st.bundled_driver) text += " (" + I18n.t("wh.bundled") + ")";
    text += "  ·  " + (st.conflicts && st.conflicts.length
      ? I18n.t("wh.conflicts", { list: st.conflicts.join(", ") })
      : I18n.t("wh.conflicts_none"));
    el.textContent = text;
  }

  function whShowResult(html) {
    const box = $("whResult");
    box.innerHTML = html;
    box.style.display = box.innerHTML.trim() ? "" : "none";
  }

  async function whDiag() {
    $("whResult").style.display = "none";
    const report = await bridge.run_winws_diagnostics();
    if (!report) {
      whShowResult('<div class="hint">' + I18n.t("wh.no_result") + "</div>");
      return;
    }
    const html = [];
    if (report.last_crash_diagnosis && report.last_crash_diagnosis.cause) {
      html.push('<div class="hint">' + I18n.t("wh.exit_line", { line: report.last_crash_diagnosis.cause }) + "</div>");
    }
    if (report.windivert_error) {
      html.push('<div class="hint">' + I18n.t("wh.suggest", {
        s: report.windivert_error.meaning + ". " + (report.windivert_error.solution || ""),
      }) + "</div>");
    }
    (report.suggestions || []).forEach((s) => {
      html.push('<div class="hint">' + I18n.t("wh.suggest", { s: s }) + "</div>");
    });
    if (!html.length) html.push('<div class="hint">' + I18n.t("wh.ready") + "</div>");
    whShowResult(html.join(""));
    renderWinDivert();
  }

  async function whCleanup(level) {
    $("whResult").style.display = "none";
    const res = await bridge.windivert_cleanup(level);
    if (!res) {
      whShowResult('<div class="hint">' + I18n.t("wh.no_result") + "</div>");
      return;
    }
    let msg;
    if (res.requires_admin) {
      msg = I18n.t("wh.cleanup_admin");
    } else if (res.ok) {
      msg = I18n.t("wh.cleanup_ok");
    } else {
      msg = I18n.t("wh.cleanup_busy", { msg: (res.failed || []).join("; ") || "" });
    }
    whShowResult('<div class="hint">' + msg + "</div>");
    renderWinDivert();
  }

  async function whKillConflicts() {
    $("whResult").style.display = "none";
    const res = await bridge.kill_conflicting_processes();
    if (!res) {
      whShowResult('<div class="hint">' + I18n.t("wh.no_result") + "</div>");
      return;
    }
    let msg;
    if (res.ok && (res.killed || []).length) {
      msg = I18n.t("wh.kill_done");
    } else if (res.ok) {
      msg = I18n.t("wh.kill_none");
    } else {
      msg = I18n.t("wh.kill_failed", { msg: (res.killed || [res.error || ""]).join("; ") });
    }
    whShowResult('<div class="hint">' + msg + "</div>");
    renderWinDivert();
  }

  async function whLog() {
    $("whResult").style.display = "none";
    const res = await bridge.get_winws_log(8000);
    if (!res) {
      whShowResult('<div class="hint">' + I18n.t("wh.no_result") + "</div>");
      return;
    }
    const log = res && res.ok && res.log ? res.log : "";
    whShowResult(log ? "<pre class=\"mono-block\">" + log.replace(/</g, "&lt;") + "</pre>" : '<div class="hint">' + I18n.t("wh.ready") + "</div>");
  }

  const WL_STATUS_TEXT = {
    no_log: "wl.status_no_log",
    ok: "wl.status_ok",
    warning: "wl.status_warning",
    error: "wl.status_error",
  };
  const WL_REASON_TEXT = {
    no_log: "wl.reason_no_log",
    no_content: "wl.reason_no_content",
    external: "wl.reason_external",
    stopped: "wl.reason_stopped",
    clean_exit: "wl.reason_clean_exit",
    waiting: "wl.reason_waiting",
    booting: "wl.reason_booting",
    pf_calc: "wl.reason_pf_calc",
    no_config: "wl.reason_no_config",
    load_failed: "wl.reason_load_failed",
    not_appeared: "wl.reason_not_appeared",
    appeared_disappeared: "wl.reason_appeared_disappeared",
  };

  function wlShowResult(html) {
    const box = $("wlResult");
    box.innerHTML = html;
    box.style.display = box.innerHTML.trim() ? "" : "none";
  }

  async function wlStatus() {
    const box = $("wlResult");
    if (box) box.style.display = "none";
    const el = $("wlStatus");
    if (!el) return;
    el.textContent = I18n.t("wl.loading");
    const st = await bridge.get_winws_log_status();
    if (!st || st.ok === false) {
      el.textContent = I18n.t("wl.no_log");
      return;
    }
    const v = st.verdict || {};
    const statusKey = WL_STATUS_TEXT[v.status] || "wl.status_no_log";
    const bits = [I18n.t(statusKey)];
    if (v.status === "no_log") {
      el.textContent = I18n.t(WL_REASON_TEXT[v.reason] || "wl.reason_no_log");
      return;
    }
    if (v.reason && WL_REASON_TEXT[v.reason]) bits.push(I18n.t(WL_REASON_TEXT[v.reason]));
    if (st.last_session && st.last_session.started_at) {
      bits.push(I18n.t("wl.last_run", { at: st.last_session.started_at }));
    }
    bits.push(I18n.t("wl.sessions", { count: st.sessions_count }));
    el.textContent = bits.join("  ·  ");
    const html = [];
    if (v.detail) {
      html.push('<div class="hint">' + I18n.t("wl.detail") + ": " + v.detail.replace(/</g, "&lt;") + "</div>");
    }
    if (st.errors && st.errors.length) {
      html.push('<div class="hint">' + I18n.t("wl.errors") + " (" + st.errors.length + ")</div>");
      html.push('<pre class="mono-block">' + st.errors.map((l) => l.replace(/</g, "&lt;")).join("\n") + "</pre>");
    }
    if (st.warnings && st.warnings.length) {
      html.push('<div class="hint">' + I18n.t("wl.warnings") + " (" + st.warnings.length + ")</div>");
      html.push('<pre class="mono-block">' + st.warnings.map((l) => l.replace(/</g, "&lt;")).join("\n") + "</pre>");
    }
    wlShowResult(html.join(""));
  }

  async function wlShow() {
    const box = $("wlResult");
    if (!box) return;
    box.style.display = "none";
    const res = await bridge.read_winws_log_last(200);
    const rows = (res && res.ok && res.lines) ? res.lines : [];
    box.textContent = rows.length ? rows.join("\n") : I18n.t("wl.no_content");
    box.style.display = "";
  }

  async function runDiag() {
    const btn = $("runDiagBtn");
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = I18n.t("tl.running");
    $("diagResult").innerHTML = "";
    $("diagVerdict").style.display = "none";
    $("diagActions").style.display = "none";
    const report = await bridge.run_diagnostics();
    btn.disabled = false;
    btn.textContent = old;
    renderDiagReport(report);
  }

  function renderDiagReport(report) {
    if (!report || !report.ok) {
      $("diagResult").innerHTML = '<div class="hint">' + I18n.t("tl.failed") + "</div>";
      return;
    }
    const verdict = $("diagVerdict");
    verdict.style.display = "";
    verdict.className = "notice diag-verdict " + report.verdict;
    verdict.textContent = I18n.t("dg.verdict_" + report.verdict) + "  ·  " + report.duration_ms + " мс";
    const acts = $("diagActions");
    acts.innerHTML = "";
    acts.style.display = "";
    (report.suggestions || []).forEach((s) => {
      const b = document.createElement("button");
      b.className = "btn btn-sm " + (s.action === "none" ? "btn-ghost" : "btn-primary");
      b.textContent = I18n.t(s.key);
      b.addEventListener("click", () => diagAction(s.action, report));
      acts.appendChild(b);
    });
    const box = $("diagResult");
    box.innerHTML = "";
    (report.groups || []).forEach((g) => {
      const card = document.createElement("div");
      card.className = "diag-group";
      const head = document.createElement("div");
      head.className = "card-subtitle";
      head.textContent = I18n.t("dg.group_" + g.key);
      card.appendChild(head);
      (g.items || []).forEach((it) => card.appendChild(diagRow(it)));
      box.appendChild(card);
    });
  }

  function diagRow(it) {
    const row = document.createElement("div");
    row.className = "diag-row";
    const dot = document.createElement("span");
    dot.className = "status-dot " + (it.status === "ok" ? "ok" : it.status === "fail" ? "err" : "");
    const label = document.createElement("span");
    label.className = "diag-label";
    label.textContent = I18n.t("dg.msg_" + it.msg_key) + (it.title ? "  " + it.title : "");
    const text = document.createElement("span");
    text.className = "hint diag-text";
    const args = {};
    ["ms", "value", "ips", "pid", "count", "port"].forEach((k) => {
      if (it[k] != null) args[k] = it[k];
    });
    text.textContent = I18n.t("dg.detail_" + it.msg_key, args);
    row.append(dot, label, text);
    return row;
  }

  async function diagAction(action, report) {
    if (action === "internet_cleanup") {
      await bridge.windows_cleanup();
      toast(I18n.t("tl.cleanup_done"));
      runDiag();
    } else if (action === "flush_dns") {
      await bridge.flush_dns();
      toast(I18n.t("tl.flush_done"));
    } else if (action === "force_dns") {
      await bridge.force_dns();
      toast(I18n.t("tl.force_dns_done"));
    } else if (action === "open_profiles") {
      showPage("profiles");
    } else if (action === "start_dpi") {
      const res = await bridge.start_dpi("winws2", report.recommended_profile || "Default (circular) v2.txt");
      toast(res && res.ok ? I18n.t("pf.applied") : I18n.t("pf.err_start", { msg: ((res && res.detail) || (res && res.error)) || "" }), res && res.ok ? "" : "error");
      renderDpiEngine();
      renderProfiles();
    }
  }

  // ── BlockCheck («Проверка сайтов») ────────────────────────────────────
  const BC_VERDICT_KEYS = {
    clean: "bc.verdict_clean",
    signatures: "bc.verdict_signatures",
    partial: "bc.verdict_partial",
    no_internet: "bc.verdict_no_internet",
    unreliable: "bc.verdict_unreliable",
  };
  const BC_OUTCOME_KEYS = {
    ok: "bc.outcome_ok",
    blocked: "bc.outcome_blocked",
    inconclusive: "bc.outcome_inconclusive",
  };
  const BC_STATUS_KEYS = {
    ok: "bc.test_ok",
    fail: "bc.test_fail",
    timeout: "bc.test_timeout",
    unsupported: "bc.test_unsupported",
    error: "bc.test_error",
  };
  const BC_CLASS_KEYS = {
    dns_fake: "bc.cl_dns_fake",
    http_inject: "bc.cl_http_inject",
    isp_page: "bc.cl_isp_page",
    tls_dpi: "bc.cl_tls_dpi",
    tls_mitm: "bc.cl_tls_mitm",
    tcp_reset: "bc.cl_tcp_reset",
    tcp_16_20: "bc.cl_tcp_16_20",
    stun_block: "bc.cl_stun_block",
    full_block: "bc.cl_full_block",
  };
  const BC_OUTCOME_COLORS = { ok: "#3fb950", blocked: "#e25c5c", inconclusive: "#d4a72c" };

  async function renderBlockcheckPresets() {
    const st = await bridge.get_blockcheck_presets();
    if (!st) return;
    renderUserDomains(Array.isArray(st.user_domains) ? st.user_domains : []);
  }

  function renderUserDomains(domains) {
    const wrap = $("bcUserList");
    if (!wrap) return;
    wrap.innerHTML = "";
    if (!domains.length) {
      wrap.textContent = "—";
      return;
    }
    domains.forEach((d) => {
      const chip = document.createElement("span");
      chip.style.cssText = "display:inline-flex;align-items:center;gap:4px;background:rgba(127,127,127,.18);border-radius:999px;padding:2px 8px;font-size:12px;margin:2px";
      chip.textContent = d;
      const x = document.createElement("button");
      x.type = "button";
      x.textContent = "×";
      x.title = I18n.t("bc.stop");
      x.style.cssText = "border:none;background:none;cursor:pointer;color:inherit;font-size:13px;line-height:1;padding:0";
      x.addEventListener("click", async (e) => {
        e.stopPropagation();
        await bridge.remove_blockcheck_domain(d);
        renderBlockcheckPresets();
      });
      chip.appendChild(x);
      wrap.appendChild(chip);
    });
  }

  async function blockcheckAddDomain() {
    const input = $("bcDomain");
    const domain = input.value.trim();
    if (!domain) return;
    const res = await bridge.add_blockcheck_domain(domain);
    if (res && res.added) {
      input.value = "";
      renderBlockcheckPresets();
      toast(I18n.t("bc.added", { domain: domain }));
    } else {
      toast(I18n.t("bc.add_dup", { msg: (res && res.message) || "" }), "error");
    }
  }

  async function blockcheckRun() {
    const domain = $("bcDomain").value.trim();
    if (!domain) {
      $("bcStatus").style.display = "";
      $("bcStatus").textContent = I18n.t("bc.enter_domain");
      return;
    }
    const res = await bridge.start_blockcheck(domain);
    if (!res || !res.ok) {
      $("bcStatus").style.display = "";
      $("bcStatus").textContent = I18n.t("bc.start_failed", { msg: ((res && res.detail) || (res && res.error)) || "" });
      return;
    }
    $("bcCheckBtn").disabled = true;
    $("bcStopBtn").style.display = "";
    $("bcResult").style.display = "none";
    $("bcResult").innerHTML = "";
    $("bcStatus").style.display = "";
    $("bcStatus").textContent = I18n.t("bc.running", { domain: res.domain });
    if (state.blockcheckPoll) clearInterval(state.blockcheckPoll);
    state.blockcheckPoll = setInterval(pollBlockcheck, 1500);
  }

  async function blockcheckStop() {
    await bridge.stop_blockcheck();
    $("bcStatus").textContent = I18n.t("bc.stopping");
  }

  async function pollBlockcheck() {
    const st = await bridge.get_blockcheck_status();
    if (!st) return;
    if (st.status === "running" || st.status === "starting") {
      const lines = st.lines || [];
      const last = lines.length ? lines[lines.length - 1] : "";
      $("bcStatus").textContent = I18n.t("bc.running_short") + (last ? " — " + last : "");
      return;
    }
    if (state.blockcheckPoll) {
      clearInterval(state.blockcheckPoll);
      state.blockcheckPoll = null;
    }
    $("bcCheckBtn").disabled = false;
    $("bcStopBtn").style.display = "none";
    finishBlockcheckRun(st);
  }

  function finishBlockcheckRun(st) {
    const statusEl = $("bcStatus");
    statusEl.style.display = "";
    if (st.status === "error") {
      statusEl.className = "notice";
      statusEl.textContent = I18n.t("bc.error") + (st.message ? " — " + st.message : "");
      renderBlockcheckLog(st.lines || []);
      return;
    }
    if (st.status === "cancelled") {
      statusEl.className = "notice";
      statusEl.textContent = I18n.t("bc.cancelled");
      renderBlockcheckLog(st.lines || []);
      return;
    }
    statusEl.className = "notice";
    statusEl.textContent = I18n.t("bc.done");
    renderBlockcheckReport(st.report || null);
    renderBlockcheckLog(st.lines || []);
  }

  function blockcheckBadge(text, color) {
    const b = document.createElement("span");
    b.style.cssText =
      "display:inline-block;font-size:11px;font-weight:600;border-radius:4px;padding:2px 7px;margin-left:6px;color:#fff;background:" +
      color;
    b.textContent = text;
    return b;
  }

  function renderBlockcheckReport(report) {
    const box = $("bcResult");
    box.style.display = "";
    box.innerHTML = "";
    if (!report) return;

    const verdict = report.verdict || {};
    const title = document.createElement("div");
    title.className = "card-subtitle";
    title.textContent = I18n.t(BC_VERDICT_KEYS[verdict.code] || "bc.verdict_unreliable");
    if (verdict.headline && BC_CLASS_KEYS[verdict.headline]) {
      title.textContent += "  ·  " + I18n.t(BC_CLASS_KEYS[verdict.headline]);
    }
    box.appendChild(title);
    if (typeof verdict.detail === "string" && verdict.detail) {
      const d = document.createElement("div");
      d.className = "hint";
      d.textContent = verdict.detail;
      box.appendChild(d);
    }
    const summary = document.createElement("div");
    summary.className = "hint";
    summary.textContent = I18n.t("bc.summary", {
      valid: verdict.valid_targets,
      blocked: verdict.blocked_targets,
      inc: verdict.inconclusive_targets,
    });
    box.appendChild(summary);

    (report.targets || []).forEach((t) => {
      const row = document.createElement("div");
      row.style.cssText = "margin-top:10px;padding:8px 10px;border:1px solid rgba(127,127,127,.25);border-radius:8px";
      const head = document.createElement("div");
      head.style.cssText = "display:flex;align-items:center;flex-wrap:wrap;font-weight:600";
      head.textContent = t.name || "";
      const color = BC_OUTCOME_COLORS[t.outcome] || "#8b949e";
      head.appendChild(blockcheckBadge(I18n.t(BC_OUTCOME_KEYS[t.outcome] || "bc.outcome_inconclusive"), color));
      if (t.outcome === "blocked" && t.classification && BC_CLASS_KEYS[t.classification]) {
        head.appendChild(blockcheckBadge(I18n.t(BC_CLASS_KEYS[t.classification]), "#6e40c9"));
      }
      row.appendChild(head);
      if (t.classification_detail) {
        const d = document.createElement("div");
        d.className = "hint";
        d.textContent = t.classification_detail;
        row.appendChild(d);
      }
      const tests = document.createElement("div");
      tests.style.cssText = "margin-top:4px;font-size:12px;line-height:1.5";
      (t.tests || []).forEach((tt) => {
        const line = document.createElement("div");
        line.textContent =
          "• " + (tt.test_type || "") + " [" + I18n.t(BC_STATUS_KEYS[tt.status] || tt.status || "") + "]" +
          (tt.detail ? "  " + tt.detail : "");
        tests.appendChild(line);
      });
      row.appendChild(tests);
      box.appendChild(row);
    });
  }

  function renderBlockcheckLog(lines) {
    if (!Array.isArray(lines) || !lines.length) return;
    const box = $("bcResult");
    box.style.display = "";
    const pre = document.createElement("pre");
    pre.className = "mono-block";
    pre.style.cssText = "margin-top:10px;max-height:320px;overflow:auto";
    pre.textContent = lines.join("\n");
    box.appendChild(pre);
  }

  // ── Orchestra (авто-выбор стратегии) ─────────────────────────────────
  const OR_SYM_KEYS = {
    dns_poisoning: "or.sym_dns_poisoning",
    tls_reset: "or.sym_tls_reset",
    tls_mitm: "or.sym_tls_mitm",
    http_inject: "or.sym_http_inject",
    isp_page: "or.sym_isp_page",
    tcp_reset: "or.sym_tcp_reset",
    tcp_16_20: "or.sym_tcp_16_20",
    stun_block: "or.sym_stun_block",
    quic_drop: "or.sym_quic_drop",
    full_block: "or.sym_full_block",
    just_block: "or.sym_just_block",
  };

  function orStatus(text) {
    const el = $("orStatus");
    if (!el) return;
    el.style.display = "";
    el.className = "notice";
    el.textContent = text || "";
  }

  function orSymChip(key) {
    const chip = document.createElement("span");
    chip.style.cssText = "display:inline-block;font-size:11px;font-weight:600;border-radius:4px;padding:2px 7px;margin:2px 4px 2px 0;color:#fff;background:#6e40c9";
    chip.textContent = I18n.t(OR_SYM_KEYS[key] || key);
    chip.title = key;
    return chip;
  }

  async function orchestraRun() {
    const text = ($("orSymptoms").value || "").trim();
    $("orRunBtn").disabled = true;
    orStatus(I18n.t("bc.running_short"));
    $("orResult").innerHTML = "";
    try {
      const res = await bridge.orchestra_recommend(text);
      state.orCurrent = res && res.ok ? res.recommendations : null;
      renderOrchestra(res);
    } catch (e) {
      orStatus(String((e && e.message) || e));
    } finally {
      $("orRunBtn").disabled = false;
    }
  }

  function renderOrchestra(res) {
    if (!res || !res.ok || !Array.isArray(res.recommendations)) {
      orStatus(
        res && res.error
          ? I18n.t("or.err_apply", { msg: res.error })
          : I18n.t("or.no_data")
      );
      return;
    }
    const box = $("orResult");
    box.innerHTML = "";
    orStatus(res.source === "text" ? I18n.t("or.source_manual") : I18n.t("or.source_report"));

    if (!res.symptoms || !res.symptoms.length) {
      const hint = document.createElement("div");
      hint.className = "hint";
      hint.textContent = I18n.t("or.no_data");
      box.appendChild(hint);
      return;
    }

    const symTitle = document.createElement("div");
    symTitle.className = "card-subtitle";
    symTitle.textContent = I18n.t("or.symptoms_title");
    box.appendChild(symTitle);
    const symWrap = document.createElement("div");
    res.symptoms.forEach((s) => symWrap.appendChild(orSymChip(s.key)));
    box.appendChild(symWrap);

    const recTitle = document.createElement("div");
    recTitle.className = "card-subtitle";
    recTitle.textContent = I18n.t("or.recommendations_title");
    box.appendChild(recTitle);
    res.recommendations.forEach((r) => box.appendChild(orRecommendation(r)));
  }

  function orRecommendation(r, statusFn) {
    const row = document.createElement("div");
    row.style.cssText = "margin-top:8px;padding:8px 10px;border:1px solid rgba(127,127,127,.25);border-radius:8px";
    const head = document.createElement("div");
    head.style.cssText = "display:flex;align-items:center;flex-wrap:wrap;gap:8px;font-weight:600";
    const name = document.createElement("span");
    name.textContent = r.name || r.strategy;
    head.appendChild(name);
    head.appendChild(blockcheckBadge(I18n.t("or.probability", { p: r.probability }), "#3fb950"));
    const tag = document.createElement("span");
    tag.style.cssText = "display:inline-block;font-size:11px;font-weight:600;border-radius:4px;padding:2px 7px;color:#fff;background:#1f6feb";
    tag.textContent = r.label + " · " + r.category;
    head.appendChild(tag);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btn-ghost";
    btn.textContent = I18n.t("or.apply_btn");
    btn.addEventListener("click", () => orchestraApply(r.strategy, r.name || r.strategy, statusFn));
    head.appendChild(btn);
    row.appendChild(head);
    const matched = document.createElement("div");
    matched.style.cssText = "margin-top:6px";
    (r.matched_symptoms || []).forEach((m) => matched.appendChild(orSymChip(m.symptom)));
    row.appendChild(matched);
    if (r.description) {
      const d = document.createElement("div");
      d.className = "hint";
      d.style.cssText = "margin-top:4px";
      d.textContent = r.description;
      row.appendChild(d);
    }
    return row;
  }

  async function orchestraApply(strategyId, displayName, statusFn) {
    const report = statusFn || orStatus;
    const profile = await bridge.profile_list();
    const active = profile && profile.active ? profile.active : {};
    const activeName = active.group === "user" ? active.profile : "";
    if (!window.confirm(I18n.t("or.apply_confirm", { strategy: displayName, profile: activeName }))) {
      return;
    }
    report(I18n.t("bc.running_short"));
    try {
      const res = await bridge.apply_strategy(strategyId, activeName);
      if (!res || !res.ok) {
        const msg =
          res && res.error === "active_is_builtin"
            ? I18n.t("or.err_builtin")
            : I18n.t("or.err_apply", { msg: ((res && res.detail) || (res && res.error)) || I18n.t("or.err_unknown") });
        report(msg);
        return;
      }
      const diff = I18n.t("or.applied_diff", { added: res.n_added, removed: res.n_removed });
      let msg = I18n.t("or.applied", { strategy: displayName, profile: res.profile, diff: diff });
      if (res.backup) msg += " " + I18n.t("or.backup_note", { backup: res.backup });
      if (res.needs_restart_notice) msg += " " + I18n.t("or.restart_notice");
      report(msg);
    } catch (e) {
      report(String((e && e.message) || e));
    }
  }

  // ── Orchestra LEARNING (авто-закрепление стратегий) ─────────────────
  const OR_LEARNING_STATE_KEYS = {
    idle: "or.idle",
    learning: "or.learning",
    running: "or.running",
    unlocked: "or.unlocked",
  };

  async function renderOrchestraLearning() {
    const badge = $("orLearningBadge");
    const toggle = $("orAutoLearning");
    if (!badge || !toggle) return;
    const st = await bridge.get_orchestra_status();
    if (st) {
      const key = OR_LEARNING_STATE_KEYS[st.state] || "or.idle";
      badge.textContent = I18n.t(key);
      badge.className = "status-badge" + (st.state === "learning" ? " ok" : st.state === "running" ? " warn" : "");
      if (toggle.checked !== !!st.auto_learning) toggle.checked = !!st.auto_learning;
      if (st.message === "cleared") toast(I18n.t("or.cleared"));
    }
    const locked = await bridge.list_locked_strategies();
    const box = $("orLockedList");
    if (!box) return;
    box.innerHTML = "";
    if (!locked || !locked.ok || !locked.locked || !locked.locked.length) {
      const h = document.createElement("div");
      h.className = "hint";
      h.textContent = I18n.t("or.locked_empty");
      box.appendChild(h);
      return;
    }
    locked.locked.slice(0, 20).forEach((l) => {
      const row = document.createElement("div");
      row.className = "row";
      row.style.cssText = "gap:8px;padding:3px 0";
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = "strategy " + l.strategy;
      const host = document.createElement("span");
      host.className = "hint";
      host.textContent = l.host;
      const reason = document.createElement("span");
      reason.className = "hint";
      reason.textContent = l.reason || "auto";
      row.append(chip, host, reason);
      box.appendChild(row);
    });
  }

  async function toggleOrchestraLearning() {
    const on = $("orAutoLearning").checked;
    const res = on
      ? await bridge.start_orchestra_learning()
      : await bridge.stop_orchestra_learning();
    if (res && res.ok) {
      toast(on ? I18n.t("or.learning_on") : I18n.t("or.learning_off"));
    } else {
      $("orAutoLearning").checked = !on;
      toast(on ? I18n.t("or.err_apply", { msg: (res && res.error || "") }) : I18n.t("or.err_apply", { msg: ((res && res.detail) || (res && res.error)) || "" }), "error");
    }
    renderOrchestraLearning();
  }

  async function clearOrchestraLearning() {
    if (!confirm(I18n.t("or.clear_learning"))) return;
    const res = await bridge.clear_orchestra_learning();
    if (res && res.ok) {
      toast(I18n.t("or.cleared"));
      renderOrchestraLearning();
    } else {
      toast(I18n.t("toast.err", { msg: ((res && res.detail) || (res && res.error)) || "" }), "error");
    }
  }

  // ── Updates ────────────────────────────────────────────────────────────
  async function refreshUpdates(force) {
    const st = await bridge.get_update_status();
    if (!st) return;

    const ver = $("upVersion");
    if (ver) ver.textContent = st.current || "-";
    const eng = $("upEngine");
    if (eng) eng.textContent = st.engine_files_present ? I18n.t("up.engine_ok") : I18n.t("up.engine_missing");

    renderUpdateJob();
    renderReleases();
    renderReleaseHistory();
  }

  function renderCheckError(box, text) {
    box.replaceChildren();
    const pre = document.createElement("div");
    pre.className = "mono-block";
    pre.style.whiteSpace = "pre-wrap";
    pre.textContent = text;
    box.appendChild(pre);
    box.appendChild(Components.button(I18n.t("cmn.copy"), "btn-ghost btn-sm", "copy", () => copyText(text)));
    try { bridge.report_ui_error("updates", text); } catch (e) {}
  }

  async function runGithubCheck() {
    const btn = $("upCheckBtn");
    const box = $("upCheckResult");
    const pre = document.createElement("div");
    pre.className = "mono-block";
    pre.style.whiteSpace = "pre-wrap";
    pre.textContent = I18n.t("up.checking");
    box.replaceChildren(pre);
    if (btn) btn.disabled = true;
    let r;
    try {
      r = await bridge.check_updates(true);
    } catch (e) {
      r = null;
    }
    if (btn) btn.disabled = false;
    if (!r) {
      renderCheckError(box, I18n.t("up.check_failed"));
      return;
    }
    const lines = [];
    if (r.error) {
      renderCheckError(box, I18n.t("up.check_failed") + " " + r.error);
      return;
    } else if (r.has_update) {
      lines.push(I18n.t("up.available", { latest: r.latest || "?" }));
    } else if (r.ahead_of_release) {
      lines.push(I18n.t("up.ahead_of_release", { cur: r.current || "?", latest: r.latest || "-" }));
    } else if (r.checked) {
      lines.push(I18n.t("up.no_update"));
    } else {
      renderCheckError(box, I18n.t("up.check_failed"));
      return;
    }
    if (r.html_url) lines.push(r.html_url);
    pre.textContent = lines.join("\n");

    const actions = $("upCheckActions");
    if (actions) {
      actions.innerHTML = "";
      if (r && r.has_update) {
        actions.appendChild(Components.button(I18n.t("up.install_latest"), "btn btn-sm", "download", async () => {
          const res = await bridge.download_update();
          if (!(res && res.ok)) {
            toast(I18n.t("toast.failed") + ((res && res.detail) ? " " + res.detail : ""), "error");
            return;
          }
          toast(I18n.t("up.checking"));
          if (state.updatePoll) clearInterval(state.updatePoll);
          state.updatePoll = setInterval(pollUpdateJob, 700);
          renderUpdateJob();
        }));
      }
    }
    box.replaceChildren(pre);
  }

  async function runFingerprint() {
    const btn = $("upIntegrityBtn");
    const box = $("upFpResult");
    const pre = document.createElement("pre");
    pre.className = "mono-block";
    pre.style.whiteSpace = "pre-wrap";
    pre.textContent = I18n.t("up.checking");
    box.replaceChildren(pre);
    if (btn) btn.disabled = true;
    const r = await bridge.engine_fingerprint(true);
    if (!r) {
      pre.textContent = I18n.t("toast.failed");
      if (btn) btn.disabled = false;
      return;
    }
    renderFingerprint(r);
  }

  function fingerprintStatusLabel(f) {
      if (f.status === "tampered") return I18n.t("up.fp_tampered", { f: f.name });
      if (f.status === "missing") return I18n.t("up.fp_missing", { f: f.name });
      return I18n.t("up.fp_added", { f: f.name });
    }

    function renderFingerprint(r) {
    const box = $("upFpResult");
    const actions = $("upFpActions");
    actions.innerHTML = "";
    if (box) box.innerHTML = "";
    const pre = document.createElement("pre");
    pre.className = "mono-block";
    pre.style.whiteSpace = "pre-wrap";
    const lines = [];
    if (r.created) {
      lines.push(I18n.t("up.fp_baseline"));
    } else if (r.reason === "no_baseline") {
      lines.push(I18n.t("up.fp_none"));
    } else if (r.ok) {
      lines.push(I18n.t("up.fp_ok"));
    } else {
      lines.push(I18n.t("up.fp_bad", { n: r.changed_files ? r.changed_files.length : 0 }));
      (r.changed_files || []).forEach((f) => lines.push("  " + fingerprintStatusLabel(f)));
    }
    pre.textContent = lines.join("\n");
    box.appendChild(pre);
    if (r.ok === true || r.ok === false) {
      const h = document.createElement("div");
      h.className = "hint";
      h.textContent = I18n.t("up.fp_hint_accept");
      box.appendChild(h);
      actions.appendChild(Components.button(I18n.t("up.accept_baseline"), "btn-ghost btn-sm", "shield", async () => {
        await bridge.reset_engine_baseline();
        const next = await bridge.engine_fingerprint(true);
        toast(next && next.created ? I18n.t("up.baseline_saved") : I18n.t("toast.failed"));
        renderFingerprint(next);
      }));
    }
    const btn = $("upIntegrityBtn");
    if (btn) btn.disabled = false;
  }

  function releaseDate(d) {
    return (d || "").replace("T", " ").replace("Z", "").slice(0, 16);
  }

  async function startReleaseDownload(tag) {
    const r = await bridge.rollback_to(tag);
    if (!(r && r.ok)) {
      toast(I18n.t("toast.failed"));
      return;
    }
    toast(tag + " …");
    if (state.updatePoll) clearInterval(state.updatePoll);
    state.updatePoll = setInterval(pollUpdateJob, 700);
    renderUpdateJob();
  }

  async function pollUpdateJob() {
    const j = await bridge.get_update_job();
    renderUpdateJob(j);
    if (j && (j.state === "done" || j.state === "error")) {
      if (state.updatePoll) clearInterval(state.updatePoll);
      state.updatePoll = null;
    }
  }

  async function renderUpdateJob(j) {
    const job = j || await bridge.get_update_job();
    const box = $("upDownloadBox");
    const actions = $("upDownloadActions");
    if (!box) return;
    if (!job || job.state === "idle" || job.state === "check") {
      box.style.display = "none";
      if (actions) actions.innerHTML = "";
      return;
    }
    box.style.display = "";
    const fill = $("upProgressFill");
    const text = $("upProgressText");
    const percent = job.percent != null ? job.percent : (typeof job.progress === "number" ? job.progress : 0);
    fill.style.width = Math.max(0, Math.min(100, percent)) + "%";
    if (job.state === "downloading") {
      text.textContent = I18n.t("up.download_progress", { p: Math.round(percent) });
      if (actions) actions.innerHTML = "";
    } else if (job.state === "done") {
      fill.style.width = "100%";
      text.textContent = I18n.t("up.download_done");
      if (actions) {
        actions.innerHTML = "";
        actions.appendChild(Components.button(I18n.t("up.open_downloads"), "btn-ghost btn-sm", "folder", () => bridge.open_downloads_dir()));
        try {
          const pending = await bridge.restart_pending();
          if (pending) {
            actions.appendChild(Components.button(I18n.t("up.release_restart"), "btn btn-sm", "refresh", () => bridge.restart_app()));
          }
        } catch (e) { /* ignore */ }
      }
    } else if (job.state === "error") {
      text.textContent = I18n.t("up.download_failed", { msg: job.message || job.state });
      if (actions) actions.innerHTML = "";
    } else {
      text.textContent = job.message || job.state;
      if (actions) actions.innerHTML = "";
    }
  }

  async function renderReleases() {
    const box = $("upReleasesBox");
    if (!box || box.dataset.loaded === "1") return;
    box.dataset.loaded = "1";
    const versions = await bridge.list_available_versions(12) || [];
    if (!versions.length) {
      const h = document.createElement("div");
      h.className = "hint";
      h.textContent = I18n.t("up.versions_fail");
      box.appendChild(h);
      return;
    }
    versions.forEach((v, i) => {
      const row = document.createElement("div");
      row.className = "up-release-row";
      const main = document.createElement("div");
      main.className = "up-release-main";
      const t = document.createElement("div");
      t.className = "up-release-title";
      t.textContent = v.tag + (v.prerelease ? " (pre)" : "") + (i === 0 ? " · " + I18n.t("up.release_update") : "");
      const d = document.createElement("div");
      d.className = "up-release-meta";
      d.textContent = releaseDate(v.published_at) + " · " + (v.name || "").slice(0, 80);
      main.append(t, d);
      const btn = document.createElement("button");
      btn.className = "up-release-tag";
      btn.type = "button";
      btn.textContent = I18n.t("up.release_install");
      btn.addEventListener("click", () => startReleaseDownload(v.tag));
      row.append(main, btn);
      box.appendChild(row);
    });
  }

  async function renderReleaseHistory() {
    const box = $("releaseHistory");
    if (!box || box.dataset.loaded === "1") return;
    box.dataset.loaded = "1";
    const versions = await bridge.list_available_versions(10) || [];
    const older = versions.slice(1);
    if (!older.length) {
      const h = document.createElement("div");
      h.className = "hint";
      h.textContent = I18n.t("up.versions_fail");
      box.appendChild(h);
      return;
    }
    older.forEach((v) => {
      const row = document.createElement("div");
      row.className = "up-release-row";
      const main = document.createElement("div");
      main.className = "up-release-main";
      const t = document.createElement("div");
      t.textContent = v.tag + (v.prerelease ? " (pre)" : "");
      const d = document.createElement("div");
      d.className = "up-release-meta";
      d.textContent = releaseDate(v.published_at);
      main.append(t, d);
      const btn = Components.button(I18n.t("up.rollback_to"), "btn-ghost btn-sm", "download", () => startReleaseDownload(v.tag));
      row.append(main, btn);
      box.appendChild(row);
    });
  }

  // ── Help ───────────────────────────────────────────────────────────────
  async function renderHelp() {
    const box = $("helpBody");
    if (!box) return;
    box.innerHTML = "";
    const keys = ["what", "mt", "tg", "dns", "hosts", "presets", "updates", "cli", "share", "settings", "logs", "security", "router", "server", "docker"];
    for (const k of keys) {
      const item = document.createElement("div");
      item.className = "help-item";
      const h = document.createElement("div");
      h.className = "preset-title";
      h.textContent = I18n.t(`hp.${k}_title`);
      const p = document.createElement("div");
      p.className = "hint";
      p.textContent = I18n.t(`hp.${k}_text`);
      item.append(h, p);

      const moreText = I18n.t(`hp.${k}_more`);
      if (moreText && moreText !== `hp.${k}_more`) {
        const det = document.createElement("details");
        det.className = "help-more";
        const sum = document.createElement("summary");
        sum.textContent = I18n.t("hp.more_btn");
        const body = document.createElement("div");
        body.className = "hint help-more-body";
        moreText.split("\n").forEach((line) => {
          const row = document.createElement("div");
          row.textContent = line.trim() || "\u200b";
          body.appendChild(row);
        });
        det.append(sum, body);
        item.appendChild(det);
      }

      box.appendChild(item);
    }
  }

  // ── Logs ───────────────────────────────────────────────────────────────
  let logTimer = null;
  function logBottomState() {
    const view = $("logView");
    if (!view) return;
    const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    const btn = $("logBottomBtn");
    if (btn) btn.classList.toggle("show", !atBottom);
  }
  async function loadLogs() {
    const view = $("logView");
    if (!view) return;
    const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    const tail = await bridge.get_log_tail(400);
    view.textContent = tail && tail.trim() ? tail : I18n.t("lg.empty");
    if (atBottom) view.scrollTop = view.scrollHeight;
    logBottomState();
  }

  function logAutoTicks() {
    if (logTimer) clearInterval(logTimer);
    logTimer = null;
    if (!$("logAuto").checked) return;
    logTimer = setInterval(() => {
      const active = $$(".page.active")[0];
      if (active && active.dataset.pageView === "logs") {
        if (logSeg === "all") loadLogs();
        else renderLogSeg();
      }
    }, 3000);
  }

  // ── Logs: сегменты по статусам ─────────────────────────────────────────
  let logSeg = "all";

  async function renderLogSeg() {
    const box = $("logStatusBox");
    if (!box) return;
    const isRaw = logSeg === "all";
    $("logWrap").style.display = isRaw ? "" : "none";
    box.style.display = isRaw ? "none" : "";
    $$("#logSeg button").forEach((b) => b.classList.toggle("active", b.dataset.val === logSeg));
    if (isRaw) {
      loadLogs();
      return;
    }
    box.innerHTML = '<div class="hint">' + I18n.t("wl.loading") + "</div>";
    if (logSeg === "autopilot") {
      const j = await bridge.auto_journal(400);
      const lines = (j && j.ok && j.lines) || [];
      box.innerHTML = "";
      const pre = document.createElement("pre");
      pre.className = "log-view";
      pre.style.cssText = "max-height:460px;overflow:auto";
      pre.textContent = lines.length ? lines.map((e) => e.ts + "  " + e.text).join("\n") : I18n.t("au.journal_empty");
      box.appendChild(pre);
      return;
    }
    const st = await bridge.get_winws_log_status();
    if (!st || st.ok === false || !st.has_log) {
      box.innerHTML = '<div class="hint">' + I18n.t("wl.no_log") + "</div>";
      return;
    }
    const html = [];
    if (logSeg === "sessions") {
      const list = st.sessions || [];
      if (!list.length) {
        box.innerHTML = '<div class="hint">' + I18n.t("lg.none_sessions") + "</div>";
        return;
      }
      const counts = [];
      if (st.ok_count) counts.push(I18n.t("lg.ok_count", { n: st.ok_count }));
      if (st.fail_count) counts.push(I18n.t("lg.fail_count", { n: st.fail_count }));
      if (st.warn_count) counts.push(I18n.t("lg.warn_count", { n: st.warn_count }));
      if (counts.length) html.push('<div class="hint" style="padding-bottom:6px">' + counts.join(" · ") + "</div>");
      list.slice().reverse().forEach((s) => {
        const ok = !!s.ok;
        const cls = ok ? "ok" : s.exit_code === 0 ? "warn" : "off";
        html.push('<div style="padding:8px 0;border-bottom:1px solid rgba(127,127,127,.15)">');
        html.push('<div class="row" style="gap:8px;flex-wrap:wrap">');
        html.push('<span class="status-badge ' + cls + '">' + (ok ? I18n.t("wl.status_ok") : I18n.t("wl.status_error")) + "</span>");
        if (s.mode) html.push('<span class="hint">' + escapeHTML(s.mode) + "</span>");
        if (s.pid) html.push('<span class="hint">PID ' + s.pid + "</span>");
        if (s.exit_code != null) html.push('<span class="hint">exit ' + s.exit_code + "</span>");
        html.push("</div>");
        if (s.started_at) {
          let l = escapeHTML(s.started_at);
          if (s.lifetime_seconds != null) l += " · " + Math.round(s.lifetime_seconds) + " s";
          html.push('<div class="hint">' + l + "</div>");
        }
        html.push("</div>");
      });
    } else if (logSeg === "errors") {
      const list = st.errors || [];
      if (!list.length) {
        box.innerHTML = '<div class="hint">' + I18n.t("lg.none_errors") + "</div>";
        return;
      }
      html.push("<pre class=\"log-view\" style=\"max-height:460px;overflow:auto\">" + list.map(escapeHTML).join("\n") + "</pre>");
    } else {
      const list = st.warnings || [];
      if (!list.length) {
        box.innerHTML = '<div class="hint">' + I18n.t("lg.none_warnings") + "</div>";
        return;
      }
      html.push("<pre class=\"log-view\" style=\"max-height:460px;overflow:auto\">" + list.map(escapeHTML).join("\n") + "</pre>");
    }
    box.innerHTML = html.join("");
  }

  // ── Settings ───────────────────────────────────────────────────────────
  // All writes happen on change (auto-save).
  function wireSettings() {
    $$("#nav a").forEach((a) => {
      a.addEventListener("click", () => showPage(a.dataset.page));
    });
    on("mtHost", "input", () => debouncedSave("proxy", "host", () => $("mtHost").value.trim()));
    on("mtPort", "input", () => debouncedSave("proxy", "port", () => parseInt($("mtPort").value, 10) || 1443));
    on("mtSecret", "input", () => debouncedSave("proxy", "secret", () => $("mtSecret").value.trim()));
    on("mtSecretGen", "click", () => {
      const b = new Uint8Array(16);
      crypto.getRandomValues(b);
      const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
      $("mtSecret").value = hex;
      debouncedSave("proxy", "secret", () => hex);
    });
    on("pfSearch", "input", () => renderProfiles());
    on("pfCopy", "click", () => {
      const pre = $("pfDetailPre");
      if (!pre || !pre.textContent) return;
      navigator.clipboard.writeText(pre.textContent);
      const btn = $("pfCopy");
      const old = btn.textContent;
      btn.textContent = I18n.t("pf.copied");
      setTimeout(() => { btn.textContent = old; }, 1200);
    });
    on("pfApplyBtn", "click", applyOpenProfile);
    on("pfEditBtn", "click", editOpenProfile);
    on("pfListEditBtn", "click", editOpenProfile);
    on("pfListRefreshBtn", "click", renderProfiles);
    on("pfSaveBtn", "click", async () => {
      const name = $("pfEditorName").value.trim();
      syncDrawerItems();
      const text = pfSerialize((state.pfDrawer && state.pfDrawer.items) || []);
      if (!name) {
        toast(I18n.t("pr.name_invalid"), "error");
        return;
      }
      const isRec = isRecommendedName(name);
      if (isRec || state.dpiRunning) {
        const msg = isRec ? I18n.t("pr.confirm_save_rec") : I18n.t("pr.confirm_save_active");
        if (!confirm(msg)) return;
      }
      const res = await bridge.profile_write(name, text);
      if (!res || res.ok === false) {
        toast(I18n.t("pr.err_save", { msg: profileErrorMsg(res && res.error) }), "error");
        return;
      }
      renderVerdict(res.validation);
      if (res.validation && res.validation.ok) {
        toast(I18n.t("pr.saved"));
        closeProfileDrawer();
        state.pfOpen = null;
        renderProfiles();
      } else {
        toast(I18n.t("pr.saved_errors"), "error");
      }
    });
    on("pfValidateBtn", "click", async () => {
      syncDrawerItems();
      const text = pfSerialize((state.pfDrawer && state.pfDrawer.items) || []);
      const res = await bridge.profile_validate_paste(text);
      renderVerdict(res);
    });
    on("pfResetBtn", "click", async () => {
      const name = $("pfEditorName").value.trim();
      if (!confirm(I18n.t("pr.confirm_reset"))) return;
      const res = await bridge.profile_reset(name);
      if (res && res.ok) {
        state.pfDrawer.items = pfParseLines(res.content || "");
        renderDrawer();
        renderVerdict(res.validation);
        toast(I18n.t("pr.reset_done"));
      } else {
        toast(I18n.t("pr.err_reset", { msg: profileErrorMsg(res && res.error) }), "error");
      }
    });
    on("pfDeleteBtn", "click", async () => {
      const name = $("pfEditorName").value.trim();
      if (!name) return;
      if (!confirm(I18n.t("pr.confirm_delete"))) return;
      const res = await bridge.profile_delete(name);
      if (res && res.ok) {
        toast(I18n.t("pr.deleted"));
        closeProfileDrawer();
        state.pfOpen = null;
        renderProfiles();
      } else {
        toast(I18n.t("pr.err_delete", { msg: profileErrorMsg(res && res.error) }), "error");
      }
    });
    on("pfEditorCancelBtn", "click", closeProfileDrawer);
    on("pfDrawerCloseBtn", "click", closeProfileDrawer);
    on("pfDrawerBackdrop", "click", (e) => { if (e.target === $("pfDrawerBackdrop")) closeProfileDrawer(); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && $("pfDrawer").classList.contains("open")) closeProfileDrawer();
    });
    on("pfAddParamBtn", "click", () => {
      $("pfAddParamRow").style.display = "flex";
      $("pfAddParamValue").focus();
    });
    on("pfAddParamCancelBtn", "click", () => { $("pfAddParamRow").style.display = "none"; });
    on("pfAddParamOkBtn", "click", () => {
      if (!state.pfDrawer) return;
      const key = $("pfAddParamKey").value;
      const value = $("pfAddParamValue").value.trim();
      state.pfDrawer.items.push({ type: "param", key: "--" + key, paramKey: key, value: value, base: value, auto: false, strategy: "" });
      renderDrawer();
    });
    on("dpiStartBtn", "click", async () => {
      const res = await bridge.start_dpi();
      if (res && res.ok) {
        toast(I18n.t("pf.applied"));
      } else {
        toast(I18n.t("pf.err_start", { msg: ((res && res.detail) || (res && res.error)) || I18n.t("pf.not_found") }), "error");
      }
      renderDpiEngine();
      renderProfiles();
    });
    on("dpiStopBtn", "click", async () => {
      await bridge.stop_dpi();
      toast(I18n.t("pf.stopped"));
      renderDpiEngine();
      renderProfiles();
    });
    on("dpiRestartBtn", "click", async () => {
      const res = await bridge.restart_dpi();
      if (!(res && res.ok)) {
        toast(I18n.t("pf.err_start", { msg: ((res && res.detail) || (res && res.error)) || "" }), "error");
      }
      renderDpiEngine();
      renderProfiles();
    });
    on("dpiModeSeg", "click", async (e) => {
      const btn = e.target.closest("button[data-val]");
      if (!btn) return;
      const mode = btn.dataset.val;
      await bridge.set_zapret_settings({ mode: mode });
      $$("#dpiModeSeg button").forEach((b) => b.classList.toggle("active", b.dataset.val === mode));
    });
    on("dpiAutostartChk", "change", async () => {
      await bridge.set_zapret_settings({ autostart: $("dpiAutostartChk").checked });
      toast($("dpiAutostartChk").checked ? I18n.t("pf.autostart_on") : I18n.t("pf.autostart_off"));
    });
    on("dpiLogRefreshBtn", "click", loadWinwsLog);
    on("runDiagBtn", "click", runDiag);
    on("bcCheckBtn", "click", blockcheckRun);
    on("bcAddBtn", "click", blockcheckAddDomain);
    on("bcStopBtn", "click", blockcheckStop);
    const bcInput = $("bcDomain");
    if (bcInput) bcInput.addEventListener("keydown", (e) => { if (e.key === "Enter") blockcheckRun(); });
    on("orRunBtn", "click", orchestraRun);
    const orInput = $("orSymptoms");
    if (orInput) orInput.addEventListener("keydown", (e) => { if (e.key === "Enter") orchestraRun(); });
    on("orAutoLearning", "change", toggleOrchestraLearning);
    on("orLearningRefreshBtn", "click", renderOrchestraLearning);
    on("orClearLearningBtn", "click", clearOrchestraLearning);
    on("winCleanupBtn", "click", async () => {
      $("winToolsResult").textContent = I18n.t("tl.running");
      const res = await bridge.windows_cleanup();
      $("winToolsResult").textContent = res && res.ok
        ? I18n.t("tl.cleanup_done")
        : I18n.t("tl.cleanup_failed", { msg: (res.failed || []).join("; ") || "" });
    });
    on("winFlushBtn", "click", async () => {
      const r = await bridge.flush_dns();
      $("winToolsResult").textContent = r || I18n.t("tl.flush_done");
    });
    on("winDefenderBtn", "click", async () => {
      $("winToolsResult").textContent = I18n.t("tl.running");
      const res = await bridge.defender_exclude();
      $("winToolsResult").textContent = res && res.ok
        ? I18n.t("tl.defender_done")
        : I18n.t("tl.defender_failed", { msg: ((res && res.detail) || (res && res.error)) || "" });
      renderTools();
    });
    on("whDiagBtn", "click", whDiag);
    on("whCleanupBtn", "click", () => whCleanup("standard"));
    on("whCleanupAggBtn", "click", () => whCleanup("aggressive"));
    on("whKillBtn", "click", whKillConflicts);
    on("whLogBtn", "click", whLog);
    on("wlStatusBtn", "click", wlStatus);
    on("wlShowBtn", "click", wlShow);
    on("mtPool", "input", () => debouncedSave("proxy", "pool_size", () => parseInt($("mtPool").value, 10) || 4));
    on("mtEnable", "change", async () => {
      await save("app", "run_proxy_on_startup", $("mtEnable").checked);
      await toggleProxyFromToggle();
    });
    on("proxyMode", "click", async (e) => {
      if (e.target.tagName !== "BUTTON") return;
      applyProxyMode(e.target.dataset.val);
      await save("app", "proxy_mode", e.target.dataset.val);
    });
    on("shareLan", "change", async () => setShare($("shareLan").checked));
    on("shareInternet", "change", async () => {
      const on = $("shareInternet").checked;
      await save("app", "share_public", on);
      await shareInternetApply(on);
    });
    on("copyShareMt", "click", async () => {
      const ok = await bridge.copy_text($("shareLinkMt").value || "");
      toast(ok ? I18n.t("toast.copied") : I18n.t("toast.failed"), ok ? "" : "error");
    });
    on("copyShareSocks", "click", async () => {
      const ok = await bridge.copy_text($("shareLinkSocks").value || "");
      toast(ok ? I18n.t("toast.copied") : I18n.t("toast.failed"), ok ? "" : "error");
    });
    on("connectShareMt", "click", async () => {
      const ok = await bridge.open_link($("shareLinkMt").value || "");
      if (!ok) toast(I18n.t("toast.failed"), "error");
    });
    on("connectShareSocks", "click", async () => {
      const v = ($("shareLinkSocks").value || "").split(":");
      const ok = await bridge.open_link(buildSocksLink(v[0] || "", v[1] || "1353"));
      if (!ok) toast(I18n.t("toast.failed"), "error");
    });
    on("connectPub", "click", async () => {
      const ok = await bridge.open_link($("pubLink").value || "");
      if (!ok) toast(I18n.t("toast.failed"), "error");
    });
    on("copyPub", "click", async () => {
      const ok = await bridge.copy_text($("pubLink").value || "");
      toast(ok ? I18n.t("toast.copied") : I18n.t("toast.failed"), ok ? "" : "error");
    });

    on("logRefreshBtn", "click", renderLogSeg);
    on("logOpenBtn", "click", () => bridge.open_logs_dir());
    on("logAuto", "change", logAutoTicks);
    on("logSeg", "click", (e) => {
      const b = e.target.closest("button");
      if (!b || !b.dataset.val) return;
      logSeg = b.dataset.val;
      renderLogSeg();
    });
    on("autoStartBtn", "click", async () => {
      const res = await bridge.auto_start();
      if (!res || !res.ok) {
        toast(I18n.t("au.err_start", { msg: ((res && res.detail) || (res && res.error)) || "" }), "error");
      }
      await renderAutopilot();
    });
    on("autoStopBtn", "click", async () => {
      const res = await bridge.auto_stop();
      if (res && res.ok) toast(I18n.t("au.stopped"));
      await renderAutopilot();
      renderDpiEngine();
      refreshDashDpi();
    });
    on("autoResetBtn", "click", async () => {
      await bridge.auto_reset();
      await renderAutopilot();
    });
    on("pfCreateBtn", "click", showPfCreate);
    on("pfCreateCancelBtn", "click", () => { $("pfCreateRow").style.display = "none"; });
    on("pfCreateOkBtn", "click", pfCreateOk);
    on("pfOrRunBtn", "click", pfOrRun);
    on("logBottomBtn", "click", () => { const v=$("logView"); if(v) v.scrollTop=v.scrollHeight; logBottomState(); });
    on("logView", "scroll", logBottomState);

    on("tgHost", "input", () => debouncedSave("telegram", "bind_host", () => $("tgHost").value.trim()));
    on("tgPort", "input", () => debouncedSave("telegram", "port", () => parseInt($("tgPort").value, 10) || 1353));

    on("themeMode", "click", async (e) => {
      if (e.target.tagName !== "BUTTON") return;
      syncTheme(e.target.dataset.val);
      await save("appearance", "mode", e.target.dataset.val);
      setAppearance("mode", e.target.dataset.val);
      applyThemeUI();
    });

    on("langBtn", "click", () => {
      const m = $("langMenu");
      if (m) m.style.display = m.style.display === "none" ? "" : "none";
    });
    document.addEventListener("click", (e) => {
      if (!e.target.closest || !e.target.closest("#langSelectBox")) {
        const m = $("langMenu");
        if (m) m.style.display = "none";
      }
    });
    $$("#langMenu .lang-option").forEach((o) => o.addEventListener("click", async () => {
      $("langMenu").style.display = "none";
      $("langValue").value = o.dataset.val;
      await changeLang(o.dataset.val);
    }));

    on("setTrayMin", "change", () => save("app", "minimize_to_tray", $("setTrayMin").checked));
    on("setStartMin", "change", () => save("app", "start_minimized", $("setStartMin").checked));

    on("experimentalToggle", "change", async () => {
      await save("app", "experimental", $("experimentalToggle").checked);
      if (state.settings && state.settings.app) state.settings.app.experimental = $("experimentalToggle").checked;
      await applyProxyMode(state.proxyMode);
    });
    on("sysProxyToggle", "change", async () => {
      const on = $("sysProxyToggle").checked;
      const r = await bridge.set_system_proxy(on);
      if (r && r.ok) {
        await save("app", "system_proxy", on);
      } else {
        $("sysProxyToggle").checked = !on;
        toast((r && r.detail) || I18n.t("st.sys_proxy_unsupported"), "error");
      }
    });

    // Autostart
    on("asScope", "click", (e) => {
      if (e.target.tagName !== "BUTTON") return;
      state.asScope = e.target.dataset.val;
      renderAutostart();
    });
    on("asList", "click", async (e) => {
      const btn = e.target.closest("[data-act]");
      if (!btn) return;
      const method = btn.dataset.provider;
      const scope = state.asScope || "app";
      if (btn.dataset.act === "install") {
        const r = await bridge.autostart_install(method, scope);
        toast(r && r.ok ? I18n.t("as.toast_install_ok") : I18n.t("as.toast_install_err", { msg: (r && r.detail) || (r && r.error) || "" }), r && r.ok ? "" : "error");
      } else {
        const r = await bridge.autostart_remove(method, scope);
        toast(r && r.ok ? I18n.t("as.toast_remove_ok") : I18n.t("as.toast_remove_err", { msg: (r && r.detail) || (r && r.error) || "" }), r && r.ok ? "" : "error");
      }
      renderAutostart();
    });
    on("asStartService", "click", async () => {
      const r = await bridge.autostart_start_service(state.asScope || "app");
      toast(r && r.ok ? I18n.t("as.toast_start_ok") : I18n.t("as.toast_start_err", { msg: (r && r.detail) || (r && r.error) || "" }), r && r.ok ? "" : "error");
      renderAutostart();
    });
    on("asStopService", "click", async () => {
      const r = await bridge.autostart_stop_service(state.asScope || "app");
      toast(r && r.ok ? I18n.t("as.toast_stop_ok") : I18n.t("as.toast_stop_err", { msg: (r && r.detail) || (r && r.error) || "" }), r && r.ok ? "" : "error");
      renderAutostart();
    });

    // Dashboard
    on("copyLink", "click", async () => {
      const ok = await bridge.copy_proxy_link();
      toast(ok ? I18n.t("toast.copied") : I18n.t("toast.failed"), ok ? "" : "error");
    });
    on("dashConnect", "click", async () => {
      if (state.proxyMode === "socks5") {
        const ok = await bridge.copy_text($("proxyLink").value || "");
        toast(ok ? I18n.t("toast.copied") : I18n.t("toast.failed"), ok ? "" : "error");
        return;
      }
      await bridge.open_proxy_link();
    });
    on("restartFromMt", "click", async () => { await restartProxy(); });
    on("dashMtToggle", "change", toggleDashMt);
    on("dashSocksToggle", "change", toggleDashSocks);
    on("dashDpiToggle", "change", toggleDashDpi);
    on("dashStrategyBtn", "click", () => showPage("profiles"));

    // Telegram
    on("startTgBtn", "click", async () => {
      const r = await bridge.start_tg_proxy();
      toast(r && r.ok ? I18n.t("toast.applied") : I18n.t("toast.err", { msg: (r && r.detail) || "" }));
      await refreshStatus();
    });

    // DNS
    on("dnsCheckBtn", "click", runDnsCheck);
    on("dnsFlushBtn", "click", async () => {
      const r = await bridge.flush_dns();
      $("dnsResult").textContent = r || "";
    });
    on("dnsForceBtn", "click", runDnsForce);
    on("dnsRestoreBtn", "click", runDnsRestore);
    on("dnsAdaptersBtn", "click", renderDnsAdapters);
    on("dnsQuickBtn", "click", runQuickDnsCheck);
    on("dnsPoisonBtn", "click", runDnsPoisoning);
    on("dnsPoisonStopBtn", "click", stopDnsPoisoning);

    // Hosts
    on("applyHostsBtn", "click", applyHosts);
    on("clearHostsBtn", "click", clearHosts);
    $$("[data-href-page]").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.hrefPage)));

    // Updates
    on("upCheckBtn", "click", runGithubCheck);
    on("upIntegrityBtn", "click", runFingerprint);

    // Titlebar
    on("tbMin", "click", () => bridge.window_minimize());
    on("tbMax", "click", () => bridge.window_toggle_maximize());
    on("tbFull", "click", () => bridge.window_toggle_fullscreen());
    on("tbClose", "click", () => bridge.window_close());
    on("collapseBtn", "click", toggleCollapse);
  }

  async function toggleDashMt() {
    const run = $("dashMtToggle").checked;
    const st = await bridge.get_proxy_status();
    if (run && !(st && st.running)) await bridge.start_proxy();
    else if (!run && st && st.running) await bridge.stop_proxy();
    await refreshStatus();
  }

  async function toggleDashSocks() {
    const run = $("dashSocksToggle").checked;
    const st = await bridge.get_tg_proxy_status();
    if (run && !(st && st.running)) await bridge.start_tg_proxy();
    else if (!run && st && st.running) await bridge.stop_tg_proxy();
    await refreshStatus();
  }

  async function toggleDashDpi() {
    const run = $("dashDpiToggle").checked;
    const st = await bridge.get_dpi_status();
    const running = st && (st.state === "running" || st.state === "starting");
    if (run && !running) {
      const res = await bridge.start_dpi();
      if (!(res && res.ok)) {
        toast(I18n.t("pf.err_start", { msg: ((res && res.detail) || (res && res.error)) || I18n.t("pf.not_found") }), "error");
      }
    } else if (!run && running) {
      await bridge.stop_dpi();
      toast(I18n.t("pf.stopped"));
    }
    await refreshDashDpi();
    renderDpiEngine();
    renderProfiles();
  }

  async function toggleProxyFromButton() {
    const st = await bridge.get_proxy_status();
    if (st && st.running) await bridge.stop_proxy();
    else await bridge.start_proxy();
    await refreshStatus();
  }

  async function toggleProxyFromToggle() {
    const run = $("mtEnable").checked;
    const st = await bridge.get_proxy_status();
    if (run && !(st && st.running)) await bridge.start_proxy();
    else if (!run && st && st.running) await bridge.stop_proxy();
    await refreshStatus();
  }

  async function restartProxy() {
    await bridge.stop_proxy();
    await delay(600);
    await bridge.start_proxy();
    await refreshStatus();
  }

  function applyProxyMode(mode) {
    state.proxyMode = mode === "socks5" ? "socks5" : "mt";
    const exp = !!(state.settings && state.settings.app && state.settings.app.experimental);
    $("mtCard").style.display = exp || mode !== "socks5" ? "" : "none";
    $("socksCard").style.display = exp || mode === "socks5" ? "" : "none";
    $$("#proxyMode button").forEach((b) => b.classList.toggle("active", b.dataset.val === mode));
    const seg = $("proxyMode");
    if (seg) seg.style.display = exp ? "none" : "";
  }

  async function restartActiveProxy() {
    if (state.proxyMode === "socks5") {
      const st = await bridge.get_tg_proxy_status();
      if (st && st.running) {
        await bridge.stop_tg_proxy();
        await delay(600);
        await bridge.start_tg_proxy();
      }
    } else {
      const st = await bridge.get_proxy_status();
      if (st && st.running) {
        await bridge.stop_proxy();
        await delay(600);
        await bridge.start_proxy();
      }
    }
  }

  function sharePort() {
    const cfg = state.settings || {};
    if (state.proxyMode === "socks5") {
      return (cfg.telegram && cfg.telegram.port) || 1353;
    }
    return (cfg.proxy && cfg.proxy.port) || 1443;
  }

  async function refreshShare() {
    const box = $("shareBox");
    if (!box) return;
    const cfg = (state.settings && state.settings.proxy) || {};
    const tg = (state.settings && state.settings.telegram) || {};
    if (!$("shareLan").checked) {
      box.style.display = "none";
      return;
    }
    box.style.display = "";
    $("shareIntRow").style.display = "";
    const ip = await bridge.get_lan_ip();
    $("shareHint").textContent = I18n.t("pg.share_hint", { ip, port: sharePort() });
    $("shareLinkMt").value = buildProxyLink(ip, cfg);
    $("shareLinkSocks").value = `${ip}:${tg.port || 1353}`;
    $("shareInternet").checked = !!(state.settings && state.settings.app && state.settings.app.share_public);
    await shareInternetApply($("shareInternet").checked);
  }

  function buildSocksLink(host, port) {
    return `tg://socks?server=${host}&port=${port}`;
  }

  async function shareInternetApply(on) {
    const cfg = (state.settings && state.settings.proxy) || {};
    const port = sharePort();
    if (on) {
      const mapped = await bridge.upnp_map([port]);
      const pub = await bridge.get_public_ip();
      if (pub) {
        $("pubHint").style.display = "";
        $("pubHint").className = "hint";
        $("pubHint").textContent = mapped.ok
          ? I18n.t("pg.pub_ok", { ip: pub, port })
          : I18n.t("pg.pub_ok", { ip: pub, port }) + " · " + I18n.t("pg.upnp_warn", { port });
        $("pubRow").style.display = "";
        $("pubLink").value = state.proxyMode === "socks5"
          ? `${pub}:${port}`
          : buildProxyLink(pub, cfg);
      } else {
        $("pubRow").style.display = "none";
        $("pubHint").style.display = "";
        $("pubHint").className = "hint error";
        $("pubHint").textContent = I18n.t("pg.pub_fail");
      }
    } else {
      await bridge.upnp_unmap([port]);
      $("pubRow").style.display = "none";
      $("pubHint").style.display = "none";
    }
  }

  async function setShare(on) {
    const restore = state.saveHost || "127.0.0.1";
    const host = on ? "0.0.0.0" : restore;
    await save("proxy", "host", host, { silent: true });
    await save("telegram", "bind_host", host, { silent: true });
    $("mtHost").value = host;
    state.settings.proxy = Object.assign({}, state.settings.proxy, { host });
    if (on) {
      await save("app", "share_lan", true);
      await restartActiveProxy();
      await refreshShare();
    } else {
      $("shareInternet").checked = false;
      await save("app", "share_lan", false);
      await save("app", "share_public", false, { silent: true });
      await bridge.upnp_unmap([sharePort()]);
      await refreshShare();
      await restartActiveProxy();
    }
  }

  function syncTheme(mode) {
    $$("#themeMode button").forEach((b) => b.classList.toggle("active", b.dataset.val === mode));
  }
  function applyThemeUI() {
    const ap = (state.settings && state.settings.appearance) || {};
    applyTheme(ap);
  }

  // ── load settings into UI ──────────────────────────────────────────────
  async function loadSettings() {
    const s = await bridge.get_settings();
    if (!s) return;
    state.settings = s;
    const p = s.proxy || {};
    const tg = s.telegram || {};
    const ap = s.appearance || {};
    const app = s.app || {};

    $("mtHost").value = p.host || "127.0.0.1";
    $("mtPort").value = p.port || 1443;
    $("mtSecret").value = p.secret || "";
    $("mtPool").value = p.pool_size || 4;
    $("mtEnable").checked = app.run_proxy_on_startup !== false;

    state.saveHost = p.host || "127.0.0.1";
    applyProxyMode(app.proxy_mode === "socks5" ? "socks5" : "mt");
    $("shareLan").checked = !!app.share_lan;
    if (!app.share_lan) {
      let healed = false;
      if ((p.host || "") === "0.0.0.0") {
        await save("proxy", "host", "127.0.0.1", { silent: true });
        state.settings.proxy = Object.assign({}, state.settings.proxy, { host: "127.0.0.1" });
        $("mtHost").value = "127.0.0.1";
        healed = true;
      }
      if ((tg.bind_host || "") === "0.0.0.0") {
        await save("telegram", "bind_host", "127.0.0.1", { silent: true });
        state.settings.telegram = Object.assign({}, state.settings.telegram, { bind_host: "127.0.0.1" });
        healed = true;
      }
      if (healed) await restartActiveProxy();
    }

    $("tgHost").value = tg.bind_host || "127.0.0.1";
    $("tgPort").value = tg.port || 1353;

    $("setTrayMin").checked = app.minimize_to_tray !== false;
    $("setStartMin").checked = !!app.start_minimized;
    $("experimentalToggle").checked = !!app.experimental;
    $("sysProxyToggle").checked = !!app.system_proxy;

    syncTheme(ap.mode || "auto");
    applyTheme(ap);

    await resolveAndSetLang();
    applyCollapsed(!!app.sidebar_collapsed);
    await refreshShare();
    await loadData();
    logAutoTicks();
  }

  function renderDynamic() {
    renderPresets();
    renderProfiles();
    renderDpiEngine();
    refreshDashDpi();
    renderHosts();
    renderDns();
    renderDnsAdapters();
    renderTools();
    renderWinDivert();
    renderBlockcheckPresets();
    renderHelp();
    renderAutostart();
    renderAutopilot();
    renderOrchestraLearning();
    refreshStatus();
    refreshProxyLink();
    refreshDashStats();
    loadLogs();
    if (state.autoMode) toggleAutoMode();
  }

  async function loadData() {
    await Promise.all([
      renderDns(),
      renderHosts(),
      renderPresets(),
      renderProfiles(),
      renderDpiEngine(),
      refreshDashDpi(),
      renderTools(),
      renderBlockcheckPresets(),
      renderHelp(),
      renderAutostart(),
      renderAutopilot(),
      renderOrchestraLearning(),
      refreshStatus(),
      refreshProxyLink(),
      refreshDashStats(),
    ]);
    if (state.autoMode) toggleAutoMode();
  }

  // ── bootstrap ──────────────────────────────────────────────────────────
  async function boot() {
    try {
      const info = await bridge.get_app_info();
      if (info) {
        state.appInfo = info;
        $("aboutLine").textContent = I18n.t("st.about_line", {
          version: info.version, engine: info.engine_version, platform: info.platform,
        });
        $("tbVersion").textContent = `v${info.version}`;
      }
      await loadSettings();
      wireSettings();
      bridge.profile_list().then((r) => { if (r && r.ok) state.pfRecommended = r.recommended || ""; });
      refreshUpdates(false);
      setInterval(() => { refreshUpdates(false); }, 9000);
      setInterval(() => {
        const active = $$(".page.active")[0];
        if (active && active.dataset.pageView === "tools") renderOrchestraLearning();
      }, 5000);
      setInterval(() => {
        const active = $$(".page.active")[0];
        if (active && active.dataset.pageView === "profiles") renderAutopilot();
      }, 2000);
      const lb = $("logBottomBtn");
      if (lb) lb.innerHTML = Icon("down", 14);
      $$(".tb-btn").forEach((b) => {
        b.addEventListener("mousedown", (e) => e.stopPropagation());
      });
      setInterval(() => {
        const active = $$(".page.active")[0];
        if (active && active.dataset.pageView === "dashboard") {
          refreshStatus();
          refreshDashDpi();
          refreshDashStats();
        }
      }, 3000);
    } catch (e) {
      console.error("SwiftUI boot failed:", e);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
  // expose for debugging
  window.__swiftState = state;
})();