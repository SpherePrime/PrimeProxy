// PrimeProxy — JS bridge to Python via window.pywebview.api.
// Waits for the pywebview API to be fully injected before calling, so
// calls made at page-load time resolve once the bridge is ready.

(function () {
  function waitFor(name, tries, delay) {
    return new Promise(function (resolve) {
      var n = 0;
      function step() {
        var native = window.pywebview && window.pywebview.api;
        if (native && typeof native[name] === "function") {
          return resolve(true);
        }
        if (++n >= tries) {
          return resolve(false);
        }
        setTimeout(step, delay);
      }
      step();
    });
  }

  function call(name) {
    var args = Array.prototype.slice.call(arguments, 1);
    return waitFor(name, 150, 25).then(function (ready) {
      if (!ready) return null;
      try {
        return window.pywebview.api[name].apply(null, args);
      } catch (e) {
        return null;
      }
    });
  }

  var bridge = {
    // App / meta
    get_app_info: function () { return call("get_app_info"); },
    get_settings: function () { return call("get_settings"); },
    set_setting: function (s, k, v) { return call("set_setting", s, k, v); },

    // Window controls (frameless titlebar)
    window_state: function () { return call("window_state"); },
    window_minimize: function () { return call("window_minimize"); },
    window_toggle_maximize: function () { return call("window_toggle_maximize"); },
    window_toggle_fullscreen: function () { return call("window_toggle_fullscreen"); },
    window_close: function () { return call("window_close"); },
    apply_window_effect: function () { return call("apply_window_effect"); },
    set_live_glass: function (enabled, sharp) { return call("set_live_glass", enabled, sharp); },
    pick_wallpaper: function (kind) { return call("pick_wallpaper", kind); },
    wallpaper_url: function (path) { return call("wallpaper_url", path); },

    // MTProto proxy
    get_proxy_status: function () { return call("get_proxy_status"); },
    start_proxy: function () { return call("start_proxy"); },
    stop_proxy: function () { return call("stop_proxy"); },

    // Telegram WSS proxy
    get_tg_proxy_status: function () { return call("get_tg_proxy_status"); },
    start_tg_proxy: function () { return call("start_tg_proxy"); },
    stop_tg_proxy: function () { return call("stop_tg_proxy"); },

    // DNS
    get_dns_providers: function () { return call("get_dns_providers"); },
    get_dns_provider: function (id) { return call("get_dns_provider", id); },
    run_dns_check: function (id) { return call("run_dns_check", id); },
    get_system_dns: function () { return call("get_system_dns"); },
    flush_dns: function () { return call("flush_dns"); },
    force_dns: function (servers) { return call("force_dns", servers || null); },
    restore_dns: function () { return call("restore_dns"); },
    get_network_adapters: function () { return call("get_network_adapters"); },
    run_quick_dns_check: function () { return call("run_quick_dns_check"); },
    run_dns_poisoning_check: function () { return call("run_dns_poisoning_check"); },
    get_dns_check_status: function () { return call("get_dns_check_status"); },
    stop_dns_poisoning_check: function () { return call("stop_dns_poisoning_check"); },

    // Hosts
    get_hosts_services: function () { return call("get_hosts_services"); },
    get_hosts_active: function () { return call("get_hosts_active"); },
    get_hosts_selection: function () { return call("get_hosts_selection"); },
    apply_hosts_services: function (ids, adobe) { return call("apply_hosts_services", ids, adobe); },
    clear_hosts: function () { return call("clear_hosts"); },

    // Proxy link
    get_tray_proxy_link: function () { return call("get_tray_proxy_link"); },
    copy_proxy_link: function () { return call("copy_proxy_link"); },
    copy_text: function (text) { return call("copy_text", text); },
    open_proxy_link: function () { return call("open_proxy_link"); },
    open_link: function (url) { return call("open_link", url); },
    set_system_proxy: function (on) { return call("set_system_proxy", !!on); },
    get_system_proxy: function () { return call("get_system_proxy"); },
    get_lan_ip: function () { return call("get_lan_ip"); },
    get_public_ip: function () { return call("get_public_ip"); },
    get_upnp_status: function () { return call("get_upnp_status"); },
    upnp_map: function (ports) { return call("upnp_map", ports || []); },
    upnp_unmap: function (ports) { return call("upnp_unmap", ports || []); },

    // Updates
    get_update_status: function () { return call("get_update_status"); },
    check_updates: function (force) { return call("check_updates", !!force); },
    get_update_job: function () { return call("get_update_job"); },
    download_update: function () { return call("download_update"); },
    rollback_to: function (tag) { return call("rollback_to", tag); },
    list_available_versions: function (limit) { return call("list_available_versions", limit); },
    restart_pending: function () { return call("restart_pending"); },
    open_downloads_dir: function () { return call("open_downloads_dir"); },
    restart_app: function () { return call("restart_app"); },

    // Manifest updates (hardened source / integrity)
    set_update_source: function (url) { return call("set_update_source", url || ""); },
    set_auto_check: function (enabled) { return call("set_auto_check", !!enabled); },
    run_updates_check: function () { return call("run_updates_check"); },
    get_updates_check_status: function () { return call("get_updates_check_status"); },
    engine_fingerprint: function (compute) { return call("engine_fingerprint", !!compute); },
    reset_engine_baseline: function () { return call("reset_engine_baseline"); },

    // Presets & clients
    get_presets: function () { return call("get_presets"); },
    get_active_preset: function () { return call("get_active_preset"); },
    apply_preset: function (id) { return call("apply_preset", id); },
    save_user_preset: function (label, description, changes) { return call("save_user_preset", label, description, changes); },
    delete_user_preset: function (id) { return call("delete_user_preset", id); },
    // Zapret profiles & engine (winws)
    get_zapret_profiles: function (group) { return call("get_zapret_profiles", group || "winws2"); },
    get_zapret_profile_text: function (group, fileName) { return call("get_zapret_profile_text", group, fileName); },
    get_zapret_strategies: function () { return call("get_zapret_strategies"); },
    get_zapret_engine: function () { return call("get_zapret_engine"); },
    set_zapret_settings: function (values) { return call("set_zapret_settings", values || {}); },
    get_dpi_status: function () { return call("get_dpi_status"); },
    start_dpi: function (group, fileName) { return call("start_dpi", group || "", fileName || ""); },
    stop_dpi: function () { return call("stop_dpi"); },
    restart_dpi: function () { return call("restart_dpi"); },
    get_winws_log: function (limit) { return call("get_winws_log", limit || 8000); },
    get_winws_log_status: function () { return call("get_winws_log_status"); },
    read_winws_log_last: function (lines) { return call("read_winws_log_last", lines || 200); },
    get_zapret_user_profiles: function () { return call("get_zapret_user_profiles"); },
    get_zapret_user_profile: function (name) { return call("get_zapret_user_profile", name); },
    save_zapret_user_profile: function (name, text) { return call("save_zapret_user_profile", name, text); },
    delete_zapret_user_profile: function (name) { return call("delete_zapret_user_profile", name); },
    profile_list: function () { return call("profile_list"); },
    profile_read: function (name) { return call("profile_read", name); },
    profile_write: function (name, content) { return call("profile_write", name, content); },
    profile_reset: function (name) { return call("profile_reset", name); },
    profile_delete: function (name) { return call("profile_delete", name); },
    profile_validate_paste: function (content) { return call("profile_validate_paste", content); },
    // Diagnostics & Windows tools
    run_diagnostics: function () { return call("run_diagnostics"); },
    get_windows_tool_status: function () { return call("get_windows_tool_status"); },
    windows_cleanup: function () { return call("windows_cleanup"); },
    defender_exclude: function (path) { return call("defender_exclude", path || ""); },
    get_lists_status: function () { return call("get_lists_status"); },
    save_user_list: function (text) { return call("save_user_list", text); },
    // BlockCheck («Проверка сайтов»)
    get_blockcheck_presets: function () { return call("get_blockcheck_presets"); },
    start_blockcheck: function (domain) { return call("start_blockcheck", domain || ""); },
    get_blockcheck_status: function () { return call("get_blockcheck_status"); },
    stop_blockcheck: function () { return call("stop_blockcheck"); },
    add_blockcheck_domain: function (domain) { return call("add_blockcheck_domain", domain || ""); },
    remove_blockcheck_domain: function (domain) { return call("remove_blockcheck_domain", domain || ""); },
    // Orchestra (авто-выбор стратегии)
    list_strategies: function () { return call("list_strategies"); },
    orchestra_recommend: function (symptomsText) { return call("orchestra_recommend", symptomsText || ""); },
    apply_strategy: function (strategyId, profileName, sectionName) {
      return call("apply_strategy", strategyId || "", profileName || "", sectionName || "");
    },
    // Orchestra learning (LEARNING / auto-strategy lock)
    get_orchestra_status: function () { return call("get_orchestra_status"); },
    start_orchestra_learning: function () { return call("start_orchestra_learning"); },
    stop_orchestra_learning: function () { return call("stop_orchestra_learning"); },
    clear_orchestra_learning: function () { return call("clear_orchestra_learning"); },
    list_locked_strategies: function () { return call("list_locked_strategies"); },
    // Autopilot (авто-pilot «Обход Zapret»)
    auto_status: function () { return call("auto_status"); },
    auto_start: function () { return call("auto_start"); },
    auto_stop: function () { return call("auto_stop"); },
    auto_reset: function () { return call("auto_reset"); },
    auto_journal: function (limit) { return call("auto_journal", limit || 250); },

    // Browser extension
    get_browser_ext_info: function () { return call("get_browser_ext_info"); },
    open_browser: function (browser) { return call("open_browser", browser); },

    // Logs
    get_log_tail: function (limit) { return call("get_log_tail", limit); },
    open_logs_dir: function () { return call("open_logs_dir"); },
    report_ui_error: function (source, message) { return call("report_ui_error", source, message); },
    open_devtools: function () { return call("open_devtools"); },

    // WinDivert health & diagnostics
    get_windivert_health: function () { return call("get_windivert_health"); },
    run_winws_diagnostics: function () { return call("run_winws_diagnostics"); },
    windivert_cleanup: function (level) { return call("windivert_cleanup", level || "standard"); },
    kill_conflicting_processes: function () { return call("kill_conflicting_processes"); },
    get_winws_health: function () { return call("get_winws_health"); },

    // Autostart (services / scheduled tasks / shortcuts)
    get_autostart_status: function () { return call("get_autostart_status"); },
    autostart_install: function (method, scope) { return call("autostart_install", method || "task", scope || "app"); },
    autostart_remove: function (method, scope) { return call("autostart_remove", method || "task", scope || "app"); },
    autostart_start_service: function (scope) { return call("autostart_start_service", scope || "app"); },
    autostart_stop_service: function (scope) { return call("autostart_stop_service", scope || "app"); },
  };

  window.bridge = bridge;
})();