// SwiftProxy Browser — service worker (Manifest V3).
// Routes the whole browser through the local SOCKS5 proxy.

const DEFAULTS = { host: "127.0.0.1", port: 1353 };

async function settings() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  return { host: s.host || DEFAULTS.host, port: Number(s.port) || DEFAULTS.port };
}

function setBadge(on) {
  try {
    if (on) {
      chrome.action.setBadgeBackgroundColor({ color: "#0a84ff" });
      chrome.action.setBadgeText({ text: "ON" });
    } else {
      chrome.action.setBadgeBackgroundColor({ color: "#8a8a8e" });
      chrome.action.setBadgeText({ text: "" });
    }
  } catch (e) {
    /* ignored */
  }
}

async function applyNow() {
  const { enabled } = await chrome.storage.sync.get({ enabled: false });
  setBadge(!!enabled);
  if (!enabled) {
    try {
      await chrome.proxy.settings.clear({ scope: "regular" });
      chrome.action.setTitle({ title: "SwiftProxy \u2014 off" });
    } catch (e) {
      /* ignored */
    }
    return;
  }
  const c = await settings();
  const config = {
    mode: "fixed_servers",
    rules: {
      singleProxy: { scheme: "socks5", host: c.host, port: c.port },
    },
    bypassList: ["<local>"],
  };
  try {
    await chrome.proxy.settings.set({ value: config, scope: "regular" });
    chrome.action.setTitle({ title: "SwiftProxy \u2014 on (" + c.host + ":" + c.port + ")" });
  } catch (e) {
    setBadge(false);
  }
}

chrome.runtime.onInstalled.addListener(applyNow);
chrome.runtime.onStartup.addListener(applyNow);

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || !msg.type) return;
  if (msg.type === "get") {
    chrome.storage.sync.get({ enabled: false }, (s) => sendResponse({ ok: true, enabled: !!s.enabled }));
  } else if (msg.type === "set") {
    chrome.storage.sync.set({ enabled: !!msg.enabled }, async () => {
      await applyNow();
      sendResponse({ ok: true });
    });
  } else {
    sendResponse({ ok: false });
  }
  return true;
});

// Don't spam the console with proxy errors — the toggle is the source of truth.
chrome.proxy.onProxyError.addListener(() => {});