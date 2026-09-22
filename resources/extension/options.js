// PrimeProxy Browser — options page.

const DEFAULTS = { host: "127.0.0.1", port: 1353 };

chrome.storage.sync.get(DEFAULTS, (s) => {
  document.getElementById("host").value = s.host || DEFAULTS.host;
  document.getElementById("port").value = Number(s.port) || DEFAULTS.port;
});

document.getElementById("save").addEventListener("click", () => {
  const host = (document.getElementById("host").value || "").trim() || DEFAULTS.host;
  const port = parseInt(document.getElementById("port").value, 10) || DEFAULTS.port;
  chrome.storage.sync.set({ host, port, enabled: false }, () => {
    const saved = document.getElementById("saved");
    saved.style.display = "";
    setTimeout(() => { saved.style.display = "none"; }, 1500);
  });
});