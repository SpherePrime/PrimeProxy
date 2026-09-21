// SwiftProxy Browser — popup toggle.

(function () {
  const status = document.getElementById("status");
  const toggle = document.getElementById("toggle");

  function render(on) {
    if (on) {
      toggle.textContent = "Turn off proxy";
      toggle.className = "on";
      status.textContent = "On — browser traffic goes through the proxy";
    } else {
      toggle.textContent = "Turn on proxy";
      toggle.className = "off";
      status.textContent = "Off";
    }
  }

  chrome.runtime.sendMessage({ type: "get" }, (res) => {
    if (res && res.ok) render(!!res.enabled);
  });

  toggle.addEventListener("click", () => {
    const next = !toggle.classList.contains("on");
    chrome.runtime.sendMessage({ type: "set", enabled: next }, (res) => {
      if (res && res.ok) render(next);
    });
  });

  document.getElementById("opts").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
})();