// SwiftProxy — reusable UI components (iOS 26 Liquid Glass).

(function () {
  const Components = {
    /**
     * Renders an inline SVG icon.
     */
    icon(name, size, cls) {
      const wrap = document.createElement("span");
      wrap.className = "icon-box" + (cls ? " " + cls : "");
      wrap.innerHTML = Icon(name, size);
      return wrap;
    },

    /**
     * SVG inside a small badge circle.
     */
    iconBadge(name, color) {
      const el = document.createElement("span");
      el.className = "icon-badge";
      if (color) el.style.color = color;
      el.innerHTML = Icon(name, 16);
      return el;
    },

    /**
     * Creates a toggle element wired to a change listener.
     */
    toggle(checked, onchange) {
      const label = document.createElement("label");
      label.className = "toggle";
      const input = document.createElement("input");
      input.type = "checkbox";
      input.checked = !!checked;
      input.addEventListener("change", () => onchange && onchange(input.checked));
      const track = document.createElement("span");
      track.className = "track";
      const thumb = document.createElement("span");
      thumb.className = "thumb";
      label.append(input, track, thumb);
      return label;
    },

    /**
     * Creates an iOS-style segmented control.
     * options: [{label, value}]  onchange(value)
     */
    segmented(options, active, onchange) {
      const wrap = document.createElement("div");
      wrap.className = "segmented-control";
      options.forEach((opt) => {
        const btn = document.createElement("button");
        btn.textContent = opt.label;
        btn.dataset.val = opt.value;
        if (opt.value === active) btn.classList.add("active");
        btn.addEventListener("click", () => {
          wrap.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
          onchange && onchange(opt.value);
        });
        wrap.appendChild(btn);
      });
      return wrap;
    },

    /**
     * Creates a small status pill: ok / off / warn.
     */
    badge(level, text) {
      const el = document.createElement("span");
      el.className = "status-badge " + level;
      el.textContent = text;
      return el;
    },

    /**
     * Creates a button with optional leading icon.
     */
    button(label, cls, iconName, onclick) {
      const btn = document.createElement("button");
      btn.className = "btn " + (cls || "");
      if (iconName) {
        const ic = document.createElement("span");
        ic.className = "btn-icon";
        ic.innerHTML = Icon(iconName, 15);
        btn.appendChild(ic);
      }
      const tx = document.createElement("span");
      tx.textContent = label;
      btn.appendChild(tx);
      if (onclick) btn.addEventListener("click", onclick);
      return btn;
    },

    /**
     * Brief toast notification.
     */
    toast(message, level) {
      const host = document.getElementById("toastHost");
      if (!host) return;
      const el = document.createElement("div");
      el.className = "toast" + (level ? " toast-" + level : "");
      el.textContent = message;
      host.appendChild(el);
      requestAnimationFrame(() => el.classList.add("show"));
      setTimeout(() => {
        el.classList.remove("show");
        setTimeout(() => el.remove(), 300);
      }, 2200);
    },
  };

  window.Components = Components;
})();