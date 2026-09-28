// Small DOM toolkit. All text goes through text nodes (never innerHTML), so exam content,
// names and server messages cannot inject markup or script.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (["value", "checked", "disabled", "selected"].includes(k)) el[k] = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const c of [children].flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function clear(el, ...children) {
  el.replaceChildren();
  return append(el, children);
}

// --- icons (stroke paths, 24x24) ---------------------------------------------------

const ICONS = {
  check: ["M20 6 9 17l-5-5"],
  x: ["M18 6 6 18", "M6 6l12 12"],
  lock: ["M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z",
         "M7 11V7a5 5 0 0 1 10 0v4"],
  shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", "m9 12 2 2 4-4"],
  alert: ["M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z",
          "M12 9v4", "M12 17h.01"],
  key: ["M15.5 7.5 19 4", "M21 2l-2 2", "m15.5 7.5 3 3L22 7l-3-3",
        "M11.39 11.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78z", "m11.39 11.61 4.11-4.11"],
  download: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M7 10l5 5 5-5", "M12 15V3"],
  upload: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M17 8l-5-5-5 5", "M12 3v12"],
  clock: ["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M12 6v6l4 2"],
  user: ["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"],
  users: ["M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2", "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z",
          "M23 21v-2a4 4 0 0 0-3-3.87", "M16 3.13a4 4 0 0 1 0 7.75"],
  logout: ["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "M16 17l5-5-5-5", "M21 12H9"],
  plus: ["M12 5v14", "M5 12h14"],
  refresh: ["M21 12a9 9 0 1 1-2.64-6.36L21 8", "M21 3v5h-5"],
  file: ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6"],
  clipboard: ["M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2",
              "M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2z", "m9 14 2 2 4-4"],
  activity: ["M22 12h-4l-3 9L9 3l-3 9H2"],
  server: ["M4 3h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z",
           "M4 13h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2z",
           "M6 7h.01", "M6 17h.01"],
  arrowLeft: ["M19 12H5", "m12 19-7-7 7-7"],
  eye: ["M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"],
  copy: ["M9 9h11a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2z",
         "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"],
  trash: ["M3 6h18", "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6", "M10 11v6", "M14 11v6",
          "M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"],
};

const SVG = "http://www.w3.org/2000/svg";
export function icon(name, cls = "icon") {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", cls);
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name] || []) {
    const p = document.createElementNS(SVG, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}

// --- feedback ------------------------------------------------------------------------

export function toast(message, kind = "info", ms = 4500) {
  const root = document.getElementById("toasts");
  const el = h("div", { class: `toast toast-${kind}`, role: kind === "error" ? "alert" : "status" },
               icon(kind === "error" ? "alert" : kind === "success" ? "check" : "shield"),
               h("span", null, message));
  root.append(el);
  setTimeout(() => { el.classList.add("leaving"); setTimeout(() => el.remove(), 250); }, ms);
}

// Opens a modal dialog. `actions` = [{label, kind, value}], resolves with the chosen value
// (or `null` when dismissed). `onAction(value)` may return false to keep the dialog open.
export function modal({ title, body, actions = [], onAction, wide = false, dismissable = true }) {
  return new Promise((resolve) => {
    const root = document.getElementById("modal-root");
    const previous = document.activeElement;
    let done = false;
    const close = (value) => {
      if (done) return;
      done = true;
      root.removeEventListener("keydown", onKey);
      overlay.remove();
      previous?.focus?.();
      resolve(value);
    };
    const buttons = actions.map((a) => h("button", {
      class: `btn ${a.kind ? "btn-" + a.kind : ""}`, type: a.submit ? "submit" : "button",
      onclick: async (ev) => {
        if (a.submit) return;          // handled by the form's submit event
        ev.preventDefault();
        await run(a.value);
      },
    }, a.label));
    async function run(value) {
      if (onAction) {
        buttons.forEach((b) => (b.disabled = true));
        let keep = false;
        try { keep = (await onAction(value)) === false; } finally {
          buttons.forEach((b) => (b.disabled = false));
        }
        if (keep) return;
      }
      close(value);
    }
    const submitAction = actions.find((a) => a.submit);
    const form = h("form", {
      class: `modal ${wide ? "modal-wide" : ""}`, role: "dialog", "aria-modal": "true",
      "aria-labelledby": "modal-title", novalidate: true,
      onsubmit: (ev) => { ev.preventDefault(); if (submitAction) run(submitAction.value); },
    },
      h("div", { class: "modal-head" }, h("h2", { id: "modal-title" }, title),
        dismissable && h("button", { type: "button", class: "icon-btn", "aria-label": "Close",
                                     onclick: () => close(null) }, icon("x"))),
      h("div", { class: "modal-body" }, body),
      actions.length && h("div", { class: "modal-actions" }, buttons));
    const overlay = h("div", { class: "overlay", onmousedown: (ev) => {
      if (dismissable && ev.target === overlay) close(null);
    } }, form);
    const onKey = (ev) => { if (ev.key === "Escape" && dismissable) close(null); };
    root.addEventListener("keydown", onKey);
    root.append(overlay);
    (form.querySelector("input, select, textarea") || form.querySelector(".modal-actions .btn:last-child"))?.focus();
  });
}

export async function confirmDialog(title, message, { confirmLabel = "Confirm", danger = false } = {}) {
  const r = await modal({
    title, body: h("p", null, message),
    actions: [{ label: "Cancel", value: false }, { label: confirmLabel, kind: danger ? "danger" : "primary", value: true }],
  });
  return r === true;
}

// Asks for a password; `check(password)` runs inside the dialog and may throw to show an error.
export async function passwordDialog(title, message, check, confirmLabel = "Unlock") {
  const input = h("input", { type: "password", autocomplete: "current-password", required: true });
  const error = h("p", { class: "form-error", role: "alert" });
  let result = null;
  const r = await modal({
    title,
    body: [h("p", null, message), h("label", { class: "field" }, h("span", null, "Password"), input), error],
    actions: [{ label: "Cancel", value: null }, { label: confirmLabel, kind: "primary", value: "ok", submit: true }],
    onAction: async (v) => {
      if (v !== "ok") return true;
      error.textContent = "";
      try { result = await check(input.value); } catch (exc) {
        error.textContent = exc.message;
        input.select();
        return false;
      }
      return true;
    },
  });
  return r === "ok" ? result : null;
}

// --- files ---------------------------------------------------------------------------

export function download(filename, text, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function pickFile(accept) {
  return new Promise((resolve) => {
    const input = h("input", { type: "file", accept, class: "visually-hidden" });
    input.addEventListener("change", async () => {
      const f = input.files[0];
      input.remove();
      resolve(f ? { name: f.name, text: await f.text() } : null);
    });
    document.body.append(input);
    input.click();
  });
}

// --- formatting ----------------------------------------------------------------------

export function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleString(undefined, {
    day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

export function fmtCountdown(seconds) {
  seconds = Math.max(0, Math.floor(seconds));
  const hh = Math.floor(seconds / 3600), mm = Math.floor((seconds % 3600) / 60), ss = seconds % 60;
  const two = (n) => String(n).padStart(2, "0");
  return hh ? `${hh}:${two(mm)}:${two(ss)}` : `${two(mm)}:${two(ss)}`;
}

export function fmtRelative(ts) {
  const diff = ts - Date.now() / 1000, abs = Math.abs(diff);
  const units = [["day", 86400], ["hour", 3600], ["minute", 60]];
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, size] of units)
    if (abs >= size) return rtf.format(Math.round(diff / size), unit);
  return diff >= 0 ? "in under a minute" : "just now";
}

export function badge(text, kind = "neutral") {
  return h("span", { class: `badge badge-${kind}` }, text);
}

export function checklist(checks) {
  return h("ul", { class: "checklist" }, checks.map(([label, ok]) =>
    h("li", { class: ok ? "ok" : "bad" }, icon(ok ? "check" : "x"), h("span", null, label))));
}

export function spinner(label = "Working…") {
  return h("div", { class: "loading" }, h("span", { class: "spinner", "aria-hidden": "true" }), label);
}

export function emptyState(title, text, iconName = "file") {
  return h("div", { class: "empty" }, icon(iconName, "icon icon-lg"), h("h3", null, title), h("p", null, text));
}

export function field(label, input, hint) {
  return h("label", { class: "field" }, h("span", null, label), input, hint && h("small", null, hint));
}

// Disables a button while an async action runs, showing a spinner.
export async function busy(button, fn) {
  const label = [...button.childNodes];
  button.disabled = true;
  button.classList.add("is-busy");
  button.prepend(h("span", { class: "spinner", "aria-hidden": "true" }));
  try { return await fn(); } finally {
    button.disabled = false;
    button.classList.remove("is-busy");
    button.replaceChildren(...label);
  }
}
