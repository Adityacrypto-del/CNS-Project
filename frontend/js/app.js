// Application shell: secure session lifecycle, signing keys, routing, and the screens that
// work without an exam role (sign in, activate account, account settings, verify a file).

import { CONFIG } from "/config.js";
import { ApiError, SecureSession } from "./channel.js";
import { classifyFile, ExamClient, verifyReceiptFile } from "./client.js";
import {
  decryptPkcs8, encryptPkcs8, generateUserKey, importPkcs8, importServerKey, nowSeconds,
  unlockKey, verifySigned, WrongPasswordError,
} from "./crypto.js";
import {
  badge, busy, checklist, clear, confirmDialog, download, emptyState, field, fmtTime, h, icon,
  modal, passwordDialog, pickFile, spinner, toast,
} from "./dom.js";
import * as keystore from "./keystore.js";
import * as student from "./student.js";
import * as admin from "./admin.js";

const SESSION_STORE = "secure-exam-session";   // sessionStorage: this tab only, gone when it closes
const KEEPALIVE_MS = 4 * 60 * 1000;            // the API drops sessions idle for 30 min

export const app = {
  server: null,          // pinned server key (imported from /config.js)
  client: null,          // ExamClient over the current SecureSession
  user: null,            // {user_id, role, name}
  signingKey: null,      // non-extractable CryptoKey, memory only
  clockSkew: 0,
};

// --- errors --------------------------------------------------------------------------

const MESSAGES = {
  INVALID_CREDENTIALS: "Wrong user ID or password.",
  ACCOUNT_LOCKED: "Too many failed attempts. Try again in 5 minutes, or ask the examiner to unlock the account.",
  SESSION_ACTIVE: "This account is already signed in elsewhere (another tab, window or device). Sign out there, or wait for that session to expire (30 minutes of inactivity).",
  INVALID_ENROLLMENT: "Unknown student ID, or the enrollment code is wrong, expired or already used.",
  RESULTS_NOT_RELEASED: "Results for this exam have not been released yet.",
  ALREADY_SUBMITTED: "You have already submitted this exam.",
  DEADLINE_PASSED: "The deadline for this exam has passed.",
  EXAM_NOT_OPEN: "This exam is not open.",
  INVALID_SIGNATURE: "The signature was rejected. The signing key on this device does not match the one registered for your account.",
  STALE_ACTION: "The action was rejected because this computer's clock is off by more than 60 seconds.",
  SERVER_AUTH_FAILED: "The server could not prove its identity with the pinned key. You may be talking to an impostor. Do not continue.",
  UNKNOWN_SESSION: "Your secure session expired. Please sign in again.",
  SESSION_EXPIRED: "Your sign-in is older than 3 hours. Please sign in again.",
  TAMPERING_DETECTED: "A message failed its integrity check, so the session was closed for your safety.",
  REPLAY_DETECTED: "A message was rejected as a replay or as too old (check this computer's clock). The session was closed.",
};

export function describeError(exc) {
  if (exc instanceof ApiError) {
    if (exc.code === "ACCOUNT_INACTIVE")
      return /pending/.test(exc.detail) ? "This account is not activated yet. Use “Activate account” with your enrollment code."
                                        : "This account has been disabled. Contact the examiner.";
    return MESSAGES[exc.code] || exc.detail || exc.code;
  }
  return exc?.message || String(exc);
}

export class Cancelled extends Error {}

export function handleError(exc) {
  if (exc instanceof Cancelled) return;
  console.error(exc);
  if (exc instanceof ApiError && (exc.sessionLost || app.client?.session.closed) && app.user) {
    endSession();
    showLogin(describeError(exc));
    return;
  }
  toast(describeError(exc), "error", 7000);
}

// --- session lifecycle ---------------------------------------------------------------

function persist() {
  try {
    if (!app.client || app.client.session.closed) sessionStorage.removeItem(SESSION_STORE);
    else sessionStorage.setItem(SESSION_STORE, JSON.stringify({
      ...app.client.session.serialise(), user: app.user,
    }));
  } catch { /* storage unavailable: a reload will simply need a new sign-in */ }
  renderHeader();
}

async function connect() {
  const session = await SecureSession.handshake(CONFIG.apiBase, app.server);
  return new ExamClient(session, app.server);
}

function adopt(client, user) {
  app.client = client;
  app.user = user;
  client.user = user;
  client.session.onChange = persist;
  persist();
}

export function endSession() {
  app.client = null;
  app.user = null;
  app.signingKey = null;
  try { sessionStorage.removeItem(SESSION_STORE); } catch { /* ignore */ }
  renderHeader();
}

async function resume() {
  let saved;
  try { saved = JSON.parse(sessionStorage.getItem(SESSION_STORE) || "null"); } catch { saved = null; }
  if (!saved?.user) return false;
  try {
    const session = await SecureSession.restore(CONFIG.apiBase, app.server, saved);
    const client = new ExamClient(session, app.server);
    client.user = saved.user;
    await client.call("WHOAMI");
    adopt(client, saved.user);
    return true;
  } catch {
    endSession();
    return false;
  }
}

async function logout() {
  const client = app.client;
  endSession();
  if (client) await client.logout();
  showLogin("You have signed out.", "info");
}

setInterval(() => {
  if (app.client && !app.client.session.closed)
    app.client.call("WHOAMI").catch(handleError);
}, KEEPALIVE_MS);

// --- signing keys --------------------------------------------------------------------

// Returns the unlocked signing key, asking for the password or a key file if needed.
export async function requireKey(purpose = "sign this action") {
  if (app.signingKey) return app.signingKey;
  const { role, user_id: uid } = app.user;
  const pem = await keystore.loadKeyPem(role, uid);
  if (!pem) {
    if (!await importKeyFile()) throw new Cancelled();
    return app.signingKey;
  }
  const key = await passwordDialog("Unlock your signing key",
    `Your private key is stored on this device encrypted with your password. Enter it to ${purpose}.`,
    async (pw) => {
      try { return await unlockKey(pem, pw); } catch (exc) {
        throw exc instanceof WrongPasswordError ? new Error("Wrong password for the stored key.") : exc;
      }
    });
  if (!key) throw new Cancelled();
  app.signingKey = key;
  renderHeader();
  return key;
}

// Imports a password-protected key file (e.g. data/clients/<id>_key.pem from the CLI tools).
export async function importKeyFile() {
  const { role, user_id: uid } = app.user;
  const file = await pickFile(".pem,application/x-pem-file,text/plain");
  if (!file) return false;
  const imported = await passwordDialog("Import signing key",
    `Enter the password that protects “${file.name}”. This is usually your account password from when the key was created.`,
    async (pw) => {
      try { return { pkcs8: await decryptPkcs8(file.text, pw), pw }; } catch (exc) {
        throw exc instanceof WrongPasswordError ? new Error("Wrong password for this key file.") : exc;
      }
    }, "Import");
  if (!imported) return false;
  // Stored re-encrypted with 600 000 PBKDF2 iterations (the CLI file format uses fewer).
  await keystore.saveKeyPem(role, uid, await encryptPkcs8(imported.pkcs8, imported.pw));
  app.signingKey = await importPkcs8(imported.pkcs8);
  renderHeader();
  toast("Signing key imported and stored encrypted on this device.", "success");
  return true;
}

// --- routing -------------------------------------------------------------------------

const main = () => document.getElementById("app");
let cleanups = [];
let renderToken = 0;

export function onCleanup(fn) { cleanups.push(fn); }
export function go(path) {
  if (location.hash === `#/${path}`) render();
  else location.hash = `#/${path}`;
}

function parseRoute() {
  const parts = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  return { name: parts[0] || "", args: parts.slice(1) };
}

const PUBLIC = { login: loginView, enroll: enrollView, verify: verifyView };

function routeFor(route) {
  const role = app.user?.role;
  if (route.name === "verify") return verifyView;
  if (!role) return PUBLIC[route.name] || loginView;
  if (route.name === "account") return accountView;
  if (role === "student") return student.routes[route.name] || student.routes.exams;
  return admin.routes[route.name] || admin.routes.admin;
}

export async function render() {
  for (const fn of cleanups.splice(0)) { try { fn(); } catch { /* ignore */ } }
  const token = ++renderToken;
  const route = parseRoute();
  const view = routeFor(route);
  if (!app.user && !PUBLIC[route.name]) history.replaceState(null, "", "#/login");
  renderHeader(route);
  clear(main(), spinner("Loading…"));
  try {
    const node = await view(...route.args);
    if (token === renderToken) clear(main(), node);
  } catch (exc) {
    if (token !== renderToken) return;
    handleError(exc);
    if (app.user) clear(main(), emptyState("Something went wrong", describeError(exc), "alert"));
  }
  if (token === renderToken) main().focus({ preventScroll: true });
}

function showLogin(message, kind = "error") {
  loginNotice = message ? { message, kind } : null;
  go("login");
}

// --- header & security panel -------------------------------------------------------------

function renderHeader(route = parseRoute()) {
  const header = document.getElementById("header");
  const brand = h("a", { class: "brand", href: app.user ? "#/" : "#/login" },
                  h("span", { class: "brand-mark" }, icon("shield")), h("span", null, "SecureExam"));
  if (!app.user) {
    clear(header, brand, h("nav", { class: "nav" },
      h("a", { href: "#/verify", class: route.name === "verify" ? "active" : "" }, "Verify a file")));
    return;
  }
  const links = app.user.role === "student"
    ? [["exams", "My exams", "clipboard"], ["verify", "Verify", "shield"], ["account", "Account", "user"]]
    : [["admin", "Exams", "clipboard"], ["students", "Students", "users"], ["audit", "Audit log", "activity"],
       ["system", "System", "server"], ["account", "Account", "user"]];
  const current = ["exam", "result", "receipt"].includes(route.name) ? "exams"
                : ["new-exam", "exam-detail", "submissions"].includes(route.name) ? "admin" : route.name;
  const closed = app.client?.session.closed;
  clear(header,
    brand,
    h("nav", { class: "nav", "aria-label": "Main" }, links.map(([r, label, ic]) =>
      h("a", { href: `#/${r}`, class: current === r || (!current && r === links[0][0]) ? "active" : "" },
        icon(ic), h("span", null, label)))),
    h("div", { class: "header-right" },
      h("button", { class: `secure-pill ${closed ? "is-closed" : ""}`, type: "button", onclick: securityPanel,
                    title: "Connection security details" },
        icon(closed ? "alert" : "lock"), h("span", null, closed ? "Session closed" : "Secure session")),
      h("span", { class: "user-chip", title: `${app.user.name} (${app.user.role === "admin" ? "examiner" : "student"})` },
        h("span", { class: "avatar" }, (app.user.name || app.user.user_id).slice(0, 1).toUpperCase()),
        h("span", { class: "user-name" }, app.user.user_id)),
      h("button", { class: "icon-btn", type: "button", "aria-label": "Sign out", title: "Sign out", onclick: logout },
        icon("logout"))));
}

async function securityPanel() {
  const s = app.client?.session;
  const keyState = app.signingKey ? "Unlocked (in memory, non-extractable)"
    : await keystore.loadKeyPem(app.user.role, app.user.user_id) ? "Stored encrypted on this device (locked)"
    : "Not on this device";
  const row = (k, v) => h("div", { class: "kv-row" }, h("dt", null, k), h("dd", null, v));
  await modal({
    title: "Connection security", wide: true,
    body: [
      checklist([
        ["TLS 1.3 to the API (the server refuses older versions)", true],
        ["Server proved its identity: RSA-PSS handshake signature checked against the pinned key", true],
        ["Session keys from RSA-OAEP key transport + HKDF-SHA256, held only in this tab", true],
        ["Every message: AES-256-CBC encryption + HMAC-SHA256, sequence number and timestamp", true],
      ]),
      h("dl", { class: "kv" },
        row("Pinned server key (SHA-256)", h("code", null, app.server.fingerprint)),
        row("Session", h("code", null, s ? `${s.sessionId.slice(0, 10)}…` : "none")),
        row("Messages sent / verified", s ? `${s.stats.sent} / ${s.stats.received}` : "–"),
        row("Next sequence number", s ? String(s.sendSeq) : "–"),
        row("Clock offset from server", `${app.clockSkew >= 0 ? "+" : ""}${app.clockSkew} s`),
        row("Your signing key", keyState)),
    ],
    actions: [{ label: "Close", value: null }],
  });
}

// --- sign in ---------------------------------------------------------------------------

let loginNotice = null;

async function loginView() {
  const notice = loginNotice;
  loginNotice = null;
  let role = "student";
  const uid = h("input", { name: "user_id", autocomplete: "username", required: true, spellcheck: "false",
                           autocapitalize: "off" });
  const pw = h("input", { name: "password", type: "password", autocomplete: "current-password", required: true });
  const error = h("p", { class: "form-error", role: "alert" }, notice?.kind === "error" ? notice.message : "");
  const seg = h("div", { class: "segmented", role: "radiogroup", "aria-label": "Sign in as" });
  const setRole = (r) => {
    role = r;
    for (const b of seg.children) b.setAttribute("aria-checked", String(b.dataset.role === r));
    uid.placeholder = r === "student" ? "e.g. S1001" : "e.g. examiner";
  };
  for (const [r, label] of [["student", "Student"], ["admin", "Examiner"]])
    seg.append(h("button", { type: "button", role: "radio", dataset: { role: r }, onclick: () => setRole(r) }, label));
  setRole("student");
  const submit = h("button", { class: "btn btn-primary btn-block", type: "submit" }, icon("lock"), "Sign in securely");

  const form = h("form", { class: "auth-form", novalidate: true, onsubmit: (ev) => {
    ev.preventDefault();
    error.textContent = "";
    if (!uid.value.trim() || !pw.value) { error.textContent = "Enter your user ID and password."; return; }
    busy(submit, async () => {
      try {
        await signIn(uid.value.trim(), pw.value, role);
      } catch (exc) {
        if (exc instanceof ApiError && exc.code === "NETWORK_ERROR") error.replaceChildren(...networkHelp());
        else error.textContent = describeError(exc);
        pw.select();
      }
    });
  } },
    field("Sign in as", seg), field("User ID", uid), field("Password", pw), error, submit);

  return authLayout("Sign in", "Use the account issued by your examiner.", [
    notice?.kind === "info" && h("div", { class: "notice notice-info" }, icon("check"), notice.message),
    form,
    h("p", { class: "auth-alt" }, "First time here? ", h("a", { href: "#/enroll" }, "Activate your account")),
    h("details", { class: "demo" }, h("summary", null, "Demo accounts"),
      h("ul", null,
        h("li", null, h("b", null, "Examiner: "), h("code", null, "examiner"), " / ", h("code", null, "Secure#Exam2026")),
        h("li", null, h("b", null, "Student: "), h("code", null, "S1001"), " / ", h("code", null, "Alice@Exam2026")),
        h("li", null, h("b", null, "To activate: "), h("code", null, "S1004"), " with code ",
          h("code", null, "DEMO-ENRL-CODE-2026")))),
  ]);
}

async function signIn(userId, password, role) {
  const client = await connect();
  let r;
  try {
    r = await client.login(userId, password, role);
  } catch (exc) {
    client.session.closed = true;   // abandon the unauthenticated session
    throw exc;
  }
  adopt(client, { user_id: r.user_id, role: r.role, name: r.name });
  app.clockSkew = r.server_time - nowSeconds();
  if (Math.abs(app.clockSkew) > 20)
    toast(`This computer's clock is ${Math.abs(app.clockSkew)} s off the server's. Messages more than 60 s off are rejected, so please fix it.`, "error", 10000);
  const pem = await keystore.loadKeyPem(role, r.user_id);
  if (pem) {
    try { app.signingKey = await unlockKey(pem, password); } catch {
      toast("Your stored signing key is protected by a different password. You will be asked for it when needed.", "info", 8000);
    }
  } else {
    toast(role === "admin" ? "No signing key on this device yet. Import your key file on the Account page."
                           : "No signing key on this device yet. You will need your key file to submit an exam.", "info", 8000);
  }
  renderHeader();
  go(role === "admin" ? "admin" : "exams");
}

function networkHelp() {
  const health = `${CONFIG.apiBase}/api/v1/health`;
  return [
    "Cannot reach the exam server. Check that it is running (",
    h("code", null, "python -m secure_exam.server"),
    "). If it is, your browser does not trust the system's private CA yet: open ",
    h("a", { href: health, target: "_blank", rel: "noopener noreferrer" }, health),
    " once and accept the certificate, or install ", h("code", null, "data/pki/ca_cert.pem"), " as a trusted root.",
  ];
}

function authLayout(title, subtitle, content) {
  return h("div", { class: "auth" },
    h("section", { class: "auth-card card" },
      h("div", { class: "auth-head" }, h("span", { class: "brand-mark lg" }, icon("shield")),
        h("h1", null, title), h("p", { class: "muted" }, subtitle)),
      content),
    h("aside", { class: "auth-side" },
      h("h2", null, "How your exam is protected"),
      h("ul", { class: "feature-list" },
        feature("lock", "Private channel", "TLS 1.3, plus an inner AES-256 + HMAC session whose keys only this tab holds."),
        feature("shield", "Verified server", "Every paper, receipt and result is RSA-signed and checked against a pinned key."),
        feature("key", "Your signature", "Answers are signed with a key generated on your device, so nobody can alter or deny them."))));
}

const feature = (ic, title, text) =>
  h("li", null, h("span", { class: "feature-icon" }, icon(ic)), h("div", null, h("b", null, title), h("p", null, text)));

// --- password policy (mirrors service.check_password_policy) --------------------------

export function passwordChecks(pw, userId) {
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  return [
    ["At least 10 characters", pw.length >= 10],
    ["3 of: lowercase, uppercase, digit, symbol", classes >= 3],
    ["Does not contain your user ID", !userId || !pw.toLowerCase().includes(userId.toLowerCase())],
  ];
}

export function passwordFields(getUserId, labels = ["New password", "Confirm new password"]) {
  const pw = h("input", { type: "password", autocomplete: "new-password", required: true });
  const confirm = h("input", { type: "password", autocomplete: "new-password", required: true });
  const meter = h("div", { class: "policy" });
  const update = () => {
    const checks = passwordChecks(pw.value, getUserId());
    if (confirm.value) checks.push(["Passwords match", pw.value === confirm.value]);
    clear(meter, checklist(checks));
  };
  pw.addEventListener("input", update);
  confirm.addEventListener("input", update);
  update();
  return {
    nodes: [field(labels[0], pw), field(labels[1], confirm), meter],
    value: () => pw.value,
    problem: () => {
      const bad = passwordChecks(pw.value, getUserId()).find(([, ok]) => !ok);
      if (bad) return `Password: ${bad[0].toLowerCase()}.`;
      if (pw.value !== confirm.value) return "The passwords do not match.";
      return null;
    },
  };
}

// --- activate account (enrollment) ----------------------------------------------------------

async function enrollView() {
  const sid = h("input", { autocomplete: "username", required: true, spellcheck: "false", autocapitalize: "off",
                           placeholder: "e.g. S1004" });
  const code = h("input", { required: true, spellcheck: "false", autocomplete: "one-time-code",
                            placeholder: "XXXX-XXXX-XXXX-XXXX", class: "mono" });
  const pw = passwordFields(() => sid.value.trim(), ["Choose a password", "Confirm password"]);
  const error = h("p", { class: "form-error", role: "alert" });
  const steps = h("ol", { class: "steps" });
  const submit = h("button", { class: "btn btn-primary btn-block", type: "submit" }, icon("key"), "Generate my key & activate");
  const container = h("div");

  const setStep = (i, state) => {
    const items = ["Generate an RSA-2048 key pair on this device", "Sign a proof that you hold the private key",
                   "Register your public key with the server", "Encrypt the private key with your password (PBKDF2, 600 000 rounds)"];
    if (!steps.children.length) items.forEach((t) => steps.append(h("li", null, t)));
    [...steps.children].forEach((li, j) => { li.className = j < i ? "done" : j === i ? state : ""; });
  };

  const form = h("form", { class: "auth-form", novalidate: true, onsubmit: (ev) => {
    ev.preventDefault();
    error.textContent = "";
    const studentId = sid.value.trim();
    if (!studentId || !code.value.trim()) { error.textContent = "Enter your student ID and enrollment code."; return; }
    const problem = pw.problem();
    if (problem) { error.textContent = problem; return; }
    busy(submit, async () => {
      try {
        setStep(0, "active");
        const key = await generateUserKey(2048);
        setStep(1, "active");
        const client = await connect();
        setStep(2, "active");
        await client.enroll(studentId, code.value.trim(), pw.value(), key);
        client.session.closed = true;
        setStep(3, "active");
        const pem = await encryptPkcs8(key.pkcs8, pw.value());
        key.pkcs8.fill(0);
        let stored = true;
        try { await keystore.saveKeyPem("student", studentId, pem); } catch { stored = false; }
        setStep(4, "done");
        clear(container, enrolledCard(studentId, pem, stored));
      } catch (exc) {
        [...steps.children].forEach((li) => { if (li.className === "active") li.className = "failed"; });
        error.textContent = exc instanceof ApiError && exc.code === "NETWORK_ERROR"
          ? "" : describeError(exc);
        if (exc instanceof ApiError && exc.code === "NETWORK_ERROR") error.replaceChildren(...networkHelp());
      }
    });
  } },
    field("Student ID", sid), field("Enrollment code", code, "The one-time code from your examiner. It works once."),
    ...pw.nodes, error, steps, submit);
  container.append(form, h("p", { class: "auth-alt" }, "Already activated? ", h("a", { href: "#/login" }, "Sign in")));
  return authLayout("Activate your account", "Your signing key is created here and never leaves this device unencrypted.",
                    container);
}

function enrolledCard(studentId, pem, stored) {
  return h("div", { class: "success-block" },
    h("div", { class: "success-icon" }, icon("check")),
    h("h2", null, "Account activated"),
    h("p", null, `Welcome, ${studentId}. Your public key is registered, and your private key is `,
      stored ? "stored on this device, encrypted with your password." : "ready to download (this browser blocks local storage)."),
    h("div", { class: "notice notice-warn" }, icon("alert"),
      h("span", null, "Download a backup of your key. Without it you cannot submit exams from another device, or from this one if the browser data is cleared.")),
    h("div", { class: "btn-row" },
      h("button", { class: "btn", type: "button", onclick: () => download(`${studentId}_key.pem`, pem, "application/x-pem-file") },
        icon("download"), "Download key backup"),
      h("a", { class: "btn btn-primary", href: "#/login" }, "Continue to sign in")));
}

// --- account --------------------------------------------------------------------------------

async function accountView() {
  const { role, user_id: uid, name } = app.user;
  const keyCard = h("section", { class: "card" });
  const drawKey = async () => {
    const pem = await keystore.loadKeyPem(role, uid);
    clear(keyCard,
      h("h2", null, icon("key"), " Signing key"),
      h("p", { class: "muted" }, role === "student"
        ? "Used to sign your exam answers. The server only has your public key."
        : "Used to sign every administrative action (publish, release, add students…)."),
      h("p", null, "Status: ", pem ? (app.signingKey ? badge("Unlocked", "success") : badge("Stored, locked", "info"))
                                  : badge("Not on this device", "warn")),
      (await keystore.persistent()) ? null
        : h("p", { class: "notice notice-warn" }, icon("alert"), "This browser blocks IndexedDB, so keys last only until the tab closes."),
      h("div", { class: "btn-row" },
        h("button", { class: "btn", type: "button", onclick: async () => { if (await importKeyFile().catch(handleError)) drawKey(); } },
          icon("upload"), pem ? "Replace with key file…" : "Import key file…"),
        pem && h("button", { class: "btn", type: "button", onclick: () => download(`${uid}_key.pem`, pem, "application/x-pem-file") },
          icon("download"), "Download encrypted backup"),
        pem && h("button", { class: "btn btn-ghost-danger", type: "button", onclick: async () => {
          if (!await confirmDialog("Remove key from this device?",
            "You will need your key file to sign anything from this browser again. Make sure you have a backup.",
            { confirmLabel: "Remove key", danger: true })) return;
          await keystore.deleteKey(role, uid);
          app.signingKey = null;
          renderHeader();
          drawKey();
        } }, icon("trash"), "Remove from this device")));
  };
  await drawKey();

  const current = h("input", { type: "password", autocomplete: "current-password", required: true });
  const pw = passwordFields(() => uid);
  const error = h("p", { class: "form-error", role: "alert" });
  const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Change password");
  const form = h("form", { class: "card", novalidate: true, onsubmit: (ev) => {
    ev.preventDefault();
    error.textContent = "";
    const problem = pw.problem();
    if (!current.value) { error.textContent = "Enter your current password."; return; }
    if (problem) { error.textContent = problem; return; }
    busy(submit, async () => {
      try {
        const pem = await keystore.loadKeyPem(role, uid);
        let pkcs8 = null;
        if (pem) {
          try { pkcs8 = await decryptPkcs8(pem, current.value); } catch { /* key uses another password */ }
        }
        await app.client.call("CHANGE_PASSWORD", { old_password: current.value, new_password: pw.value() });
        if (pkcs8) {
          await keystore.saveKeyPem(role, uid, await encryptPkcs8(pkcs8, pw.value()));
          pkcs8.fill(0);
        }
        toast(pkcs8 ? "Password changed. Your stored key is now encrypted with the new password."
                    : "Password changed.", "success");
        form.reset();
        drawKey();
      } catch (exc) {
        if (exc instanceof ApiError && !exc.sessionLost) error.textContent = describeError(exc);
        else handleError(exc);
      }
    });
  } },
    h("h2", null, icon("lock"), " Change password"),
    h("p", { class: "muted" }, "Your stored signing key is re-encrypted with the new password."),
    field("Current password", current), ...pw.nodes, error, h("div", { class: "btn-row" }, submit));

  return h("div", { class: "page" },
    h("header", { class: "page-head" }, h("div", null, h("h1", null, "Account"),
      h("p", { class: "muted" }, `${name} · ${uid} · ${role === "admin" ? "Examiner" : "Student"}`))),
    h("div", { class: "grid-2" }, keyCard, form));
}

// --- offline verification of receipts, results and exports ----------------------------------

async function verifyView() {
  const out = h("div", { class: "verify-out" });
  const choose = h("button", { class: "btn btn-primary", type: "button", onclick: async () => {
    const file = await pickFile(".json,application/json");
    if (file) clear(out, await verifyFile(file));
  } }, icon("upload"), "Choose a file…");
  const drop = h("div", { class: "dropzone" }, icon("file", "icon icon-lg"),
    h("p", null, "Drop a receipt, result or results export here, or"), choose);
  drop.addEventListener("dragover", (ev) => { ev.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", async (ev) => {
    ev.preventDefault();
    drop.classList.remove("over");
    const f = ev.dataTransfer.files[0];
    if (f) clear(out, await verifyFile({ name: f.name, text: await f.text() }));
  });
  return h("div", { class: "page narrow" },
    h("header", { class: "page-head" }, h("div", null, h("h1", null, "Verify a signed file"),
      h("p", { class: "muted" }, "Checked entirely in your browser against the exam server's pinned public key. Nothing is uploaded."))),
    drop, out);
}

async function verifyFile(file) {
  let data;
  try { data = JSON.parse(file.text); } catch {
    return h("div", { class: "notice notice-error" }, icon("x"), `${file.name} is not valid JSON.`);
  }
  const kind = classifyFile(data);
  const head = (ok, title) => h("div", { class: `verdict ${ok ? "ok" : "bad"}` },
    icon(ok ? "shield" : "alert", "icon icon-lg"), h("div", null, h("h2", null, title), h("p", null, file.name)));
  try {
    if (kind === "receipt") {
      const checks = await verifyReceiptFile(app.server, data);
      const ok = checks.every(([, v]) => v), b = data.signed_receipt.body;
      return h("div", { class: "card" }, head(ok, ok ? "Authentic submission receipt" : "Receipt does NOT match"),
        checklist(checks), kv([["Student", b.student_id], ["Exam", b.exam_id], ["Received", fmtTime(b.received_at)],
                                ["Answers", String(Object.keys(data.submission.answers).length)],
                                ["Submission hash", h("code", null, b.submission_hash)]]));
    }
    if (kind === "result") {
      const b = await verifySigned(app.server, data);
      return h("div", { class: "card" }, head(true, "Authentic result"), checklist([["Signed by the exam server", true]]),
        kv([["Student", b.student_id], ["Exam", b.exam_id], ["Score", `${b.score} / ${b.total} (${b.percentage}%)`],
            ["Issued", fmtTime(b.issued_at)]]));
    }
    if (kind === "export") {
      const b = await verifySigned(app.server, data);
      return h("div", { class: "card" }, head(true, "Authentic results export"), checklist([["Signed by the exam server", true]]),
        kv([["Exam", `${b.title} (${b.exam_id})`], ["Generated", fmtTime(b.generated_at)], ["For", b.generated_for],
            ["Results", String(b.results.length)], ["No submission", b.no_submission.join(", ") || "none"]]));
    }
  } catch (exc) {
    return h("div", { class: "card" }, head(false, "Verification FAILED"),
      checklist([["Signed by the exam server", false]]), h("p", { class: "muted" }, exc.message));
  }
  return h("div", { class: "notice notice-error" }, icon("x"), "Not a receipt, result or results export file.");
}

export function kv(rows) {
  return h("dl", { class: "kv" }, rows.map(([k, v]) => h("div", { class: "kv-row" }, h("dt", null, k), h("dd", null, v))));
}

// --- boot -------------------------------------------------------------------------------

async function boot() {
  try {
    app.server = await importServerKey(CONFIG.serverPublicKeyPem);
  } catch (exc) {
    clear(main(), emptyState("Configuration error", `Cannot load the pinned server key: ${exc.message}`, "alert"));
    return;
  }
  // Sanity check only: the pin comes from /config.js, never from the API response.
  fetch(`${CONFIG.apiBase}/api/v1/info`, { cache: "no-store", credentials: "omit" })
    .then((r) => r.json())
    .then((info) => {
      if (info.server_key_fingerprint !== app.server.fingerprint)
        toast("The API reports a different server key than the pinned one. Handshakes will fail.", "error", 15000);
    })
    .catch(() => {});
  await resume();
  window.addEventListener("hashchange", render);
  render();
}

boot();
