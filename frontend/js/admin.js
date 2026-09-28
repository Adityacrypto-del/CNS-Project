// Examiner console. Reads are plain requests; every state change is an ADMIN_ACTION signed
// with the examiner's own RSA key (see ExamClient.adminAction).

import { app, Cancelled, describeError, go, handleError, kv, requireKey } from "./app.js";
import {
  badge, busy, checklist, clear, confirmDialog, download, emptyState, field, fmtRelative, fmtTime,
  h, icon, modal, pickFile, toast,
} from "./dom.js";

// Runs a signed examiner action; returns the result, or null if cancelled or failed.
async function act(op, params, { success } = {}) {
  try {
    const key = await requireKey("sign this action");
    const r = await app.client.adminAction(op, params, key);
    if (success) toast(typeof success === "function" ? success(r) : success, "success");
    return r;
  } catch (exc) {
    if (!(exc instanceof Cancelled)) handleError(exc);
    return null;
  }
}

function pageHead(title, subtitle, ...actions) {
  return h("header", { class: "page-head" },
    h("div", null, h("h1", null, title), subtitle && h("p", { class: "muted" }, subtitle)),
    actions.length && h("div", { class: "btn-row" }, actions));
}

const table = (headers, rows, cls = "") =>
  h("div", { class: "table-wrap" }, h("table", { class: `table ${cls}` },
    h("thead", null, h("tr", null, headers.map((x) => h("th", { scope: "col" }, x)))),
    h("tbody", null, rows)));

const shortHash = (hash) => h("code", { title: hash }, `${hash.slice(0, 12)}…`);

const EXAM_STATUS = { draft: ["Draft", "neutral"], published: ["Published", "success"], closed: ["Closed", "info"] };

function examStatus(e) {
  const [label, kind] = EXAM_STATUS[e.status] || [e.status, "neutral"];
  return [badge(label, kind), e.results_released && badge("Results released", "accent")];
}

// Lifecycle buttons for an exam, in the order the state machine allows.
function lifecycleButtons(e, done) {
  const btn = (label, op, confirmText, kind = "", success) =>
    h("button", { class: `btn btn-sm ${kind}`, type: "button", onclick: async (ev) => {
      const button = ev.currentTarget;   // reset to null once the handler awaits
      if (confirmText && !await confirmDialog(`${label}: ${e.exam_id}?`, confirmText, { confirmLabel: label })) return;
      await busy(button, async () => {
        if (await act(op, { exam_id: e.exam_id }, { success })) done();
      });
    } }, label);
  const out = [];
  if (e.status === "draft")
    out.push(btn("Publish", "PUBLISH_EXAM", "Students will see the exam and can start it once its window opens. Questions can no longer be changed.",
                 "btn-primary", `${e.exam_id} published.`));
  if (e.status === "published")
    out.push(btn("Close", "CLOSE_EXAM", "No new attempts or submissions will be accepted.", "", `${e.exam_id} closed.`));
  if (e.status === "closed" && !e.results_released)
    out.push(btn("Release results", "RELEASE_RESULTS", "Students can then fetch their signed results. This cannot be undone.",
                 "btn-primary", `Results for ${e.exam_id} released.`));
  return out;
}

// --- exams -------------------------------------------------------------------------------------

async function examsView() {
  const { exams } = await app.client.call("ADMIN_LIST_EXAMS");
  const rows = exams.map((e) => h("tr", null,
    h("td", null, h("a", { class: "strong", href: `#/exam-detail/${encodeURIComponent(e.exam_id)}` }, e.title),
      h("div", { class: "muted small" }, h("code", null, e.exam_id), ` · ${e.questions} questions · ${e.duration_minutes} min`)),
    h("td", null, h("div", { class: "badges" }, examStatus(e))),
    h("td", { class: "small" }, fmtTime(e.opens_at), h("div", { class: "muted" }, `to ${fmtTime(e.closes_at)}`)),
    h("td", { class: "num" }, `${e.submitted} / ${e.started}`),
    h("td", null, h("div", { class: "btn-row nowrap" },
      lifecycleButtons(e, () => go("admin")),
      h("a", { class: "btn btn-sm", href: `#/submissions/${encodeURIComponent(e.exam_id)}` }, "Submissions")))));
  return h("div", { class: "page wide" },
    pageHead("Exams", "Create, publish and grade exams. Every change is signed with your key.",
      h("button", { class: "btn", type: "button", onclick: () => go("admin") }, icon("refresh"), "Refresh"),
      h("a", { class: "btn btn-primary", href: "#/new-exam" }, icon("plus"), "New exam")),
    exams.length ? table(["Exam", "Status", "Window", "Submitted / started", ""], rows)
                 : emptyState("No exams yet", "Create your first exam to get started.", "clipboard"));
}

async function examDetailView(examId) {
  const { exam, answer_key: answerKey } = await app.client.call("ADMIN_GET_EXAM", { exam_id: examId });
  const total = exam.questions.reduce((n, q) => n + q.marks, 0);
  return h("div", { class: "page" },
    h("a", { class: "back", href: "#/admin" }, icon("arrowLeft"), "All exams"),
    pageHead(exam.title, exam.description,
      ...lifecycleButtons(exam, () => go(`exam-detail/${encodeURIComponent(examId)}`)),
      h("a", { class: "btn", href: `#/submissions/${encodeURIComponent(examId)}` }, "Submissions")),
    h("section", { class: "card" },
      h("div", { class: "badges" }, examStatus(exam)),
      kv([["Exam ID", h("code", null, exam.exam_id)], ["Duration", `${exam.duration_minutes} minutes`],
          ["Opens", `${fmtTime(exam.opens_at)} (${fmtRelative(exam.opens_at)})`],
          ["Closes", `${fmtTime(exam.closes_at)} (${fmtRelative(exam.closes_at)})`],
          ["Questions", `${exam.questions.length} (${total} marks)`], ["Created by", exam.created_by || "–"]])),
    h("h2", { class: "section-title" }, "Questions and answer key"),
    h("p", { class: "muted small" }, "The answer key is stored encrypted on the server and is never sent to students."),
    exam.questions.map((q, i) => h("section", { class: "card question readonly" },
      h("div", { class: "q-head" }, h("span", { class: "q-num" }, `${i + 1}. ${q.id}`),
        h("span", { class: "muted small" }, `${q.marks} mark${q.marks === 1 ? "" : "s"}`)),
      h("p", { class: "q-text" }, q.text),
      h("div", { class: "options" }, Object.entries(q.options).map(([k, text]) =>
        h("div", { class: `option ${answerKey?.[q.id] === k ? "correct" : ""}` },
          h("span", { class: "option-key" }, k), h("span", { class: "option-text" }, text),
          answerKey?.[q.id] === k && badge("Correct", "success")))))));
}

// --- exam builder ----------------------------------------------------------------------------

const EXAM_ID_RE = /^[A-Z0-9][A-Z0-9-]{2,39}$/;

// Same relative times as the CLI: "now", "+30m", "+2h", "+7d", ISO dates or epoch seconds.
export function parseTime(value, now = Math.floor(Date.now() / 1000)) {
  if (Number.isInteger(value)) return value;
  const s = String(value).trim();
  if (s === "now") return now;
  const m = /^\+(\d+)([mhd])$/.exec(s);
  if (m) return now + Number(m[1]) * { m: 60, h: 3600, d: 86400 }[m[2]];
  if (/^\d+$/.test(s)) return Number(s);
  const t = Date.parse(s);
  if (Number.isNaN(t)) throw new Error(`cannot understand the time “${s}”`);
  return Math.floor(t / 1000);
}

const toLocalInput = (ts) => {
  const d = new Date(ts * 1000);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 16);
};
const fromLocalInput = (v) => Math.floor(new Date(v).getTime() / 1000);

function blankQuestion(n) {
  return { id: `Q${n}`, text: "", options: [["A", ""], ["B", ""], ["C", ""], ["D", ""]], answer: "", marks: 1 };
}

function validateDraft(d) {
  const errors = [];
  if (!EXAM_ID_RE.test(d.exam_id)) errors.push("Exam ID: 3–40 characters of A–Z, 0–9 and “-”, starting with a letter or digit.");
  if (!d.title.trim()) errors.push("Title is required.");
  if (!(Number.isInteger(d.duration) && d.duration >= 1 && d.duration <= 600)) errors.push("Duration must be 1–600 minutes.");
  if (!(d.opens < d.closes)) errors.push("The exam must open before it closes.");
  if (!d.questions.length) errors.push("Add at least one question.");
  const ids = new Set();
  d.questions.forEach((q, i) => {
    const n = `Question ${i + 1}`;
    if (!q.id.trim() || ids.has(q.id)) errors.push(`${n}: the ID is empty or duplicated.`);
    ids.add(q.id);
    if (!q.text.trim()) errors.push(`${n}: the question text is empty.`);
    const keys = q.options.map(([k]) => k);
    if (q.options.length < 2 || q.options.some(([k, t]) => !k.trim() || !t.trim()) || new Set(keys).size !== keys.length)
      errors.push(`${n}: needs 2–8 options, each with a unique label and text.`);
    if (!keys.includes(q.answer)) errors.push(`${n}: choose the correct answer.`);
    if (!(Number.isInteger(q.marks) && q.marks >= 1 && q.marks <= 100)) errors.push(`${n}: marks must be 1–100.`);
  });
  return errors;
}

function toPayload(d) {
  return {
    exam: {
      exam_id: d.exam_id, title: d.title.trim(), description: d.description.trim(),
      duration_minutes: d.duration, opens_at: d.opens, closes_at: d.closes,
      questions: d.questions.map((q) => ({ id: q.id.trim(), text: q.text.trim(),
        options: Object.fromEntries(q.options.map(([k, t]) => [k.trim(), t.trim()])), marks: q.marks })),
    },
    answer_key: Object.fromEntries(d.questions.map((q) => [q.id.trim(), q.answer])),
  };
}

function fromFile(json) {
  const exam = json.exam || json, key = json.answer_key || {};
  const now = Math.floor(Date.now() / 1000);
  return {
    exam_id: exam.exam_id || "", title: exam.title || "", description: exam.description || "",
    duration: Number(exam.duration_minutes) || 30,
    opens: parseTime(exam.opens_at ?? "now", now), closes: parseTime(exam.closes_at ?? "+7d", now),
    questions: (exam.questions || []).map((q, i) => ({
      id: q.id || `Q${i + 1}`, text: q.text || "", options: Object.entries(q.options || {}),
      answer: key[q.id] || "", marks: Number(q.marks ?? 1),
    })),
  };
}

async function newExamView() {
  const now = Math.floor(Date.now() / 1000);
  let d = { exam_id: "", title: "", description: "", duration: 30, opens: now - (now % 300) + 300,
            closes: now - (now % 300) + 300 + 7 * 86400, questions: [blankQuestion(1)] };
  const root = h("div", { class: "page" });
  const errorsBox = h("div", { role: "alert" });

  const draw = () => {
    const input = (value, onInput, attrs = {}) =>
      h("input", { value, ...attrs, oninput: (ev) => onInput(ev.target.value) });
    const questionCards = d.questions.map((q, qi) => {
      const optionRows = q.options.map(([k, t], oi) => h("div", { class: "opt-row" },
        h("input", { type: "radio", name: `answer-${qi}`, checked: q.answer === k && k !== "", title: "Correct answer",
                     "aria-label": `Option ${k} is correct`, onchange: () => { q.answer = q.options[oi][0]; } }),
        input(k, (v) => { if (q.answer === q.options[oi][0]) q.answer = v; q.options[oi][0] = v; },
              { class: "opt-key", maxlength: 4, "aria-label": "Option label" }),
        input(t, (v) => { q.options[oi][1] = v; }, { class: "opt-text", placeholder: `Option ${k}`, "aria-label": `Option ${k} text` }),
        h("button", { class: "icon-btn", type: "button", title: "Remove option", "aria-label": "Remove option",
                      disabled: q.options.length <= 2, onclick: () => {
                        if (q.answer === q.options[oi][0]) q.answer = "";
                        q.options.splice(oi, 1);
                        draw();
                      } }, icon("x"))));
      return h("section", { class: "card q-edit" },
        h("div", { class: "q-edit-head" },
          h("span", { class: "q-num" }, `Question ${qi + 1}`),
          h("label", { class: "inline" }, "ID ", input(q.id, (v) => { q.id = v.trim(); }, { class: "small-input" })),
          h("label", { class: "inline" }, "Marks ", input(String(q.marks), (v) => { q.marks = Number(v); },
            { type: "number", min: 1, max: 100, class: "small-input" })),
          h("button", { class: "icon-btn", type: "button", title: "Delete question", "aria-label": "Delete question",
                        disabled: d.questions.length <= 1, onclick: () => { d.questions.splice(qi, 1); draw(); } }, icon("trash"))),
        h("textarea", { rows: 2, placeholder: "Question text", "aria-label": "Question text",
                        oninput: (ev) => { q.text = ev.target.value; } }, q.text),
        h("div", { class: "opt-list" }, h("p", { class: "muted small" }, "Select the correct answer:"), optionRows),
        q.options.length < 8 && h("button", { class: "link-btn", type: "button", onclick: () => {
          const used = new Set(q.options.map(([k]) => k));
          const next = "ABCDEFGH".split("").find((c) => !used.has(c)) || String(q.options.length + 1);
          q.options.push([next, ""]);
          draw();
        } }, icon("plus"), "Add option"));
    });

    const save = async (publish, button) => {
      const errors = validateDraft(d);
      clear(errorsBox, errors.length && h("div", { class: "notice notice-error" }, icon("alert"),
        h("ul", null, errors.map((e) => h("li", null, e)))));
      if (errors.length) { errorsBox.scrollIntoView({ behavior: "smooth", block: "center" }); return; }
      await busy(button, async () => {
        const created = await act("CREATE_EXAM", toPayload(d));
        if (!created) return;
        if (publish && !await act("PUBLISH_EXAM", { exam_id: d.exam_id })) { go(`exam-detail/${encodeURIComponent(d.exam_id)}`); return; }
        toast(`${d.exam_id} ${publish ? "created and published" : "saved as a draft"}.`, "success");
        go(`exam-detail/${encodeURIComponent(d.exam_id)}`);
      });
    };
    const saveDraft = h("button", { class: "btn", type: "button", onclick: (ev) => save(false, ev.currentTarget) }, "Save as draft");
    const savePublish = h("button", { class: "btn btn-primary", type: "button", onclick: (ev) => save(true, ev.currentTarget) },
                          icon("key"), "Save & publish");

    clear(root,
      h("a", { class: "back", href: "#/admin" }, icon("arrowLeft"), "All exams"),
      pageHead("New exam", "Build the paper and its answer key. Both are stored encrypted; only the paper is sent to students.",
        h("button", { class: "btn", type: "button", onclick: async () => {
          const file = await pickFile(".json,application/json");
          if (!file) return;
          try { d = fromFile(JSON.parse(file.text)); draw(); toast(`Loaded ${file.name}.`, "success"); } catch (exc) {
            toast(`Cannot load ${file.name}: ${exc.message}`, "error");
          }
        } }, icon("upload"), "Import JSON")),
      h("section", { class: "card form-grid" },
        field("Exam ID", input(d.exam_id, (v) => { d.exam_id = v.toUpperCase(); }, { class: "mono upper", placeholder: "CNS-QUIZ-3", autocapitalize: "characters" }),
              "Capital letters, digits and dashes."),
        field("Title", input(d.title, (v) => { d.title = v; }, { placeholder: "Quiz 3 – Hash functions" })),
        h("label", { class: "field span-2" }, h("span", null, "Description"),
          h("textarea", { rows: 2, placeholder: "Instructions shown to students", oninput: (ev) => { d.description = ev.target.value; } }, d.description)),
        field("Duration (minutes)", input(String(d.duration), (v) => { d.duration = Number(v); }, { type: "number", min: 1, max: 600 })),
        h("div"),
        field("Opens", input(toLocalInput(d.opens), (v) => { d.opens = fromLocalInput(v); }, { type: "datetime-local" })),
        field("Closes", input(toLocalInput(d.closes), (v) => { d.closes = fromLocalInput(v); }, { type: "datetime-local" }))),
      h("h2", { class: "section-title" }, `Questions (${d.questions.length})`),
      questionCards,
      h("button", { class: "btn btn-dashed", type: "button", onclick: () => {
        d.questions.push(blankQuestion(d.questions.length + 1));
        draw();
      } }, icon("plus"), "Add question"),
      errorsBox,
      h("div", { class: "form-actions" }, saveDraft, savePublish));
  };
  draw();
  return root;
}

// --- submissions ----------------------------------------------------------------------------------

async function submissionsView(examId) {
  const [{ submissions, not_submitted: notSubmitted }, { exam }] = await Promise.all([
    app.client.call("ADMIN_LIST_SUBMISSIONS", { exam_id: examId }),
    app.client.call("ADMIN_GET_EXAM", { exam_id: examId }),
  ]);
  const avg = submissions.length ? submissions.reduce((n, s) => n + s.score / s.total, 0) / submissions.length : 0;
  const rows = submissions.map((s) => h("tr", null,
    h("td", null, h("strong", null, s.student_id)),
    h("td", { class: "num" }, `${s.score} / ${s.total}`),
    h("td", { class: "small" }, fmtTime(s.received_at)),
    h("td", null, shortHash(s.submission_hash)),
    h("td", null, h("button", { class: "btn btn-sm", type: "button", onclick: (ev) =>
      busy(ev.currentTarget, () => showVerification(examId, s.student_id)) }, icon("shield"), "Verify signature"))));
  return h("div", { class: "page wide" },
    h("a", { class: "back", href: "#/admin" }, icon("arrowLeft"), "All exams"),
    pageHead(`Submissions: ${exam.title}`, examId,
      h("button", { class: "btn", type: "button", onclick: (ev) => busy(ev.currentTarget, () => exportResults(examId)) },
        icon("download"), "Export signed results")),
    h("div", { class: "stats" },
      stat("Submitted", String(submissions.length)),
      stat("Started, not submitted", String(notSubmitted.length)),
      stat("Average score", submissions.length ? `${(100 * avg).toFixed(1)}%` : "–"),
      stat("Status", examStatus(exam))),
    submissions.length ? table(["Student", "Score", "Received", "Submission hash", ""], rows)
                       : emptyState("No submissions yet", "Signed submissions will appear here.", "clipboard"),
    notSubmitted.length > 0 && h("p", { class: "muted" }, "Started but not submitted: ", notSubmitted.join(", ")));
}

const stat = (label, value) => h("div", { class: "stat card" }, h("span", { class: "muted small" }, label), h("strong", null, value));

async function showVerification(examId, studentId) {
  let v;
  try { v = await app.client.verifySubmission(examId, studentId); } catch (exc) { handleError(exc); return; }
  const sub = v.record.submission;
  await modal({
    title: `Submission by ${studentId}`, wide: true,
    body: [
      h("div", { class: `verdict ${v.verified ? "ok" : "bad"}` }, icon(v.verified ? "shield" : "alert", "icon icon-lg"),
        h("div", null, h("h3", null, v.verified ? "Non-repudiable" : "Verification FAILED"),
          h("p", null, v.verified ? "Only the holder of this student's private key could have produced this submission. Checked in your browser, independently of the server's own verdict."
                                  : "This submission does not verify. Treat it as tampered with."))),
      checklist(v.checks),
      kv([["Student key fingerprint", h("code", null, v.keyFingerprint)], ["Submitted (client clock)", fmtTime(sub.submitted_at)],
          ["Received (server clock)", fmtTime(v.record.received_at)], ["Paper hash", h("code", null, sub.exam_hash)],
          ["Answers", Object.entries(sub.answers).map(([q, a]) => `${q}: ${a}`).join(", ") || "none"]]),
    ],
    actions: [{ label: "Close", value: null }],
  });
}

// CSV cells are escaped, and formula-like values neutralised so spreadsheets do not run them.
function csvCell(v) {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

async function exportResults(examId) {
  const key = await requireKey("sign the export request").catch((exc) => { if (!(exc instanceof Cancelled)) handleError(exc); });
  if (!key) return;
  let signed;
  try { signed = await app.client.exportResults(examId, key); } catch (exc) { handleError(exc); return; }
  const b = signed.body;
  const cols = ["student_id", "name", "score", "total", "percentage", "received_at", "submission_hash"];
  const csv = [cols.join(","), ...b.results.map((r) => cols.map((c) => csvCell(r[c])).join(","))].join("\r\n") + "\r\n";
  await modal({
    title: "Results export", body: [
      checklist([["Export signed by the exam server (verified in your browser)", true]]),
      kv([["Exam", `${b.title} (${b.exam_id})`], ["Results", String(b.results.length)],
          ["No submission", b.no_submission.join(", ") || "none"], ["Generated", fmtTime(b.generated_at)]]),
      h("p", { class: "muted small" }, "The JSON file is the signed original; anyone can verify it with “Verify” or ",
        h("code", null, "python -m secure_exam.admin verify-export FILE"), ". The CSV is an unsigned convenience copy."),
      h("div", { class: "btn-row" },
        h("button", { class: "btn btn-primary", type: "button", onclick: () =>
          download(`${examId}_results.json`, JSON.stringify(signed, null, 2)) }, icon("download"), "Signed JSON"),
        h("button", { class: "btn", type: "button", onclick: () => download(`${examId}_results.csv`, csv, "text/csv") },
          icon("download"), "CSV")),
    ],
    actions: [{ label: "Done", value: null }],
  });
}

// --- students ------------------------------------------------------------------------------------

async function studentsView() {
  const { students } = await app.client.call("ADMIN_LIST_STUDENTS");
  const reload = () => go("students");
  const statusBadge = { active: ["Active", "success"], pending: ["Pending enrollment", "warn"], disabled: ["Disabled", "danger"] };
  const rows = students.map((s) => {
    const [label, kind] = statusBadge[s.status] || [s.status, "neutral"];
    const actions = h("div", { class: "btn-row nowrap" });
    const add = (label, handler, cls = "") => actions.append(h("button", { class: `btn btn-sm ${cls}`, type: "button",
      onclick: (ev) => busy(ev.currentTarget, handler) }, label));
    if (s.locked_out) add("Unlock", async () => { if (await act("UNLOCK_ACCOUNT", { user_id: s.student_id }, { success: `${s.student_id} unlocked.` })) reload(); });
    if (s.status === "active")
      add("Disable", async () => {
        if (!await confirmDialog(`Disable ${s.student_id}?`, "They will not be able to sign in until re-enabled.", { confirmLabel: "Disable", danger: true })) return;
        if (await act("SET_STUDENT_STATUS", { student_id: s.student_id, status: "disabled" }, { success: `${s.student_id} disabled.` })) reload();
      });
    if (s.status === "disabled" && s.key_fingerprint)
      add("Enable", async () => { if (await act("SET_STUDENT_STATUS", { student_id: s.student_id, status: "active" }, { success: `${s.student_id} enabled.` })) reload(); });
    add(s.status === "pending" ? "New code" : "Reissue", async () => {
      if (!await confirmDialog(`Issue a new enrollment code for ${s.student_id}?`,
        s.status === "pending" ? "The previous code stops working."
          : "Use this when a student has lost their key. Their current key and password are revoked immediately; they must activate the account again.",
        { confirmLabel: "Issue new code", danger: s.status !== "pending" })) return;
      const r = await act("REISSUE_ENROLLMENT", { student_id: s.student_id });
      if (r) { await showCode(r, s.name); reload(); }
    }, s.status === "pending" ? "" : "btn-ghost-danger");
    return h("tr", null,
      h("td", null, h("strong", null, s.student_id)),
      h("td", null, s.name, s.email && h("div", { class: "muted small" }, s.email)),
      h("td", null, h("div", { class: "badges" }, badge(label, kind), s.locked_out && badge("Locked out", "danger"))),
      h("td", null, s.key_fingerprint ? h("code", { title: "SHA-256 of the registered public key" }, `${s.key_fingerprint.slice(0, 16)}…`)
                                      : h("span", { class: "muted" }, "–")),
      h("td", null, actions));
  });
  return h("div", { class: "page wide" },
    pageHead("Students", "Register students and manage their access. Students create their own keys when they activate.",
      h("button", { class: "btn btn-primary", type: "button", onclick: addStudent }, icon("plus"), "Add student")),
    students.length ? table(["ID", "Name", "Status", "Registered key", ""], rows)
                    : emptyState("No students", "Add students to issue enrollment codes.", "users"));
}

async function addStudent() {
  const sid = h("input", { required: true, spellcheck: "false", autocapitalize: "off", placeholder: "S2001" });
  const name = h("input", { required: true, placeholder: "Full name" });
  const email = h("input", { type: "email", placeholder: "optional" });
  const error = h("p", { class: "form-error", role: "alert" });
  let result = null;
  await modal({
    title: "Add student",
    body: [field("Student ID", sid, "2–32 characters: letters, digits, _ and -"), field("Name", name), field("Email", email), error],
    actions: [{ label: "Cancel", value: null }, { label: "Add & create code", kind: "primary", value: "ok", submit: true }],
    onAction: async (v) => {
      if (v !== "ok") return true;
      error.textContent = "";
      if (!/^[A-Za-z0-9_-]{2,32}$/.test(sid.value.trim())) { error.textContent = "Invalid student ID."; return false; }
      if (!name.value.trim()) { error.textContent = "Name is required."; return false; }
      try {
        const key = await requireKey("sign this action");
        result = await app.client.adminAction("ADD_STUDENT",
          { student_id: sid.value.trim(), name: name.value.trim(), email: email.value.trim() }, key);
        return true;
      } catch (exc) {
        if (exc instanceof Cancelled) return false;
        if (exc.sessionLost) { handleError(exc); return true; }
        error.textContent = describeError(exc);
        return false;
      }
    },
  });
  if (result) { await showCode(result, name.value.trim()); go("students"); }
}

async function showCode(r, name) {
  const code = h("div", { class: "code-display mono" }, r.enrollment_code);
  await modal({
    title: "Enrollment code", body: [
      h("p", null, `Give this code to ${name || r.student_id} (${r.student_id}) through a separate channel, such as in person or by official email.`),
      code,
      h("button", { class: "btn btn-sm", type: "button", onclick: async () => {
        try { await navigator.clipboard.writeText(r.enrollment_code); toast("Code copied.", "success"); } catch { toast("Copy failed. Select the code instead.", "error"); }
      } }, icon("copy"), "Copy"),
      h("p", { class: "muted small" }, `It works once and expires ${fmtTime(r.expires_at)}. Only its hash is stored, so it cannot be shown again.`),
    ],
    actions: [{ label: "Done", kind: "primary", value: null }], dismissable: false,
  });
}

// --- audit log ----------------------------------------------------------------------------------

const DANGER_EVENTS = /TAMPER|REPLAY|VIOLATION|FAILED|BAD_SIGNATURE|REJECTED|LOCK/;

async function auditView(limitArg) {
  const limit = Number(limitArg) || 100;
  const { verified_entries: verified, integrity_error: integrityError, entries } =
    await app.client.call("ADMIN_AUDIT", { limit });
  const filter = h("input", { type: "search", placeholder: "Filter events…", "aria-label": "Filter events" });
  const onlyAlerts = h("input", { type: "checkbox" });
  const tbody = h("tbody");
  const drawRows = () => {
    const q = filter.value.toLowerCase();
    clear(tbody, entries.slice().reverse()
      .filter((e) => (!onlyAlerts.checked || DANGER_EVENTS.test(e.event))
        && (!q || `${e.event} ${JSON.stringify(e.details)}`.toLowerCase().includes(q)))
      .map((e) => h("tr", { class: DANGER_EVENTS.test(e.event) ? "row-danger" : "" },
        h("td", { class: "small nowrap" }, new Date(e.ts * 1000).toLocaleString()),
        h("td", null, badge(e.event, DANGER_EVENTS.test(e.event) ? "danger" : e.event.startsWith("ADMIN") ? "accent" : "neutral")),
        h("td", null, h("div", { class: "details" }, Object.entries(e.details || {}).map(([k, v]) => {
          const text = typeof v === "string" ? v : JSON.stringify(v);
          return h("span", { class: "detail", title: text }, h("b", null, k), " ", text.length > 48 ? `${text.slice(0, 48)}…` : text);
        }))))));
  };
  filter.addEventListener("input", drawRows);
  onlyAlerts.addEventListener("change", drawRows);
  drawRows();
  const limitSelect = h("select", { "aria-label": "Entries to show", onchange: (ev) => go(`audit/${ev.target.value}`) },
    [50, 100, 250, 1000].map((n) => h("option", { value: n, selected: n === limit }, `Last ${n}`)));
  return h("div", { class: "page wide" },
    pageHead("Audit log", "Append-only log: each entry is SHA-256 hash-chained to the previous one and HMAC-protected.",
      h("button", { class: "btn", type: "button", onclick: () => go(`audit/${limit}`) }, icon("refresh"), "Refresh")),
    h("div", { class: `verdict ${integrityError ? "bad" : "ok"}` },
      icon(integrityError ? "alert" : "shield", "icon icon-lg"),
      h("div", null, h("h3", null, integrityError ? "Audit log integrity FAILED" : "Audit log intact"),
        h("p", null, integrityError || `All ${verified} entries verified: hash chain unbroken and every HMAC valid.`))),
    h("div", { class: "toolbar" }, filter, h("label", { class: "inline" }, onlyAlerts, " Security events only"), limitSelect),
    h("div", { class: "table-wrap" }, h("table", { class: "table audit" },
      h("thead", null, h("tr", null, h("th", null, "Time"), h("th", null, "Event"), h("th", null, "Details"))), tbody)));
}

// --- system -----------------------------------------------------------------------------------------

async function systemView() {
  const rotate = h("button", { class: "btn", type: "button", onclick: async (ev) => {
    const button = ev.currentTarget;
    if (!await confirmDialog("Rotate the storage key?",
      "A new AES-256 key is generated, every database is re-encrypted under it, and the key is stored wrapped with the server's RSA key. Copies of the old key become useless.",
      { confirmLabel: "Rotate key" })) return;
    await busy(button, async () => {
      await act("ROTATE_STORAGE_KEY", {}, { success: (r) => `Storage key rotated; ${r.stores.length} databases re-encrypted.` });
    });
  } }, icon("refresh"), "Rotate storage key");
  const row = (a, b, c) => h("tr", null, h("td", null, h("strong", null, a)), h("td", null, b), h("td", { class: "muted small" }, c));
  return h("div", { class: "page wide" },
    pageHead("System", "Cryptographic configuration and key management."),
    h("div", { class: "grid-2" },
      h("section", { class: "card" },
        h("h2", null, icon("key"), " Storage encryption key"),
        h("p", { class: "muted" }, "All databases are encrypted at rest with AES-256-GCM. Rotate the key periodically, or at once if you suspect it leaked."),
        rotate),
      h("section", { class: "card" },
        h("h2", null, icon("shield"), " Pinned server key"),
        h("p", { class: "muted" }, "Browsers verify every handshake and signed object against this RSA-3072 key."),
        kv([["Fingerprint (SHA-256)", h("code", null, app.server.fingerprint)]]))),
    h("h2", { class: "section-title" }, "Protection layers"),
    h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", null, h("tr", null, h("th", null, "Layer"), h("th", null, "Mechanism"), h("th", null, "Objective"))),
      h("tbody", null,
        row("Transport", "TLS 1.3 only, private CA, HSTS and strict CSP", "Secure communication"),
        row("Key exchange", "RSA-OAEP key transport, RSA-PSS signed handshake, HKDF-SHA256", "Key management"),
        row("Messages", "AES-256-CBC + HMAC-SHA256, sequence numbers, 60 s freshness window", "Confidentiality, integrity"),
        row("Accounts", "PBKDF2-HMAC-SHA256 (600 000 rounds), lockout, one session per account", "Authentication"),
        row("Signatures", "RSA-PSS on papers, answers, receipts, results, exports and admin actions", "Non-repudiation"),
        row("Storage", "AES-256-GCM with RSA-wrapped, rotatable keys", "Confidentiality at rest"),
        row("Audit", "Hash-chained, HMAC-protected log of every security event", "Attack detection")))));
}

export const routes = {
  admin: examsView, "exam-detail": examDetailView, "new-exam": newExamView, submissions: submissionsView,
  students: studentsView, audit: auditView, system: systemView,
};
