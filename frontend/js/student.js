// Student screens: exam list, taking an exam, the submission receipt and the signed result.

import { app, Cancelled, describeError, go, handleError, kv, onCleanup, requireKey } from "./app.js";
import { verifyReceiptFile } from "./client.js";
import {
  badge, busy, checklist, clear, confirmDialog, download, emptyState, fmtCountdown, fmtRelative,
  fmtTime, h, icon, spinner, toast,
} from "./dom.js";
import * as keystore from "./keystore.js";

const GRACE_SECONDS = 30;
const STATE_BADGES = {
  open: ["Open", "success"], in_progress: ["In progress", "warn"], submitted: ["Submitted", "info"],
  upcoming: ["Upcoming", "neutral"], missed: ["Missed", "danger"], closed: ["Closed", "neutral"],
};

// --- exam list -------------------------------------------------------------------------------

async function examsView() {
  const exams = await app.client.listExams();
  const refresh = h("button", { class: "btn", type: "button", onclick: () => go("exams") }, icon("refresh"), "Refresh");
  const list = exams.length
    ? h("div", { class: "exam-grid" }, await Promise.all(exams.map(examCard)))
    : emptyState("No exams yet", "Published exams will appear here.", "clipboard");
  return h("div", { class: "page" },
    h("header", { class: "page-head" },
      h("div", null, h("h1", null, `Hello, ${app.user.name.split(" ")[0]}`),
        h("p", { class: "muted" }, "Your exams. Each one can be attempted once; the timer starts when you open it.")),
      refresh),
    list);
}

async function examCard(e) {
  const [label, kind] = STATE_BADGES[e.state] || [e.state, "neutral"];
  const actions = h("div", { class: "card-actions" });
  if (e.state === "open")
    actions.append(h("button", { class: "btn btn-primary", type: "button", onclick: () => startExam(e) }, "Start exam"));
  else if (e.state === "in_progress")
    actions.append(h("a", { class: "btn btn-primary", href: `#/exam/${encodeURIComponent(e.exam_id)}` }, "Resume exam"));
  else if (e.state === "upcoming")
    actions.append(h("button", { class: "btn", type: "button", disabled: true }, `Opens ${fmtRelative(e.opens_at)}`));
  if (e.result_available)
    actions.append(h("a", { class: "btn btn-primary", href: `#/result/${encodeURIComponent(e.exam_id)}` }, "View result"));
  if (e.state === "submitted" && await keystore.loadReceipt(app.user.user_id, e.exam_id))
    actions.append(h("a", { class: "btn", href: `#/receipt/${encodeURIComponent(e.exam_id)}` }, icon("file"), "Receipt"));
  if (e.state === "submitted" && !e.result_available)
    actions.append(h("span", { class: "muted small" }, "Result not released yet"));

  return h("article", { class: `card exam-card state-${e.state}` },
    h("div", { class: "exam-card-head" }, badge(label, kind), h("code", { class: "muted small" }, e.exam_id)),
    h("h2", null, e.title),
    h("ul", { class: "meta" },
      h("li", null, icon("clock"), `${e.duration_minutes} minutes`),
      h("li", null, icon("activity"), e.state === "upcoming" ? `Opens ${fmtTime(e.opens_at)}` : `Closes ${fmtTime(e.closes_at)}`)),
    actions);
}

async function startExam(e) {
  const ok = await confirmDialog(`Start “${e.title}”?`,
    `The ${e.duration_minutes}-minute timer starts now and keeps running even if you close this page. You get one attempt. You will need your signing key to submit.`,
    { confirmLabel: "Start now" });
  if (ok) go(`exam/${encodeURIComponent(e.exam_id)}`);
}

// --- taking an exam ------------------------------------------------------------------------------

const draftKey = (examId) => `draft:${app.user.user_id}:${examId}`;

function loadDraft(examId) {
  try { return JSON.parse(sessionStorage.getItem(draftKey(examId)) || "{}"); } catch { return {}; }
}

function saveDraft(examId, answers) {
  try { sessionStorage.setItem(draftKey(examId), JSON.stringify(answers)); } catch { /* ignore */ }
}

async function examView(examId) {
  const { paper, checks } = await app.client.getExam(examId);
  const exam = paper.exam;
  const answers = loadDraft(examId);
  let submitted = false;

  const answeredCount = () => exam.questions.filter((q) => answers[q.id]).length;
  const progress = h("span", { class: "progress-text" });
  const bar = h("div", { class: "progress-bar" }, h("span"));
  const timer = h("div", { class: "timer", role: "timer", "aria-live": "off" }, icon("clock"), h("span"));
  const navGrid = h("nav", { class: "q-nav", "aria-label": "Questions" });
  const submitBtn = h("button", { class: "btn btn-primary", type: "button", onclick: () => submit(false) },
                      icon("key"), "Sign & submit");

  const updateProgress = () => {
    const n = answeredCount();
    progress.textContent = `${n} of ${exam.questions.length} answered`;
    bar.firstChild.style.width = `${(100 * n) / exam.questions.length}%`;
    exam.questions.forEach((q, i) => navGrid.children[i]?.classList.toggle("answered", !!answers[q.id]));
  };

  const questions = exam.questions.map((q, i) => {
    const name = `q-${i}`;
    const clearBtn = h("button", { class: "link-btn", type: "button", onclick: () => {
      delete answers[q.id];
      card.querySelectorAll("input").forEach((inp) => (inp.checked = false));
      saveDraft(examId, answers);
      updateProgress();
    } }, "Clear answer");
    const card = h("fieldset", { class: "card question", id: `question-${i + 1}` },
      h("legend", { class: "q-head" }, h("span", { class: "q-num" }, `Question ${i + 1}`),
        h("span", { class: "muted small" }, `${q.marks} mark${q.marks === 1 ? "" : "s"}`)),
      h("p", { class: "q-text" }, q.text),
      h("div", { class: "options" }, Object.entries(q.options).map(([key, text]) =>
        h("label", { class: "option" },
          h("input", { type: "radio", name, value: key, checked: answers[q.id] === key, onchange: () => {
            answers[q.id] = key;
            saveDraft(examId, answers);
            updateProgress();
          } }),
          h("span", { class: "option-key" }, key), h("span", { class: "option-text" }, text)))),
      h("div", { class: "q-foot" }, clearBtn));
    navGrid.append(h("a", { href: `#question-${i + 1}`, onclick: (ev) => {
      ev.preventDefault();
      card.scrollIntoView({ behavior: "smooth", block: "center" });
      card.querySelector("input")?.focus({ preventScroll: true });
    } }, String(i + 1)));
    return card;
  });

  async function submit(auto) {
    if (submitted) return;
    const now = Date.now() / 1000;
    if (now > paper.deadline + GRACE_SECONDS) {
      toast("The time for this exam has run out.", "error");
      return;
    }
    let key;
    try { key = await requireKey("sign your answers"); } catch (exc) {
      if (!(exc instanceof Cancelled)) handleError(exc);
      return;
    }
    if (!auto) {
      const missing = exam.questions.length - answeredCount();
      const ok = await confirmDialog("Submit your answers?",
        `${missing ? `${missing} question${missing === 1 ? " is" : "s are"} unanswered. ` : ""}Your answers will be signed with your private key. You cannot change them after submitting.`,
        { confirmLabel: "Sign & submit" });
      if (!ok) return;
    }
    await busy(submitBtn, async () => {
      try {
        const chosen = Object.fromEntries(exam.questions.filter((q) => answers[q.id]).map((q) => [q.id, answers[q.id]]));
        const receipt = await app.client.submit(paper, chosen, key);
        submitted = true;
        await keystore.saveReceipt(app.user.user_id, examId, receipt).catch(() => {});
        lastReceipt = receipt;
        try { sessionStorage.removeItem(draftKey(examId)); } catch { /* ignore */ }
        go(`receipt/${encodeURIComponent(examId)}`);
      } catch (exc) {
        handleError(exc);
      }
    });
  }

  // Countdown to the server-signed deadline, with automatic submission at zero.
  const tick = () => {
    const left = paper.deadline - Date.now() / 1000;
    timer.lastChild.textContent = left > 0 ? fmtCountdown(left) : "Time is up";
    timer.classList.toggle("warn", left <= 300 && left > 60);
    timer.classList.toggle("danger", left <= 60);
    if (left <= 0 && !submitted && !autoSubmitStarted) {
      autoSubmitStarted = true;
      toast("Time is up. Submitting your answers automatically.", "info");
      submit(true);
    }
  };
  let autoSubmitStarted = false;
  const interval = setInterval(tick, 1000);
  const beforeUnload = (ev) => { if (!submitted) { ev.preventDefault(); ev.returnValue = ""; } };
  window.addEventListener("beforeunload", beforeUnload);
  onCleanup(() => { clearInterval(interval); window.removeEventListener("beforeunload", beforeUnload); });

  const verified = h("details", { class: "verified" },
    h("summary", null, icon("shield"), h("span", null, "Verified paper: signed by the exam server and issued to you")),
    checklist(checks),
    kv([["Paper hash (SHA-256)", h("code", null, paper.exam_hash)], ["Started", fmtTime(paper.started_at)],
        ["Deadline", fmtTime(paper.deadline)]]));

  const page = h("div", { class: "page exam-page" },
    h("div", { class: "exam-bar" },
      h("div", { class: "exam-bar-title" }, h("h1", null, exam.title), h("span", { class: "muted small" }, exam.exam_id)),
      h("div", { class: "exam-bar-progress" }, progress, bar),
      timer, submitBtn),
    h("div", { class: "exam-layout" },
      h("div", { class: "exam-main" },
        exam.description && h("p", { class: "exam-desc" }, exam.description),
        verified, questions,
        h("div", { class: "exam-end card" },
          h("p", null, "Finished? Your answers are signed on this device before they are sent."),
          h("button", { class: "btn btn-primary", type: "button", onclick: () => submit(false) }, icon("key"), "Sign & submit"))),
      h("aside", { class: "exam-side" }, h("div", { class: "card sticky" },
        h("h2", { class: "small-title" }, "Questions"), navGrid,
        h("p", { class: "muted small" }, `${exam.total_marks} marks in total`)))));
  updateProgress();
  tick();
  return page;
}

// --- receipt -----------------------------------------------------------------------------------------

let lastReceipt = null;

async function receiptView(examId) {
  const receipt = (lastReceipt?.submission.exam_id === examId ? lastReceipt : null)
    || await keystore.loadReceipt(app.user.user_id, examId);
  if (!receipt) return emptyState("No receipt on this device", "Receipts are saved in the browser you submitted from.", "file");
  const checks = await verifyReceiptFile(app.server, receipt);
  const body = receipt.signed_receipt.body;
  const fresh = lastReceipt === receipt;
  return h("div", { class: "page narrow" },
    h("section", { class: "card receipt" },
      h("div", { class: "success-block" }, h("div", { class: "success-icon" }, icon("check")),
        h("h1", null, fresh ? "Submission received" : "Submission receipt"),
        h("p", { class: "muted" }, "The exam server signed this receipt for your exact answers. Keep it as proof of submission.")),
      checklist(checks),
      kv([["Exam", body.exam_id], ["Student", body.student_id], ["Received by server", fmtTime(body.received_at)],
          ["Questions answered", String(Object.keys(receipt.submission.answers).length)],
          ["Submission hash (SHA-256)", h("code", null, body.submission_hash)]]),
      h("div", { class: "btn-row" },
        h("button", { class: "btn btn-primary", type: "button", onclick: () =>
          download(`${body.student_id}_${body.exam_id}_receipt.json`, JSON.stringify(receipt, null, 2)) },
          icon("download"), "Download receipt"),
        h("a", { class: "btn", href: "#/exams" }, "Back to my exams")),
      h("p", { class: "muted small" }, "Anyone can check the file offline: open “Verify” in this app, or run ",
        h("code", null, "python -m secure_exam.client verify-receipt FILE"), ".")));
}

// --- result ----------------------------------------------------------------------------------------------

async function resultView(examId) {
  const result = await app.client.getResult(examId);
  const receipt = await keystore.loadReceipt(app.user.user_id, examId);
  const pct = Number(result.percentage);
  const checks = [["Result signed by the exam server (RSA-PSS)", true],
                  [`Issued to ${app.user.user_id} for ${examId}`, true]];
  if (receipt) checks.push(["Graded submission matches your receipt", receipt.signed_receipt.body.submission_hash === result.submission_hash]);
  const ring = h("div", { class: "score-ring" }, h("div", null, h("strong", null, `${result.score}/${result.total}`),
                                                 h("span", null, `${result.percentage}%`)));
  ring.style.setProperty("--pct", String(pct));
  return h("div", { class: "page narrow" },
    h("section", { class: "card result" },
      h("header", { class: "result-head" }, h("div", null, h("h1", null, "Your result"), h("p", { class: "muted" }, examId)), ring),
      checklist(checks),
      !receipt && h("p", { class: "muted small" }, "No receipt for this exam on this device, so the graded submission can't be compared with it."),
      kv([["Score", `${result.score} out of ${result.total}`], ["Percentage", `${result.percentage}%`],
          ["Issued", fmtTime(result.issued_at)], ["Submission hash", h("code", null, result.submission_hash)]]),
      h("div", { class: "btn-row" },
        h("button", { class: "btn", type: "button", onclick: async () => {
          const r = await app.client.call("GET_RESULT", { exam_id: examId }).catch(handleError);
          if (r) download(`${result.student_id}_${examId}_result.json`, JSON.stringify(r.result, null, 2));
        } }, icon("download"), "Download signed result"),
        h("a", { class: "btn", href: "#/exams" }, "Back to my exams"))));
}

export const routes = { exams: examsView, exam: examView, receipt: receiptView, result: resultView };
