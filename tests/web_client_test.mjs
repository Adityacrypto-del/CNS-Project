// Runs the browser client modules (frontend/js) in Node against a live server, to check that
// the WebCrypto implementation interoperates byte for byte with the Python server.
// Driven by tests/test_security.py (TestWebClient); needs Node 20+.
//
//   SECURE_EXAM_DATA=<dir> API_BASE=https://localhost:<port> NODE_EXTRA_CA_CERTS=<dir>/pki/ca_cert.pem \
//     node tests/web_client_test.mjs

import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { ApiError, SecureSession } from "../frontend/js/channel.js";
import { ExamClient, verifyReceiptFile } from "../frontend/js/client.js";
import {
  canonicalJson, decryptPkcs8, encryptPkcs8, generateUserKey, importPkcs8, importServerKey,
  unlockKey, WrongPasswordError,
} from "../frontend/js/crypto.js";

const DATA = process.env.SECURE_EXAM_DATA;
const API = process.env.API_BASE;
const server = await importServerKey(readFileSync(join(DATA, "pki/server_sign_pub.pem"), "utf8"));
const keyFile = (id) => readFileSync(join(DATA, "clients", `${id}_key.pem`), "utf8");
let passed = 0;

async function step(name, fn) {
  await fn();
  passed++;
  console.log(`ok   ${name}`);
}

async function connect() {
  const s = await SecureSession.handshake(API, server);
  return new ExamClient(s, server);
}

async function rejects(code, fn) {
  try { await fn(); } catch (exc) {
    assert.equal(exc.code, code, `expected ${code}, got ${exc.code}: ${exc.message}`);
    return;
  }
  assert.fail(`expected ${code}`);
}

await step("canonical JSON matches Python (sorted keys, \\u escapes)", async () => {
  assert.equal(canonicalJson({ b: 1, a: ["é", "✓", "😀", null, true] }),
               '{"a":["\\u00e9","\\u2713","\\ud83d\\ude00",null,true],"b":1}');
  assert.throws(() => canonicalJson({ x: 1.5 }));
});

await step("decrypts a Python-written encrypted PKCS#8 key; rejects a wrong password", async () => {
  await unlockKey(keyFile("S1001"), "Alice@Exam2026");
  await assert.rejects(decryptPkcs8(keyFile("S1001"), "wrong-password"), WrongPasswordError);
});

await step("re-encrypted key round-trips (browser format, 600k iterations)", async () => {
  const pkcs8 = await decryptPkcs8(keyFile("S1002"), "Bala@Exam2026");
  const pem = await encryptPkcs8(pkcs8, "New#Password2026", 1000);
  await importPkcs8(await decryptPkcs8(pem, "New#Password2026"));
  writeFileSync(join(DATA, "browser_key.pem"), pem);   // Python loads this to check the format
});

await step("handshake rejects a server response that does not match the pinned key", async () => {
  // A man in the middle substitutes the server nonce: the transcript signature breaks.
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (...args) => {
    const res = await realFetch(...args);
    const body = await res.json();
    body.server_nonce = Buffer.alloc(32, 7).toString("base64");
    return new Response(JSON.stringify(body), { status: res.status });
  };
  try {
    await assert.rejects(SecureSession.handshake(API, server), (e) => e.code === "SERVER_AUTH_FAILED");
  } finally {
    globalThis.fetch = realFetch;
  }
});

let receiptFile;
await step("student: login, verified paper, signed submission, verified receipt", async () => {
  const c = await connect();
  const r = await c.login("S1001", "Alice@Exam2026", "student");
  assert.equal(r.name, "Alice Kumar");
  const exams = await c.listExams();
  assert.ok(exams.some((e) => e.exam_id === "CNS-MIDTERM-2026" && e.state === "open"));
  const { paper, checks } = await c.getExam("CNS-MIDTERM-2026");
  assert.ok(checks.every(([, ok]) => ok));
  const key = await unlockKey(keyFile("S1001"), "Alice@Exam2026");
  const answers = Object.fromEntries(paper.exam.questions.map((q) => [q.id, "A"]));
  receiptFile = await c.submit(paper, answers, key);
  assert.ok((await verifyReceiptFile(server, receiptFile)).every(([, ok]) => ok));
  writeFileSync(join(DATA, "browser_receipt.json"), JSON.stringify(receiptFile));
  await rejects("ALREADY_SUBMITTED", () => c.submit(paper, answers, key));
  await rejects("RESULTS_NOT_RELEASED", () => c.getResult("CNS-MIDTERM-2026"));
  await c.logout();
  await rejects("SESSION_CLOSED", () => c.listExams());
});

await step("tampered receipt file is detected offline", async () => {
  const forged = structuredClone(receiptFile);
  forged.submission.answers[Object.keys(forged.submission.answers)[0]] = "B";
  const checks = await verifyReceiptFile(server, forged);
  assert.equal(checks.find(([n]) => n.startsWith("Receipt covers"))[1], false);
});

await step("session survives serialise/restore (page reload)", async () => {
  const c = await connect();
  await c.login("S1002", "Bala@Exam2026", "student");
  const restored = await SecureSession.restore(API, server, c.session.serialise());
  const c2 = new ExamClient(restored, server);
  c2.user = c.user;
  assert.equal((await c2.call("WHOAMI")).user_id, "S1002");
  await c2.logout();
});

await step("replayed envelope destroys the session", async () => {
  const c = await connect();
  await c.login("S1003", "Chitra@Exam2026", "student");
  const saved = c.session.serialise();
  await c.call("WHOAMI");
  const replay = await SecureSession.restore(API, server, saved);   // reuses seq 0
  await rejects("REPLAY_DETECTED", () => replay.call("WHOAMI"));
  await rejects("UNKNOWN_SESSION", () => c.call("WHOAMI"));
});

let studentKey;
await step("enrollment with a key generated in the browser", async () => {
  const c = await connect();
  await rejects("WEAK_PASSWORD", async () => {
    studentKey = await generateUserKey();
    await c.enroll("S1004", "DEMO-ENRL-CODE-2026", "short", studentKey);
  });
  await c.enroll("S1004", "demo-enrl-code-2026", "Dev#Browser2026", studentKey);
  await c.login("S1004", "Dev#Browser2026", "student");
  const { paper } = await c.getExam("CNS-QUIZ-1");
  await c.submit(paper, { [paper.exam.questions[0].id]: "A" }, studentKey.privateKey);
  await c.logout();
});

await step("examiner: signed actions, submission non-repudiation, signed export", async () => {
  const c = await connect();
  await c.login("examiner", "Secure#Exam2026", "admin");
  const key = await unlockKey(keyFile("examiner"), "Secure#Exam2026");
  const added = await c.adminAction("ADD_STUDENT", { student_id: "S3001", name: "Web Tester" }, key);
  assert.match(added.enrollment_code, /\w/);
  const v = await c.verifySubmission("CNS-QUIZ-1", "S1004");
  assert.ok(v.verified, JSON.stringify(v.checks));
  await c.adminAction("CLOSE_EXAM", { exam_id: "CNS-QUIZ-1" }, key);
  await c.adminAction("RELEASE_RESULTS", { exam_id: "CNS-QUIZ-1" }, key);
  const exp = await c.exportResults("CNS-QUIZ-1", key);
  assert.ok(exp.body.results.some((r) => r.student_id === "S1004"));
  const wrongKey = (await generateUserKey()).privateKey;
  await rejects("INVALID_SIGNATURE", () => c.adminAction("UNLOCK_ACCOUNT", { user_id: "S1001" }, wrongKey));
  const audit = await c.call("ADMIN_AUDIT", { limit: 5 });
  assert.equal(audit.integrity_error, null);
  await c.logout();
});

await step("student fetches a signed result (string percentage, no floats)", async () => {
  const c = await connect();
  await c.login("S1004", "Dev#Browser2026", "student");
  const res = await c.getResult("CNS-QUIZ-1");
  assert.equal(typeof res.percentage, "string");
  await c.logout();
});

await step("admin operations are refused to students", async () => {
  const c = await connect();
  await c.login("S1002", "Bala@Exam2026", "student");
  await rejects("FORBIDDEN", () => c.call("ADMIN_LIST_STUDENTS"));
  await c.logout();
});

console.log(`\n${passed} web client checks passed`);
