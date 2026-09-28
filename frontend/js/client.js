// High-level exam operations on top of SecureSession. Every signed object from the server is
// verified here, before the UI ever sees it (mirrors ExamClient in secure_exam/client.py).

import {
  b64, b64d, canonicalBytes, importPublicKey, nowSeconds, randomBytes, sha256Hex, sign,
  verifySigned, verifyUser,
} from "./crypto.js";

export class ExamClient {
  constructor(session, server) {
    this.session = session;
    this.server = server;
    this.user = null;          // {user_id, role, name}
  }

  call(op, params) { return this.session.call(op, params); }

  async login(userId, password, role) {
    const r = await this.call("LOGIN", { user_id: userId, password, role });
    this.user = { user_id: r.user_id, role: r.role, name: r.name };
    return r;
  }

  async logout() {
    try { await this.call("LOGOUT"); } catch { /* the session may already be gone */ }
  }

  // Enrollment: prove possession of both the one-time code and the new private key.
  async enroll(studentId, code, password, key) {
    const proofBody = { student_id: studentId, public_key: key.publicPem, purpose: "enroll" };
    const proof = b64(await sign(key.privateKey, canonicalBytes(proofBody)));
    return this.call("ENROLL", { student_id: studentId, enrollment_code: code, password,
                                 public_key: key.publicPem, proof });
  }

  async listExams() { return (await this.call("LIST_EXAMS")).exams; }

  async getExam(examId) {
    const body = await verifySigned(this.server, (await this.call("GET_EXAM", { exam_id: examId })).paper);
    const hashOk = await sha256Hex(canonicalBytes(body.exam)) === body.exam_hash;
    const checks = [
      ["Paper signed by the exam server (RSA-PSS, pinned key)", true],
      ["SHA-256 of the paper matches the signed hash", hashOk],
      [`Issued to ${this.user.user_id}`, body.issued_to === this.user.user_id],
      [`Paper is ${examId}`, body.exam.exam_id === examId],
    ];
    if (!checks.every(([, ok]) => ok)) throw new Error("the exam paper failed verification");
    return { paper: body, checks };
  }

  async submit(paper, answers, privateKey) {
    const submission = {
      student_id: this.user.user_id, exam_id: paper.exam.exam_id, exam_hash: paper.exam_hash,
      answers, submitted_at: nowSeconds(), nonce: b64(randomBytes(16)),
    };
    const signature = b64(await sign(privateKey, canonicalBytes(submission)));
    const r = await this.call("SUBMIT", { submission, signature });
    const receipt = await verifySigned(this.server, r.receipt);
    if (receipt.submission_hash !== await sha256Hex(canonicalBytes(submission)))
      throw new Error("the receipt does not cover this submission");
    // Same layout as the CLI's receipt file, so `client verify-receipt` accepts it.
    return { submission, signature, signed_receipt: r.receipt };
  }

  async getResult(examId) {
    const result = await verifySigned(this.server,
                                      (await this.call("GET_RESULT", { exam_id: examId })).result);
    if (result.student_id !== this.user.user_id || result.exam_id !== examId)
      throw new Error("the result is for a different student or exam");
    return result;
  }

  // --- examiner ---------------------------------------------------------------------

  async adminAction(op, params, adminKey) {
    const action = { op, params, admin_id: this.user.user_id, ts: nowSeconds(),
                     nonce: b64(randomBytes(16)) };
    const signature = b64(await sign(adminKey, canonicalBytes(action)));
    return this.call("ADMIN_ACTION", { action, signature });
  }

  // Independent non-repudiation check, done in the examiner's browser (like
  // `admin submissions verify`): nothing here trusts the server's own verdict.
  async verifySubmission(examId, studentId) {
    const { record, student_public_key: pubPem } =
      await this.call("ADMIN_GET_SUBMISSION", { exam_id: examId, student_id: studentId });
    const sub = record.submission;
    const checks = [];
    let sigOk = false;
    try {
      sigOk = await verifyUser(await importPublicKey(pubPem), b64d(record.signature), canonicalBytes(sub));
    } catch { /* malformed key or signature */ }
    checks.push(["Student RSA-PSS signature over the submission", sigOk]);
    checks.push(["SHA-256(submission) matches the stored hash",
                 await sha256Hex(canonicalBytes(sub)) === record.submission_hash]);
    try {
      const receipt = await verifySigned(this.server, record.receipt);
      checks.push(["Server receipt signature", true]);
      checks.push(["Receipt covers this submission", receipt.submission_hash === record.submission_hash]);
    } catch {
      checks.push(["Server receipt signature", false]);
    }
    return { record, checks, verified: checks.every(([, ok]) => ok),
             keyFingerprint: (await sha256Hex(new TextEncoder().encode(pubPem))).slice(0, 32) };
  }

  async exportResults(examId, adminKey) {
    const r = await this.adminAction("EXPORT_RESULTS", { exam_id: examId }, adminKey);
    await verifySigned(this.server, r.export);
    return r.export;
  }
}

// Offline checks of files a user brings in (no session needed).
export async function verifyReceiptFile(server, data) {
  const receipt = await verifySigned(server, data.signed_receipt);
  const subHash = await sha256Hex(canonicalBytes(data.submission));
  return [
    ["Receipt signed by the exam server", true],
    ["Receipt covers this submission", receipt.submission_hash === subHash],
    ["Student and exam match the receipt", receipt.student_id === data.submission.student_id
      && receipt.exam_id === data.submission.exam_id],
  ];
}

export function classifyFile(data) {
  if (data && data.signed_receipt && data.submission) return "receipt";
  if (data && data.body && data.signature && Array.isArray(data.body.results)) return "export";
  if (data && data.body && data.signature && "score" in data.body) return "result";
  return null;
}
