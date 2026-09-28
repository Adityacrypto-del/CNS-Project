# Secure Exam API: guide for frontend developers

This guide is for anyone building a web (or other) client for the exam server. It covers the HTTPS transport, how to set up the encrypted session in the browser with WebCrypto, and every operation with its request, response and error codes.

There are two reference implementations; when in doubt, match what they send byte for byte:

- the Python client in [`secure_exam/client.py`](../secure_exam/client.py)
- the bundled web frontend in [`frontend/js/`](../frontend/js/): [`crypto.js`](../frontend/js/crypto.js) (WebCrypto primitives, canonical JSON, encrypted PKCS#8), [`channel.js`](../frontend/js/channel.js) (handshake and envelopes) and [`client.js`](../frontend/js/client.js) (every operation, with signature checks)

Both are tested against the live server in [`tests/test_web_client.py`](../tests/test_web_client.py).

---

## 1. Overview

The server offers two transports that share one protocol and one backend:

| Transport | Port (default) | Used by |
|---|---|---|
| TLS socket, 4-byte big-endian length-prefixed JSON frames | `8443` (`SECURE_EXAM_PORT`) | Python CLI clients |
| HTTPS JSON API | `8444` (`SECURE_EXAM_API_PORT`) | Web frontends |
| Static HTTPS (web app) | `5173` (`SECURE_EXAM_WEB_PORT`) | Serves `frontend/` and `/config.js` |

TLS alone is not trusted to protect exam content. Inside TLS, the client and server run their own handshake and derive session keys. After that, every operation travels as an encrypted, MAC-protected **envelope** through a single endpoint, `POST /api/v1/rpc`. URLs and status codes therefore reveal nothing about what the user is doing.

```
Browser                                                     Server
  │  GET  /api/v1/info  ───────────────────────────────────►  server public key (compare with pinned copy!)
  │  POST /api/v1/handshake {HELLO}  ──────────────────────►
  │  ◄──────────────── {session_id, HELLO_OK}                 verify RSA-PSS signature, derive keys
  │  POST /api/v1/rpc {session_id, envelope(LOGIN)} ───────►
  │  ◄──────────────── {envelope(response)}
  │  … one request at a time …
```

### Endpoints

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/v1/health` | none | `{"status": "ok"}` |
| GET | `/api/v1/info` | none | server public key (PEM), key fingerprint, algorithm descriptions, `max_clock_skew_seconds`, `session_idle_timeout_seconds` |
| POST | `/api/v1/handshake` | HELLO (section 3) | `{"session_id", "type": "HELLO_OK", "server_nonce", "signature"}` |
| POST | `/api/v1/rpc` | `{"session_id", "envelope"}` | `{"envelope"}` |
| OPTIONS | any | none | CORS preflight |

HTTP-level rules:

- POST bodies must use `Content-Type: application/json` (otherwise **415**) and be at most 1 MB (otherwise **413**).
- CORS is granted only to the origin in `SECURE_EXAM_ALLOWED_ORIGIN` (default `https://localhost:5173`). No cookies or credentials are used.
- Every response carries `Cache-Control: no-store`, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Content-Security-Policy: default-src 'none'`.

| HTTP status on `/rpc` | Meaning | What the client should do |
|---|---|---|
| 200 | Envelope processed. The operation itself may still have failed (see `ok` inside). | Open the envelope |
| 400 + `envelope` | Tampering, replay or a stale message was detected. **The session has been destroyed.** | Open the envelope for the reason, then start a new handshake |
| 400 without envelope | Invalid JSON | Fix the client |
| 401 `UNKNOWN_SESSION` | Session expired (30 min idle), logged out, destroyed, or never existed | New handshake, then log in again |
| 503 `TOO_MANY_SESSIONS` | Server at capacity | Retry later |

---

## 2. Encodings

These must match exactly, because hashes and signatures are computed over them.

- **Binary to text:** standard Base64 with padding (`+/=`), not URL-safe.
- **Canonical JSON** (for everything that is hashed or signed) is equivalent to Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"))`:
  - object keys sorted recursively, by code point
  - no whitespace
  - **every character from U+007F upward escaped** as `\uXXXX` (lowercase hex, UTF-16 surrogate pairs), because Python's `ensure_ascii` defaults to true. The snippet below is verified byte-identical to the Python encoder.
  - only strings, integers, booleans, `null`, arrays and objects appear. The protocol **never uses floats** (JS and Python print `80.0` differently), so, for example, `percentage` is the string `"80.00"`

  ```js
  function canonicalJson(v) {
    if (v === null || typeof v !== "object")
      return JSON.stringify(v).replace(/[\u007f-\uffff]/g,
        c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
    if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
    return "{" + Object.keys(v).sort().map(k => canonicalJson(k) + ":" + canonicalJson(v[k])).join(",") + "}";
  }
  const utf8 = s => new TextEncoder().encode(s);
  ```


---

## 3. Session setup (WebCrypto)

### Algorithms

| Purpose | Algorithm | WebCrypto parameters |
|---|---|---|
| Key transport | RSA-OAEP, SHA-256, MGF1-SHA-256, no label | `{name: "RSA-OAEP"}`, key imported with `hash: "SHA-256"` |
| Handshake and data signatures from the server | RSA-PSS, SHA-256, MGF1-SHA-256, **max salt length** | `{name: "RSA-PSS", saltLength: keyBytes - 34}`, which is **350** for the 3072-bit server key |
| Signatures made by the client (students, examiner) | RSA-PSS, SHA-256 | any salt length is accepted; use `saltLength: 32` |
| Key derivation | HKDF-SHA256 | `{name: "HKDF", hash: "SHA-256", salt, info}` |
| Encryption | AES-256-CBC, PKCS#7, random 16-byte IV | `{name: "AES-CBC", iv}` (WebCrypto pads with PKCS#7 automatically) |
| MAC | HMAC-SHA256 | `{name: "HMAC", hash: "SHA-256"}` |

### Pin the server key

The server's RSA public key (`data/pki/server_sign_pub.pem`) must be **bundled with the frontend at build time**. The bundled frontend receives it from `/config.js`, which [`web.py`](../secure_exam/web.py) generates from the same origin as the page; it never reads the key from the API. Compare it with `GET /info` as a sanity check, but never trust `/info` alone: whoever controls the network response would control the key.

### Handshake

1. `client_nonce` = 32 random bytes; `master` = 32 random bytes.
2. `wrapped_master` = RSA-OAEP-encrypt(`server_pub`, `master`).
3. Send `POST /handshake` with `{"type": "HELLO", "client_nonce": b64(client_nonce), "wrapped_master": b64(wrapped_master)}`.
4. The response is `{"session_id", "type": "HELLO_OK", "server_nonce", "signature"}`.
5. Verify RSA-PSS (salt length 350) with the pinned key over this transcript:
   `utf8("SECURE-EXAM-HELLO|") ‖ client_nonce ‖ server_nonce ‖ wrapped_master` (raw bytes, not Base64).
   **Abort if verification fails.** Only the real server can unwrap `master` and sign the transcript.
6. Derive `okm` = HKDF-SHA256(ikm=`master`, salt=`client_nonce ‖ server_nonce`, info=`utf8("secure-exam session v1")`, length 64 bytes). Then `k_enc` = `okm[0:32]` and `k_mac` = `okm[32:64]`.
7. Keep `session_id`, `k_enc` and `k_mac` **in memory only**, never in `localStorage`.

```js
const hs = await post("/api/v1/handshake", {type: "HELLO", client_nonce: b64(cn), wrapped_master: b64(wrapped)});
const transcript = concat(utf8("SECURE-EXAM-HELLO|"), cn, b64d(hs.server_nonce), wrapped);
if (!await crypto.subtle.verify({name: "RSA-PSS", saltLength: 350}, serverPssKey, b64d(hs.signature), transcript))
  throw new Error("server authentication failed");
const ikm = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
const okm = new Uint8Array(await crypto.subtle.deriveBits(
  {name: "HKDF", hash: "SHA-256", salt: concat(cn, b64d(hs.server_nonce)), info: utf8("secure-exam session v1")}, ikm, 512));
```

### Envelopes

Envelope format: `{"seq": int, "ts": int, "iv": b64, "ct": b64, "mac": b64}`.

**Sealing** a request (client to server):

1. `seq` starts at 0 and increases by 1 for every request. `ts` = current Unix time in seconds.
2. `iv` = 16 random bytes. `ct` = AES-256-CBC(`k_enc`, `iv`, utf8(canonicalJson(payload))).
3. `mac` = HMAC-SHA256(`k_mac`, `utf8("C2S") ‖ u64be(seq) ‖ u64be(ts) ‖ iv ‖ ct`).

**Opening** a response (server to client):

1. Recompute the MAC with direction `"S2C"` and compare. Reject the response if it does not match.
2. Require `seq` > last server `seq` seen, and |now − `ts`| ≤ 60 s.
3. Decrypt `ct` and parse the JSON.

The server applies the same checks to your requests. A failed MAC, a reused or lower `seq`, or a timestamp more than 60 s off destroys the session. **Send one request at a time per session**: wait for each response before sealing the next request. Parallel requests can arrive out of order and will be treated as a replay. If the user's clock is badly wrong, requests will be rejected. Compare `server_time` from the LOGIN response with the local clock and warn the user.

---

## 4. Operations

Every decrypted request is `{"type": OP, ...params}`. Every decrypted response is either `{"ok": true, ...result}` or `{"ok": false, "error": CODE, "detail": "human readable"}`.

A **signed object** is `{"body": {...}, "signature": b64}`. Verify it with the pinned server key (RSA-PSS, salt length 350) over `utf8(canonicalJson(body))` **before using `body`**.

### Anonymous

| Op | Params | Result |
|---|---|---|
| `LOGIN` | `user_id`, `password`, `role` (`"student"` default, or `"admin"`) | `user_id`, `role`, `name`, `server_time`, `session_ttl` |
| `ENROLL` | `student_id`, `enrollment_code`, `password`, `public_key` (SPKI PEM), `proof` | `student_id`, `status: "active"` |

**`ENROLL`** is a student's one-time account activation, using the code issued by the examiner.

1. Generate an RSA-PSS key pair of **at least 2048 bits** on the device, with `extractable: true` only so it can be exported and encrypted.
2. `proof` = b64(RSA-PSS-sign(private key, utf8(canonicalJson({"student_id", "public_key", "purpose": "enroll"})))).
3. Store the private key encrypted under the user's password. For example, wrap it with AES-GCM using a key derived with PBKDF2 (≥ 600 000 iterations) and keep it in IndexedDB. Without this key the student cannot submit.

Codes are case-insensitive, and **a code works only once**.

### Any logged-in user

| Op | Params | Result |
|---|---|---|
| `WHOAMI` | none | `user_id`, `role`, `session_expires_at` |
| `CHANGE_PASSWORD` | `old_password`, `new_password` | `{}`. Re-encrypt the locally stored private key with the new password too. |
| `LOGOUT` | none | `{}`. On HTTPS this also destroys the session. |

Password policy: at least 10 characters, at least 3 of lowercase / uppercase / digit / symbol, and it must not contain the user ID (otherwise `WEAK_PASSWORD`).

### Student

| Op | Params | Result |
|---|---|---|
| `LIST_EXAMS` | none | `exams: [{exam_id, title, duration_minutes, opens_at, closes_at, state, result_available}]` |
| `GET_EXAM` | `exam_id` | `paper`: a signed object (below) |
| `SUBMIT` | `submission`, `signature` | `receipt`: a signed object (below) |
| `GET_RESULT` | `exam_id` | `result`: a signed object (below) |

`state` is one of: `upcoming`, `open`, `in_progress`, `submitted`, `missed`, `closed`.

**`GET_EXAM`** starts the timer on the first call. Calling it again returns the same attempt, so a page reload is safe. The signed `paper.body` is:

```json
{"exam": {"exam_id", "title", "description", "duration_minutes", "total_marks",
          "questions": [{"id", "text", "options": {"A": "…"}, "marks"}]},
 "exam_hash": "hex SHA-256 of canonicalJson(exam)",
 "issued_to": "S1001", "started_at": 0, "deadline": 0, "issued_at": 0}
```

Check that the signature is valid, that `issued_to` is the logged-in user, that `exam.exam_id` is the one you asked for, and that `exam_hash` = SHA-256(canonicalJson(exam)). Questions arrive in a per-student order; keep that order. Show a countdown to `deadline`. Submissions are accepted until `deadline` plus a 30 s grace period.

**`SUBMIT`** sends a submission and its signature:

```json
submission = {"student_id": "<self>", "exam_id": "…", "exam_hash": "<from paper>",
              "answers": {"Q1": "C", "Q4": "B"}, "submitted_at": unix_seconds,
              "nonce": b64(16 random bytes)}
signature  = b64(RSA-PSS-sign(student_private_key, utf8(canonicalJson(submission))))
```

Unanswered questions are simply left out. The signed `receipt.body` is `{student_id, exam_id, exam_hash, submission_hash, received_at}`. Check that `submission_hash` equals hex SHA-256(canonicalJson(submission)). **Let the user download `{submission, signature, signed_receipt}`**: it is their proof of submission, and `python -m secure_exam.client verify-receipt FILE` can verify it.

**`GET_RESULT`** is available once the examiner releases results. The signed `result.body` is `{student_id, exam_id, score, total, percentage, submission_hash, issued_at}`. The answer key is never revealed.

### Examiner (`role: "admin"`)

These read operations are not signed:

| Op | Params | Result |
|---|---|---|
| `ADMIN_LIST_STUDENTS` | none | `students: [{student_id, name, email, status, locked_out, key_fingerprint}]` |
| `ADMIN_LIST_EXAMS` | none | `exams: [{exam_id, title, status, opens_at, closes_at, duration_minutes, results_released, created_by, questions, started, submitted}]` |
| `ADMIN_GET_EXAM` | `exam_id` | `exam` (full record), `answer_key` |
| `ADMIN_LIST_SUBMISSIONS` | `exam_id` | `submissions: [{student_id, score, total, received_at, submission_hash}]`, `not_submitted` |
| `ADMIN_GET_SUBMISSION` | `exam_id`, `student_id` | `record` (submission, signature, receipt, …), `student_public_key` |
| `ADMIN_AUDIT` | `limit` (1–1000, default 50) | `verified_entries`, `integrity_error`, `entries: [{ts, event, details}]` |

Every state change goes through **`ADMIN_ACTION`**, signed with the examiner's own RSA key:

```json
{"type": "ADMIN_ACTION",
 "action": {"op": "PUBLISH_EXAM", "params": {"exam_id": "…"}, "admin_id": "<self>",
            "ts": unix_seconds, "nonce": b64(16 random bytes)},
 "signature": b64(RSA-PSS-sign(admin_key, utf8(canonicalJson(action))))}
```

`ts` must be within ±60 s of the server's clock, and each `nonce` can be used only once.

| `op` | `params` | Result |
|---|---|---|
| `ADD_STUDENT` | `student_id`, `name`, `email?` | `student_id`, `enrollment_code`, `expires_at` (72 h) |
| `REISSUE_ENROLLMENT` | `student_id` | new code; the old key and password are revoked |
| `SET_STUDENT_STATUS` | `student_id`, `status` (`active` / `disabled`) | `student_id`, `status` |
| `UNLOCK_ACCOUNT` | `user_id` | `user_id`, `unlocked` |
| `CREATE_EXAM` | `exam`, `answer_key` (below) | `exam_id`, `status: "draft"` |
| `PUBLISH_EXAM` | `exam_id` | draft → published |
| `CLOSE_EXAM` | `exam_id` | published → closed |
| `RELEASE_RESULTS` | `exam_id` | `results_released: true` |
| `EXPORT_RESULTS` | `exam_id` | `export`: a signed `{exam_id, title, generated_at, generated_for, results: [...], no_submission}` |
| `ROTATE_STORAGE_KEY` | none | `rotated`, `stores` |

The `exam` object for `CREATE_EXAM` contains:

- `exam_id`: `^[A-Z0-9][A-Z0-9-]{2,39}$`
- `title`, `description?`
- `duration_minutes`: 1–600
- `opens_at` < `closes_at`: integer Unix times
- `questions`: 1–200 of `{id, text, options: {2–8 string pairs}, marks?: 1–100}`

`answer_key` maps every question `id` to one of that question's option keys. See [`examples/sample_exam.json`](../examples/sample_exam.json); its relative times such as `"now"` and `"+2d"` are resolved by the CLI, but API clients must send integers.

---

## 5. Error codes

| Code | Meaning |
|---|---|
| `TAMPERING_DETECTED`, `REPLAY_DETECTED`, `PROTOCOL_VIOLATION` | Channel-level security failure; the session is destroyed |
| `UNAUTHORIZED` | Not logged in, or a submission for another student |
| `FORBIDDEN` | Wrong role, or an admin action whose `admin_id` is not the caller |
| `SESSION_EXPIRED` | Login older than 3 h; log in again |
| `INVALID_CREDENTIALS` | Wrong user ID or password (deliberately does not say which) |
| `ACCOUNT_LOCKED` | 5 failures within 5 min; wait, or ask the examiner to `UNLOCK_ACCOUNT` |
| `ACCOUNT_INACTIVE` | Student is pending enrollment or disabled |
| `SESSION_ACTIVE` | The account is already logged in elsewhere |
| `ALREADY_AUTHENTICATED` | LOGIN on a session that is already logged in |
| `INVALID_ENROLLMENT`, `INVALID_PUBLIC_KEY`, `WEAK_PASSWORD` | Enrollment or password problems |
| `NO_SUCH_EXAM`, `EXAM_NOT_OPEN`, `EXAM_NOT_STARTED`, `DEADLINE_PASSED`, `ALREADY_SUBMITTED` | Exam state |
| `EXAM_HASH_MISMATCH` | Submission made against a different paper |
| `INVALID_SIGNATURE` | Student or examiner signature does not verify |
| `NO_SUBMISSION`, `RESULTS_NOT_RELEASED` | Result not available |
| `STALE_ACTION`, `REPLAYED_ACTION`, `UNKNOWN_ACTION` | Problems with a signed admin action |
| `INVALID_EXAM`, `INVALID_STATE`, `ALREADY_EXISTS`, `NO_SUCH_STUDENT`, `NOT_ENROLLED` | Examiner input errors |
| `BAD_REQUEST`, `UNKNOWN_REQUEST` | Malformed request |

---

## 6. Security checklist for a frontend

- [ ] The server public key is bundled at build time, and the handshake signature is verified before anything else.
- [ ] Session keys, `session_id` and passwords are kept only in memory. The private key is stored encrypted under the user's password.
- [ ] Every signed object (paper, receipt, result, export) is verified before its contents are shown.
- [ ] Requests are serialised per session. On a 400 or 401 response, start a new handshake.
- [ ] Question and option text is rendered as **text**, never as HTML (`textContent`, not `innerHTML`).
- [ ] The page is served over HTTPS from the origin allowed by `SECURE_EXAM_ALLOWED_ORIGIN`, with its own strict CSP.
- [ ] Students can download their submission receipt.
