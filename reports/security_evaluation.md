# Security Evaluation Report

Generated 2026-09-28 16:42:19 by `python -m secure_exam.evaluate` against a fresh sandbox (new keys and databases).

## 1. End-to-end examination flow

| Step | Result |
|---|---|
| [socket] Examiner authenticated over TLS 1.3 + signed handshake | ✅ |
| [socket] Exam created and published via RSA-signed examiner actions | ✅ |
| [socket] Student registered, one-time enrollment code issued | ✅ |
| [socket] Student enrolled: key pair generated client-side, proof-of-possession accepted | ✅ |
| [socket] Paper received; server signature + SHA-256 hash verified | ✅ |
| [socket] Answers RSA-PSS signed and submitted; receipt verified | ✅ |
| [socket] Result withheld until the examiner releases it | ✅ |
| [socket] Examiner independently verified the student's signature | ✅ |
| [socket] Exam closed, results released, signed export verified | ✅ |
| [socket] Signed result verified: 4/5 (marks-weighted) | ✅ |
| [https] Examiner authenticated over TLS 1.3 + signed handshake | ✅ |
| [https] Exam created and published via RSA-signed examiner actions | ✅ |
| [https] Student registered, one-time enrollment code issued | ✅ |
| [https] Student enrolled: key pair generated client-side, proof-of-possession accepted | ✅ |
| [https] Paper received; server signature + SHA-256 hash verified | ✅ |
| [https] Answers RSA-PSS signed and submitted; receipt verified | ✅ |
| [https] Result withheld until the examiner releases it | ✅ |
| [https] Examiner independently verified the student's signature | ✅ |
| [https] Exam closed, results released, signed export verified | ✅ |
| [https] Signed result verified: 4/5 (marks-weighted) | ✅ |

## 2. Cryptographic primitive verification

| Objective | Check | Result |
|---|---|---|
| Integrity | SHA-256 KAT: SHA256('abc') | ✅ |
| Integrity | HMAC-SHA256 KAT: RFC 4231 case 1 | ✅ |
| Key management | HKDF-SHA256 KAT: RFC 5869 case 1 | ✅ |
| Integrity | SHA-256 avalanche: 1-bit input change flips 50.2% of output bits | ✅ |
| Integrity | HMAC differs under a different key | ✅ |
| Confidentiality | AES-256-CBC encrypt/decrypt round-trip | ✅ |
| Confidentiality | AES-256-CBC randomised IV: same plaintext -> different ciphertext | ✅ |
| Confidentiality | AES-256-CBC ciphertext does not contain plaintext | ✅ |
| Confidentiality | AES-256-CBC wrong key does not recover plaintext | ✅ |
| Confidentiality | AES-256-GCM encrypt/decrypt round-trip | ✅ |
| Integrity | AES-256-GCM rejects wrong key | ✅ |
| Integrity | AES-256-GCM rejects modified ciphertext | ✅ |
| Integrity | AES-256-GCM rejects wrong associated data (file swap) | ✅ |
| Key management | RSA-OAEP wrap/unwrap of AES key | ✅ |
| Key management | RSA-OAEP is randomised | ✅ |
| Key management | RSA-OAEP unwrap fails with a different private key | ✅ |
| Non-repudiation | RSA-PSS signature verifies | ✅ |
| Non-repudiation | RSA-PSS rejects modified message | ✅ |
| Non-repudiation | RSA-PSS rejects signature from another key | ✅ |
| Authentication | PBKDF2 accepts correct password | ✅ |
| Authentication | PBKDF2 rejects wrong password | ✅ |
| Authentication | PBKDF2 salts are unique (same password -> different hash) | ✅ |

## 3. Secure communication (TLS)

- Negotiated protocol: **TLSv1.3**
- Cipher suite: **TLS_AES_256_GCM_SHA384** (256-bit)
- Server certificate subject: `{'organizationName': 'Secure Exam System', 'commonName': 'localhost'}`
- Certificate chain verified against the private CA; hostname checked against SAN
- TLS 1.2 and plaintext connections refused on both transports (see section 6)

## 4. HTTPS API hardening

| Check | Result |
|---|---|
| Header Strict-Transport-Security: max-age=63072000; includeSubDomains | ✅ |
| Header Cache-Control: no-store | ✅ |
| Header Pragma: no-cache | ✅ |
| Header X-Content-Type-Options: nosniff | ✅ |
| Header X-Frame-Options: DENY | ✅ |
| Header Referrer-Policy: no-referrer | ✅ |
| Header Content-Security-Policy: default-src 'none'; frame-ancestors 'none' | ✅ |
| Header Cross-Origin-Resource-Policy: same-origin | ✅ |
| /info publishes the same server signing key clients pin | ✅ |
| CORS allows configured origin https://localhost:5173 | ✅ |
| CORS refuses other origins (no Access-Control-Allow-Origin) | ✅ |
| Server header does not leak Python version | ✅ |
| Unknown route returns 404 | ✅ |

## 5. Confidentiality at rest

Each stored file was scanned for known plaintext (names, e-mails, passwords, question text, exam ID).

| File | No plaintext found / encrypted | 
|---|---|
| `admins.enc` | ✅ |
| `answer_keys.enc` | ✅ |
| `exams.enc` | ✅ |
| `students.enc` | ✅ |
| `submissions.enc` | ✅ |
| `audit.log (no passwords)` | ✅ |
| `audit_key.bin (RSA-OAEP wrapped, 384 bytes)` | ✅ |
| `storage_key.bin (RSA-OAEP wrapped, 384 bytes)` | ✅ |
| `clients/E2E-HTTPS-STUDENT_key.pem` | ✅ |
| `clients/E2E-SOCKET-STUDENT_key.pem` | ✅ |
| `clients/S1001_key.pem` | ✅ |
| `clients/S1002_key.pem` | ✅ |
| `clients/S1003_key.pem` | ✅ |
| `clients/S1004_key.pem` | ✅ |
| `clients/examiner_key.pem` | ✅ |

Audit log: 119 hash-chained, HMAC-protected entries verified.

## 6. Attack detection

| Category | Attack | Outcome | Evidence |
|---|---|---|---|
| Tampering | Bit-flip in encrypted LOGIN message (socket) | Blocked ✅ | server replied 'TAMPERING_DETECTED': HMAC verification failed |
| Tampering | Modify sequence number in message header | Blocked ✅ | server replied 'TAMPERING_DETECTED' (header is covered by the HMAC) |
| Tampering | Modify IV of an HTTPS API envelope | Blocked ✅ | HTTP 400 'TAMPERING_DETECTED'; session then revoked (next request HTTP 401) |
| Tampering | Alter answers after they were signed | Blocked ✅ | INVALID_SIGNATURE: submission signature does not verify |
| Tampering | Modify exam paper in transit (server-signed) | Blocked ✅ | client rejected paper: RSA-PSS signature invalid |
| Tampering | Tamper with encrypted exam database on disk | Blocked ✅ | AES-GCM rejected it: AES-GCM authentication tag invalid |
| Tampering | Swap one encrypted database file for another | Blocked ✅ | file name is GCM associated data: AES-GCM authentication tag invalid |
| Tampering | Delete entries from the audit log | Blocked ✅ | audit log chain broken at entry 1 |
| Replay | Replay a captured request in the same session (socket) | Blocked ✅ | server replied 'REPLAY_DETECTED': sequence number 1 already seen (last=1) |
| Replay | Replay a captured HTTPS API request | Blocked ✅ | first HTTP 200, replay HTTP 400 'REPLAY_DETECTED' |
| Replay | Replay a whole recorded session on a new connection | Blocked ✅ | fresh server nonce -> different session keys -> MAC fails; got encrypted error frame (attacker cannot read it) |
| Replay | Delayed / stale message (10 min old) | Blocked ✅ | server replied 'REPLAY_DETECTED': message timestamp outside allowed window |
| Replay | Resubmit answers after first submission | Blocked ✅ | ALREADY_SUBMITTED |
| Replay | Replay a signed examiner action | Blocked ✅ | REPLAYED_ACTION |
| Replay | Re-use an hour-old signed examiner action | Blocked ✅ | STALE_ACTION: action timestamp outside allowed window |
| Unauthorized access | Request exam paper without logging in | Blocked ✅ | UNAUTHORIZED: not authenticated |
| Unauthorized access | Login with wrong password | Blocked ✅ | INVALID_CREDENTIALS |
| Unauthorized access | Online brute-force of a password | Blocked ✅ | after 5 failures even the correct password gets 'ACCOUNT_LOCKED' |
| Unauthorized access | Second login with stolen credentials while victim is online | Blocked ✅ | SESSION_ACTIVE: this account is already logged in elsewhere |
| Unauthorized access | Hijack HTTPS session with a stolen session_id | Blocked ✅ | HTTP 400; forged envelope failed the MAC, reply unreadable to the attacker, session revoked |
| Unauthorized access | Call the HTTPS API with a guessed session_id | Blocked ✅ | HTTP 401 UNKNOWN_SESSION |
| Unauthorized access | Submit answers as another student | Blocked ✅ | UNAUTHORIZED: submission student_id does not match authenticated user |
| Unauthorized access | Sign submission with an unregistered key | Blocked ✅ | INVALID_SIGNATURE: submission signature does not verify |
| Unauthorized access | Student calls examiner operations | Blocked ✅ | read: FORBIDDEN: ADMIN_LIST_STUDENTS requires role admin; action: FORBIDDEN: ADMIN_ACTION requires role admin |
| Unauthorized access | Examiner action signed with the wrong key (stolen password only) | Blocked ✅ | INVALID_SIGNATURE: admin action signature does not verify |
| Unauthorized access | Fetch result before the examiner releases it | Blocked ✅ | RESULTS_NOT_RELEASED: results have not been published yet |
| Unauthorized access | Open an unpublished (draft) exam paper | Blocked ✅ | NO_SUCH_EXAM; not shown in LIST_EXAMS |
| Unauthorized access | Open a published exam before its window | Blocked ✅ | EXAM_NOT_OPEN: the exam is not open at this time |
| Unauthorized access | Enroll with a guessed enrollment code | Blocked ✅ | INVALID_ENROLLMENT: unknown student, bad or expired code |
| Unauthorized access | Enroll a public key without proof of possession | Blocked ✅ | INVALID_PUBLIC_KEY: RSA key >= 2048 bits with valid proof-of-possession signature required (RSA-PSS signature invalid) |
| Unauthorized access | Re-use a consumed enrollment code to take over an account | Blocked ✅ | INVALID_ENROLLMENT: unknown student, bad or expired code |
| Unauthorized access | Set a weak password | Blocked ✅ | WEAK_PASSWORD: use at least 10 characters and 3 of: lowercase, uppercase, digit, symbol |
| Unauthorized access | Connect to the socket server without TLS | Blocked ✅ | server closed non-TLS connection |
| Unauthorized access | Call the API over plain HTTP | Blocked ✅ | plain HTTP refused (ConnectionResetError) |
| Unauthorized access | Force a TLS 1.2 downgrade | Blocked ✅ | both transports require TLS 1.3 |
| MITM | MITM with a certificate from an untrusted CA | Blocked ✅ | TLS rejected certificate: unable to get local issuer certificate |
| MITM | Impostor server with stolen TLS certificate | Blocked ✅ | TLS passed, but the RSA-PSS handshake signature did not verify |
| Key management | Use a leaked storage key after key rotation | Blocked ✅ | old key rejected by AES-GCM; data re-encrypted and still readable by the server |
| Non-repudiation | Student denies making a submission | Blocked ✅ | stored submission verifies under S1001's public key; server receipt verifies under the server key |
| Non-repudiation | Examiner denies publishing / releasing / rotating | Blocked ✅ | 4 examiner actions logged with RSA-PSS signature and SHA-256 action hash in the HMAC-chained audit log |

## 7. Performance

| Operation | Median time |
|---|---|
| AES-256-CBC encrypt (1 MiB) | 0.55 ms  (1809 MiB/s) |
| AES-256-GCM encrypt (1 MiB) | 0.14 ms  (7205 MiB/s) |
| SHA-256 (1 MiB) | 0.31 ms |
| HMAC-SHA256 (1 MiB) | 0.31 ms |
| RSA-3072 PSS sign | 0.90 ms |
| RSA-3072 PSS verify | 0.030 ms |
| RSA-3072 OAEP unwrap | 0.91 ms |
| RSA-2048 key generation (student enrollment) | 29 ms |
| PBKDF2-SHA256 (600,000 iter) | 37 ms  (~26.9 guesses/s per core for an attacker) |
| TLS 1.3 + RSA handshake (socket) | 3.6 ms |
| Connect + login + fetch & verify paper (socket) | 42 ms |
| TLS 1.3 + RSA handshake (https) | 3.7 ms |
| Connect + login + fetch & verify paper (https) | 43 ms |

## Summary

**110/110 checks passed.**
