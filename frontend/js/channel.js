// Secure session with the exam server over the HTTPS API: RSA-authenticated handshake,
// then AES-256-CBC + HMAC-SHA256 envelopes with sequence numbers and timestamps.
// Mirrors secure_exam/protocol.py; see docs/API.md section 3.

import {
  aesCbcDecrypt, aesCbcEncrypt, b64, b64d, canonicalBytes, concat, hkdfSessionKeys, hmacSign,
  hmacVerify, importChannelKeys, nowSeconds, randomBytes, rsaEncrypt, u64be, utf8, verifyServer,
} from "./crypto.js";

export const MAX_CLOCK_SKEW = 60;

export class ApiError extends Error {
  constructor(code, detail = "") {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
    this.detail = detail;
  }
  // The session is gone and a new handshake + login is needed.
  get sessionLost() {
    return ["UNKNOWN_SESSION", "TAMPERING_DETECTED", "REPLAY_DETECTED", "PROTOCOL_VIOLATION",
            "SESSION_EXPIRED", "SESSION_CLOSED", "UNAUTHORIZED"].includes(this.code);
  }
}

async function post(apiBase, path, body) {
  let res;
  try {
    res = await fetch(apiBase + path, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body), cache: "no-store", credentials: "omit",
      referrerPolicy: "no-referrer",
    });
  } catch (exc) {
    throw new ApiError("NETWORK_ERROR", `cannot reach the exam server at ${apiBase} (${exc.message})`);
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error body */ }
  return { status: res.status, data };
}

export class SecureSession {
  constructor(apiBase, server, state) {
    this.apiBase = apiBase;
    this.server = server;              // pinned server key (importServerKey)
    this.sessionId = state.sessionId;
    this.rawKeys = state.rawKeys;      // {enc, mac} bytes, kept only for reload persistence
    this.sendSeq = state.sendSeq ?? 0;
    this.lastRecvSeq = state.lastRecvSeq ?? -1;
    this.keys = null;
    this.closed = false;
    this.queue = Promise.resolve();
    this.onChange = null;              // called after every exchange (persistence, UI stats)
    this.stats = { sent: 0, received: 0, openedAt: state.openedAt ?? Date.now() };
  }

  static async handshake(apiBase, server) {
    const clientNonce = randomBytes(32), master = randomBytes(32);
    const wrapped = await rsaEncrypt(server, master);
    const { status, data } = await post(apiBase, "/api/v1/handshake", {
      type: "HELLO", client_nonce: b64(clientNonce), wrapped_master: b64(wrapped),
    });
    if (status !== 200 || data?.type !== "HELLO_OK")
      throw new ApiError(data?.error || `HTTP_${status}`, "handshake rejected");
    const serverNonce = b64d(data.server_nonce);
    const transcript = concat(utf8("SECURE-EXAM-HELLO|"), clientNonce, serverNonce, wrapped);
    // Only the real server can sign this transcript with the pinned key.
    if (!await verifyServer(server, b64d(data.signature), transcript))
      throw new ApiError("SERVER_AUTH_FAILED",
                         "the server's handshake signature does not match the pinned key");
    const okm = await hkdfSessionKeys(master, concat(clientNonce, serverNonce));
    const s = new SecureSession(apiBase, server, {
      sessionId: data.session_id, rawKeys: { enc: okm.slice(0, 32), mac: okm.slice(32) },
    });
    await s.init();
    return s;
  }

  static async restore(apiBase, server, saved) {
    const s = new SecureSession(apiBase, server, {
      ...saved, rawKeys: { enc: b64d(saved.kEnc), mac: b64d(saved.kMac) },
    });
    await s.init();
    return s;
  }

  async init() {
    this.keys = await importChannelKeys(this.rawKeys.enc, this.rawKeys.mac);
  }

  serialise() {
    return { sessionId: this.sessionId, kEnc: b64(this.rawKeys.enc), kMac: b64(this.rawKeys.mac),
             sendSeq: this.sendSeq, lastRecvSeq: this.lastRecvSeq, openedAt: this.stats.openedAt };
  }

  static macInput(direction, seq, ts, iv, ct) {
    return concat(utf8(direction), u64be(seq), u64be(ts), iv, ct);
  }

  async seal(payload) {
    const seq = this.sendSeq++, ts = nowSeconds();
    const { iv, ct } = await aesCbcEncrypt(this.keys.enc, canonicalBytes(payload));
    const mac = await hmacSign(this.keys.mac, SecureSession.macInput("C2S", seq, ts, iv, ct));
    return { seq, ts, iv: b64(iv), ct: b64(ct), mac: b64(mac) };
  }

  async openEnvelope(env) {
    const { seq, ts } = env;
    if (!Number.isInteger(seq) || !Number.isInteger(ts)) throw new ApiError("PROTOCOL_VIOLATION");
    const iv = b64d(env.iv), ct = b64d(env.ct);
    // Encrypt-then-MAC: authenticate before decrypting anything.
    if (!await hmacVerify(this.keys.mac, b64d(env.mac), SecureSession.macInput("S2C", seq, ts, iv, ct)))
      throw new ApiError("TAMPERING_DETECTED", "response MAC does not verify");
    if (seq <= this.lastRecvSeq)
      throw new ApiError("REPLAY_DETECTED", `response sequence ${seq} already seen`);
    if (Math.abs(nowSeconds() - ts) > MAX_CLOCK_SKEW)
      throw new ApiError("REPLAY_DETECTED",
                         "response timestamp outside the 60 s window (is this computer's clock right?)");
    this.lastRecvSeq = seq;
    return JSON.parse(new TextDecoder().decode(await aesCbcDecrypt(this.keys.enc, iv, ct)));
  }

  // Requests are strictly serialised: the channel rejects out-of-order sequence numbers.
  request(payload) {
    const p = this.queue.then(() => this.exchange(payload));
    this.queue = p.catch(() => {});
    return p;
  }

  async exchange(payload) {
    if (this.closed) throw new ApiError("SESSION_CLOSED", "the secure session has ended");
    const envelope = await this.seal(payload);
    this.onChange?.(this);             // persist the used seq before it leaves the browser
    this.stats.sent++;
    const { status, data } = await post(this.apiBase, "/api/v1/rpc",
                                        { session_id: this.sessionId, envelope });
    try {
      if (status === 401) {
        this.closed = true;
        throw new ApiError("UNKNOWN_SESSION", "the session expired or was ended by the server");
      }
      if (status === 400 && data?.envelope) {
        // The server detected tampering or replay and destroyed the session.
        this.closed = true;
        const reply = await this.openEnvelope(data.envelope).catch(() => null);
        throw new ApiError(reply?.error || "PROTOCOL_VIOLATION", reply?.detail || "");
      }
      if (status !== 200 || !data?.envelope) throw new ApiError(`HTTP_${status}`, data?.error || "");
      const response = await this.openEnvelope(data.envelope);
      this.stats.received++;
      if (payload.type === "LOGOUT") this.closed = true;
      return response;
    } catch (exc) {
      if (exc instanceof ApiError && exc.sessionLost) this.closed = true;
      throw exc;
    } finally {
      this.onChange?.(this);
    }
  }

  async call(type, params = {}) {
    const r = await this.request({ type, ...params });
    if (!r.ok) {
      const err = new ApiError(r.error, r.detail);
      if (err.sessionLost) this.closed = true;
      throw err;
    }
    return r;
  }
}
