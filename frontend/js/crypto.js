// Cryptographic primitives for the browser client, built only on WebCrypto.
// Byte formats match secure_exam/crypto_utils.py exactly (see docs/API.md, sections 2-3).

const subtle = globalThis.crypto.subtle;

// --- encodings ----------------------------------------------------------------

export const utf8 = (s) => new TextEncoder().encode(s);

export function b64(bytes) {
  bytes = new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000)
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export function b64d(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export const hex = (bytes) =>
  Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");

export function concat(...parts) {
  const arrays = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)));
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function u64be(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

// Equivalent to Python json.dumps(v, sort_keys=True, separators=(",", ":")) with ensure_ascii.
export function canonicalJson(v) {
  if (typeof v === "number" && !Number.isInteger(v))
    throw new Error("floats are not allowed in canonical JSON");
  if (v === null || typeof v !== "object")
    return JSON.stringify(v).replace(/[\u007f-￿]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(v).sort()
    .map((k) => canonicalJson(k) + ":" + canonicalJson(v[k])).join(",") + "}";
}

export const canonicalBytes = (v) => utf8(canonicalJson(v));

export async function sha256Hex(data) {
  return hex(await subtle.digest("SHA-256", data));
}

export const nowSeconds = () => Math.floor(Date.now() / 1000);

// --- PEM ----------------------------------------------------------------------

export function pemToDer(pem) {
  return b64d(pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, "").replace(/\s+/g, ""));
}

export function derToPem(der, label) {
  const body = b64(der).match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

// --- RSA ----------------------------------------------------------------------

const PSS_IMPORT = { name: "RSA-PSS", hash: "SHA-256" };
const CLIENT_SALT = 32;   // the server accepts any PSS salt length for client signatures

// The server's key is used twice: RSA-OAEP to send the master secret, RSA-PSS to verify.
export async function importServerKey(pem) {
  const der = pemToDer(pem);
  const verifyKey = await subtle.importKey("spki", der, PSS_IMPORT, false, ["verify"]);
  const oaepKey = await subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" },
                                         false, ["encrypt"]);
  // Python signs with PSS.MAX_LENGTH: key bytes - hash bytes - 2 (350 for RSA-3072).
  const saltLength = verifyKey.algorithm.modulusLength / 8 - 34;
  return { verifyKey, oaepKey, saltLength, fingerprint: (await sha256Hex(der)).slice(0, 32) };
}

export async function importPublicKey(pem) {
  return subtle.importKey("spki", pemToDer(pem), PSS_IMPORT, false, ["verify"]);
}

export async function rsaEncrypt(server, data) {
  return new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, server.oaepKey, data));
}

// Verifies a server signature (max salt length).
export async function verifyServer(server, signature, data) {
  return subtle.verify({ name: "RSA-PSS", saltLength: server.saltLength },
                       server.verifyKey, signature, data);
}

// Verifies a signature made by a student or examiner key (salt length 32, like the Python client).
export async function verifyUser(publicKey, signature, data) {
  return subtle.verify({ name: "RSA-PSS", saltLength: CLIENT_SALT }, publicKey, signature, data);
}

export async function sign(privateKey, data) {
  return new Uint8Array(await subtle.sign({ name: "RSA-PSS", saltLength: CLIENT_SALT },
                                          privateKey, data));
}

// Checks a server-signed object {body, signature} and returns body, or throws.
export async function verifySigned(server, signed) {
  if (!signed || typeof signed.body !== "object" || typeof signed.signature !== "string")
    throw new Error("malformed signed object");
  if (!await verifyServer(server, b64d(signed.signature), canonicalBytes(signed.body)))
    throw new Error("server signature does not verify");
  return signed.body;
}

// New RSA-2048 key pair made on this device. Returns the public PEM, the unencrypted PKCS#8
// bytes (only to be encrypted at once) and a non-extractable signing key.
export async function generateUserKey(bits = 2048) {
  const pair = await subtle.generateKey(
    { ...PSS_IMPORT, modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]) },
    true, ["sign", "verify"]);
  const spki = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
  return { publicPem: derToPem(spki, "PUBLIC KEY"), pkcs8,
           privateKey: await importPkcs8(pkcs8) };
}

export async function importPkcs8(der) {
  return subtle.importKey("pkcs8", der, PSS_IMPORT, false, ["sign"]);
}

// --- password-encrypted PKCS#8 (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC) --------------
// This is the "ENCRYPTED PRIVATE KEY" format the Python client writes, so key files move
// freely between the command-line tools and the browser.

const OID = {
  pbes2: "2a864886f70d01050d",
  pbkdf2: "2a864886f70d01050c",
  hmacSha256: "2a864886f70d0209",
  aes256cbc: "60864801650304012a",
};
export const KEY_PBKDF2_ITERATIONS = 600000;

function derRead(buf, pos) {
  const tag = buf[pos];
  let len = buf[pos + 1], hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
    hdr += n;
  }
  if (pos + hdr + len > buf.length) throw new Error("truncated DER");
  return { tag, start: pos + hdr, end: pos + hdr + len };
}

function derChildren(buf, node) {
  const out = [];
  for (let p = node.start; p < node.end;) { const c = derRead(buf, p); out.push(c); p = c.end; }
  return out;
}

const derBytes = (buf, node) => buf.subarray(node.start, node.end);

function derEncode(tag, ...contents) {
  const body = concat(...contents);
  let len;
  if (body.length < 0x80) len = [body.length];
  else {
    len = [];
    for (let n = body.length; n > 0; n = Math.floor(n / 256)) len.unshift(n & 0xff);
    len.unshift(0x80 | len.length);
  }
  return concat(new Uint8Array([tag, ...len]), body);
}

const derSeq = (...c) => derEncode(0x30, ...c);
const derOid = (h) => derEncode(0x06, Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16)));
const derOctets = (b) => derEncode(0x04, b);
function derInt(n) {
  const bytes = [];
  for (; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff);
  if (!bytes.length || bytes[0] & 0x80) bytes.unshift(0);
  return derEncode(0x02, new Uint8Array(bytes));
}

async function pbkdf2Aes(password, salt, iterations, usage) {
  const base = await subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base,
                          { name: "AES-CBC", length: 256 }, false, [usage]);
}

export async function encryptPkcs8(pkcs8, password, iterations = KEY_PBKDF2_ITERATIONS) {
  const salt = randomBytes(16), iv = randomBytes(16);
  const key = await pbkdf2Aes(password, salt, iterations, "encrypt");
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, key, pkcs8));
  const der = derSeq(
    derSeq(derOid(OID.pbes2), derSeq(
      derSeq(derOid(OID.pbkdf2),
             derSeq(derOctets(salt), derInt(iterations), derSeq(derOid(OID.hmacSha256),
                                                                new Uint8Array([5, 0])))),
      derSeq(derOid(OID.aes256cbc), derOctets(iv)))),
    derOctets(ct));
  return derToPem(der, "ENCRYPTED PRIVATE KEY");
}

export class WrongPasswordError extends Error {}

// Returns the unencrypted PKCS#8 bytes. Throws WrongPasswordError on a bad password.
export async function decryptPkcs8(pem, password) {
  if (!/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem))
    throw new Error("not a password-protected private key (expected ENCRYPTED PRIVATE KEY)");
  const buf = pemToDer(pem);
  const [alg, data] = derChildren(buf, derRead(buf, 0));
  const [algOid, params] = derChildren(buf, alg);
  const [kdf, enc] = derChildren(buf, params);
  const [kdfOid, kdfParams] = derChildren(buf, kdf);
  const [encOid, ivNode] = derChildren(buf, enc);
  const kp = derChildren(buf, kdfParams);
  const prf = kp.find((n) => n.tag === 0x30);
  if (hex(derBytes(buf, algOid)) !== OID.pbes2 || hex(derBytes(buf, kdfOid)) !== OID.pbkdf2
      || hex(derBytes(buf, encOid)) !== OID.aes256cbc
      || !prf || hex(derBytes(buf, derChildren(buf, prf)[0])) !== OID.hmacSha256)
    throw new Error("unsupported key encryption (need PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC)");
  const iterations = derBytes(buf, kp[1]).reduce((n, b) => n * 256 + b, 0);
  const key = await pbkdf2Aes(password, derBytes(buf, kp[0]), iterations, "decrypt");
  let pkcs8;
  try {
    pkcs8 = new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv: derBytes(buf, ivNode) },
                                                key, derBytes(buf, data)));
    await importPkcs8(pkcs8);   // catches the rare wrong password that still unpads cleanly
  } catch {
    throw new WrongPasswordError("wrong password for this key file");
  }
  return pkcs8;
}

export async function unlockKey(pem, password) {
  return importPkcs8(await decryptPkcs8(pem, password));
}

// --- session channel primitives -------------------------------------------------

export async function hkdfSessionKeys(master, salt) {
  const ikm = await subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8("secure-exam session v1") }, ikm, 512));
}

export async function importChannelKeys(kEnc, kMac) {
  return {
    enc: await subtle.importKey("raw", kEnc, "AES-CBC", false, ["encrypt", "decrypt"]),
    mac: await subtle.importKey("raw", kMac, { name: "HMAC", hash: "SHA-256" }, false,
                                ["sign", "verify"]),
  };
}

export async function aesCbcEncrypt(key, plaintext) {
  const iv = randomBytes(16);
  return { iv, ct: new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, key, plaintext)) };
}

export async function aesCbcDecrypt(key, iv, ct) {
  return new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv }, key, ct));
}

export async function hmacSign(key, data) {
  return new Uint8Array(await subtle.sign("HMAC", key, data));
}

export async function hmacVerify(key, tag, data) {
  return subtle.verify("HMAC", key, tag, data);
}
