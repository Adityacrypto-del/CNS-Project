// Device-local storage in IndexedDB. Private keys are stored only as password-encrypted
// PKCS#8 PEM (the same file format as data/clients/<id>_key.pem), never in usable form.
// Receipts are kept so a student can re-download their proof of submission.

const DB_NAME = "secure-exam";
let dbPromise = null;
const memory = { keys: new Map(), receipts: new Map() };   // fallback when IndexedDB is blocked

function openDb() {
  dbPromise ??= new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore("keys", { keyPath: "id" });
        req.result.createObjectStore("receipts", { keyPath: "id" });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
      req.onblocked = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  return dbPromise;
}

async function run(store, mode, fn) {
  const db = await openDb();
  if (!db) return fn(null, memory[store]);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const req = fn(tx.objectStore(store), null);
    tx.oncomplete = () => resolve(req?.result);
    tx.onerror = () => reject(tx.error);
  });
}

const get = (store, id) => run(store, "readonly", (s, m) => (s ? s.get(id) : m.get(id)));
const put = (store, rec) => run(store, "readwrite", (s, m) => (s ? s.put(rec) : m.set(rec.id, rec)));
const del = (store, id) => run(store, "readwrite", (s, m) => (s ? s.delete(id) : m.delete(id)));

export const keyId = (role, userId) => `${role}:${userId}`;

export async function persistent() { return (await openDb()) !== null; }

export async function loadKeyPem(role, userId) {
  return (await get("keys", keyId(role, userId)))?.pem ?? null;
}

export async function saveKeyPem(role, userId, pem) {
  await put("keys", { id: keyId(role, userId), role, user_id: userId, pem, saved_at: Date.now() });
}

export async function deleteKey(role, userId) { await del("keys", keyId(role, userId)); }

export async function saveReceipt(userId, examId, receipt) {
  await put("receipts", { id: `${userId}:${examId}`, receipt });
}

export async function loadReceipt(userId, examId) {
  return (await get("receipts", `${userId}:${examId}`))?.receipt ?? null;
}
