// IndexedDB holds authenticated ciphertext only. Keys/passphrases never enter
// browser persistent storage in plaintext or a network request.
const DATABASE = 'galinsky-protected-v2',
  STORE = 'vaults';
let opening;
function database() {
  if (!opening)
    opening = new Promise((resolve, reject) => {
      const req = indexedDB.open(DATABASE, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: 'key' });
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(Error('This browser could not open encrypted local storage.'));
      req.onblocked = () =>
        reject(Error('Close another protected tab before changing local storage.'));
    });
  return opening;
}
export const deviceEntry = (account) => 'device:' + account;
export const pendingDeviceEntry = (account) => 'pending-device:' + account;
export const threadEntry = (account, record) => 'thread:' + account + ':' + record;
export async function protectedLocalGet(key) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(Error('Encrypted local storage could not be read.'));
  });
}
export async function protectedLocalList(account) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).getAll();
    req.onsuccess = () => resolve(req.result.filter((r) => r.account === account));
    req.onerror = () => reject(Error('Encrypted local storage could not be listed.'));
  });
}
export async function protectedLocalCommit(changes) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite'),
      store = tx.objectStore(STORE);
    let reason = 'Encrypted local storage changed in another tab. Synchronize before continuing.';
    for (const change of changes) {
      const req = store.get(change.key);
      req.onsuccess = () => {
        const old = req.result;
        if ((old?.generation || 0) !== change.expected) {
          tx.abort();
          return;
        }
        if (change.next) store.put(change.next);
        else store.delete(change.key);
      };
      req.onerror = () => {
        reason = 'Encrypted local storage could not be checked.';
      };
    }
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(Error(reason));
    tx.onerror = () => {
      reason = 'Encrypted local storage is unavailable or full. No private message was sent.';
    };
  });
}
export async function withProtectedLock(account, fn) {
  if (!navigator.locks?.request)
    throw Error(
      'This browser cannot safely coordinate protected state. Use a supported, updated browser.',
    );
  return navigator.locks.request('g28-protected:' + account, fn);
}
export async function deleteProtectedLocalAccount(account) {
  if (typeof BroadcastChannel === 'function') {
    const channel = new BroadcastChannel('g28-protected-lock');
    channel.postMessage({ account, action: 'lock' });
    channel.close();
  }
  return withProtectedLock(account, async () => {
    const rows = await protectedLocalList(account);
    await protectedLocalCommit(
      rows.map((r) => ({ key: r.key, expected: r.generation, next: null })),
    );
  });
}
