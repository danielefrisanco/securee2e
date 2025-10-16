class k {
  // This is a private, in-memory variable that holds the keys for the current session.
  store = null;
  storageKey = "securee2e-ltid-inmemory-mock";
  // Placeholder key
  async load() {
    return this.store ? JSON.parse(JSON.stringify(this.store)) : null;
  }
  async save(e) {
    this.store = e;
  }
  async clear() {
    this.store = null;
  }
}
const C = "securee2e-db", I = 1, a = "ltid_keys", p = "user_ltid_keys";
class A {
  /**
   * Opens a connection to the IndexedDB database.
   * If the database or object store does not exist, it creates them.
   * @returns A Promise that resolves to an IDBDatabase instance.
   */
  openDatabase() {
    return new Promise((e, r) => {
      if (typeof window > "u" || !window.indexedDB)
        return console.error("IndexedDB is not supported or available."), r(new Error("IndexedDB not supported."));
      const s = indexedDB.open(C, I);
      s.onupgradeneeded = (n) => {
        const o = n.target.result;
        o.objectStoreNames.contains(a) || (o.createObjectStore(a), console.debug(`IndexedDB: Created object store ${a}`));
      }, s.onsuccess = (n) => {
        e(n.target.result);
      }, s.onerror = (n) => {
        console.error("IndexedDB Error:", n.target.error), r(n.target.error);
      };
    });
  }
  /**
   * Helper to check if IndexedDB is available (useful for the fallback logic).
   */
  isAvailable() {
    return typeof window < "u" && !!window.indexedDB;
  }
  /**
   * Reads the LTID keys from the IndexedDB.
   * @returns A Promise that resolves to the LTIDKeySet or null if not found.
   */
  async load() {
    if (!this.isAvailable()) return null;
    try {
      const e = await this.openDatabase();
      return new Promise((r) => {
        const o = e.transaction([a], "readonly").objectStore(a).get(p);
        o.onsuccess = () => {
          e.close();
          const c = o.result;
          r(c || null);
        }, o.onerror = () => {
          e.close(), console.warn("IndexedDB Load Warning: Failed to retrieve key, treating as null."), r(null);
        };
      });
    } catch (e) {
      return console.error("IndexedDB Load Critical Error:", e), null;
    }
  }
  /**
   * Writes the LTID keys to the IndexedDB.
   * @param keyset The LTIDKeySet object to save.
   * @returns A Promise that resolves when the save is complete.
   */
  async save(e) {
    if (this.isAvailable())
      try {
        const r = await this.openDatabase();
        return new Promise((s, n) => {
          const y = r.transaction([a], "readwrite").objectStore(a).put(e, p);
          y.onsuccess = () => {
            r.close(), console.debug("IndexedDB: LTID keys saved successfully."), s();
          }, y.onerror = (u) => {
            r.close();
            const w = u.target.error;
            console.error("IndexedDB Save Error:", w), n(w);
          };
        });
      } catch (r) {
        throw console.error("IndexedDB Save Critical Error:", r), r;
      }
  }
  /**
   * Clears the LTID keys from the IndexedDB store.
   * @returns A Promise that resolves when the clear operation is complete.
   */
  async clear() {
    if (this.isAvailable())
      try {
        const e = await this.openDatabase();
        return new Promise((r, s) => {
          const c = e.transaction([a], "readwrite").objectStore(a).delete(p);
          c.onsuccess = () => {
            e.close(), console.debug("IndexedDB: LTID keys cleared successfully."), r();
          }, c.onerror = (y) => {
            e.close();
            const u = y.target.error;
            console.error("IndexedDB Clear Error:", u), s(u);
          };
        });
      } catch (e) {
        throw console.error("IndexedDB Clear Critical Error:", e), e;
      }
  }
}
function T() {
  return typeof window < "u" && window.indexedDB ? (console.log("STORAGE: Using IndexedDBProvider for persistent storage."), new A()) : (console.warn("STORAGE: IndexedDB not available. Falling back to InMemoryStorageProvider."), new k());
}
const b = T(), i = (t) => btoa(String.fromCharCode(...new Uint8Array(t))), d = (t) => {
  const e = atob(t), r = e.length, s = new Uint8Array(r);
  for (let n = 0; n < r; n++)
    s[n] = e.charCodeAt(n);
  return s.buffer;
}, K = async () => crypto.subtle.generateKey(
  {
    name: "ECDH",
    namedCurve: "P-256"
  },
  !1,
  // Private key is non-extractable (security best practice)
  ["deriveKey", "deriveBits"]
), R = async () => crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  !0,
  // Keys MUST be extractable (JWK) for LTID storage
  ["sign", "verify"]
), g = async (t) => crypto.subtle.exportKey("jwk", t), f = async (t, e) => crypto.subtle.importKey(
  "jwk",
  t,
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  !0,
  // Keys must be extractable for future export/save
  [e]
), m = async (t) => {
  const e = await crypto.subtle.exportKey("spki", t);
  return i(e);
}, v = async (t) => {
  const e = await crypto.subtle.exportKey("spki", t);
  return i(e);
}, D = async (t) => {
  const e = d(t);
  return crypto.subtle.importKey(
    "spki",
    e,
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    !0,
    []
  );
}, S = async (t) => {
  const e = d(t);
  return crypto.subtle.importKey(
    "spki",
    e,
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    !0,
    ["verify"]
  );
}, P = async (t, e) => {
  const r = await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      namedCurve: "P-256",
      public: e
    },
    t,
    256
  );
  return crypto.subtle.importKey(
    "raw",
    r,
    { name: "AES-GCM", length: 256 },
    !0,
    ["encrypt", "decrypt"]
  );
}, h = async (t, e) => {
  const r = await crypto.subtle.exportKey("spki", e), s = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    t,
    r
  );
  return i(s);
}, x = async (t, e, r) => {
  const s = await crypto.subtle.exportKey("spki", e), n = d(r);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    t,
    n,
    s
  );
}, B = async (t, e) => {
  const r = crypto.getRandomValues(new Uint8Array(12)), s = new TextEncoder().encode(e), n = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: r },
    t,
    s
  );
  return {
    iv: i(r.buffer),
    ciphertext: i(n)
  };
}, E = async (t, e, r) => {
  const s = d(e), n = d(r), o = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: s },
    t,
    n
  );
  return new TextDecoder().decode(o);
}, L = async () => {
  const t = await b.load();
  if (t) {
    const o = await f(t.ecdsaPrivateKeyJwk, "sign"), c = await f(t.ecdsaPublicKeyJwk, "verify");
    return console.log("LTID: Loaded keys successfully from storage."), { ecdsaPrivateKey: o, ecdsaPublicKey: c };
  }
  const e = await R(), r = await g(e.privateKey), s = await g(e.publicKey), n = { ecdsaPrivateKeyJwk: r, ecdsaPublicKeyJwk: s };
  return await b.save(n), console.log("LTID: New keys generated and saved to storage."), { ecdsaPrivateKey: e.privateKey, ecdsaPublicKey: e.publicKey };
};
let l;
const M = async () => {
  if (!l)
    throw new Error("LTID keys were not initialized. Await useDiffieHellman() first.");
  const t = l, e = await K(), [r, s] = await Promise.all([
    m(e.publicKey),
    v(t.ecdsaPublicKey)
  ]), n = await h(t.ecdsaPrivateKey, e.publicKey);
  return {
    payload: {
      ecdhPublicKey: r,
      ecdsaPublicKey: s,
      signature: n
    },
    keys: [e.privateKey, t.ecdsaPrivateKey]
  };
}, J = async (t, e) => {
  const r = await D(e.ecdhPublicKey), s = await S(e.ecdsaPublicKey);
  if (!await x(
    s,
    r,
    e.signature
  ))
    throw new Error("Remote key signature is invalid.");
  return await P(
    t,
    r
  );
}, O = (t, e) => B(t, e), _ = (t, e) => E(t, e.iv, e.ciphertext), j = async () => (l = await L(), {
  // LTID KEY MANAGEMENT
  // The explicit method is still exported for completeness, though it runs on initialization.
  generateLongTermIdentityKeys: () => Promise.resolve(l),
  // High-Level Exports
  generateLocalAuthPayload: M,
  deriveSecretFromRemotePayload: J,
  encryptMessage: O,
  decryptMessage: _,
  // Low-Level Exports
  generateKeyPair: K,
  exportPublicKeyBase64: m,
  exportSigningPublicKeyBase64: v,
  importRemotePublicKeyBase64: D,
  importRemoteSigningPublicKeyBase64: S,
  deriveSharedSecret: P,
  signPublicKey: h,
  verifySignature: x,
  encryptData: B,
  decryptData: E
});
export {
  j as useDiffieHellman
};
