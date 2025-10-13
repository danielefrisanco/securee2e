class h {
  storageKey = "securee2e-ltid-v0-4-0";
  async load() {
    const e = localStorage.getItem(this.storageKey);
    if (e)
      try {
        return JSON.parse(e);
      } catch (r) {
        return console.error("Failed to parse stored LTID key set from localStorage:", r), localStorage.removeItem(this.storageKey), null;
      }
    return null;
  }
  async save(e) {
    localStorage.setItem(this.storageKey, JSON.stringify(e));
  }
  async clear() {
    localStorage.removeItem(this.storageKey);
  }
}
let i = new h();
const c = (t) => btoa(String.fromCharCode(...new Uint8Array(t))), o = (t) => {
  const e = atob(t), r = e.length, a = new Uint8Array(r);
  for (let s = 0; s < r; s++)
    a[s] = e.charCodeAt(s);
  return a.buffer;
}, l = async () => crypto.subtle.generateKey(
  {
    name: "ECDH",
    namedCurve: "P-256"
  },
  !1,
  // Private key is non-extractable (security best practice)
  ["deriveKey", "deriveBits"]
), k = async () => crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  !0,
  // Keys MUST be extractable (JWK) for LTID storage
  ["sign", "verify"]
), y = async (t) => crypto.subtle.exportKey("jwk", t), u = async (t, e) => crypto.subtle.importKey(
  "jwk",
  t,
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  !0,
  // Keys must be extractable for future export/save
  [e]
), d = async (t) => {
  const e = await crypto.subtle.exportKey("spki", t);
  return c(e);
}, p = async (t) => {
  const e = await crypto.subtle.exportKey("spki", t);
  return c(e);
}, K = async (t) => {
  const e = o(t);
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
}, g = async (t) => {
  const e = o(t);
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
}, m = async (t, e) => {
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
}, b = async (t, e) => {
  const r = await crypto.subtle.exportKey("spki", e), a = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    t,
    r
  );
  return c(a);
}, w = async (t, e, r) => {
  const a = await crypto.subtle.exportKey("spki", e), s = o(r);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    t,
    s,
    a
  );
}, v = async (t, e) => {
  const r = crypto.getRandomValues(new Uint8Array(12)), a = new TextEncoder().encode(e), s = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: r },
    t,
    a
  );
  return {
    iv: c(r.buffer),
    ciphertext: c(s)
  };
}, f = async (t, e, r) => {
  const a = o(e), s = o(r), n = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: a },
    t,
    s
  );
  return new TextDecoder().decode(n);
}, S = async () => {
  const t = await i.load();
  if (t) {
    const n = await u(t.ecdsaPrivateKeyJwk, "sign"), P = await u(t.ecdsaPublicKeyJwk, "verify");
    return console.log("LTID: Loaded keys successfully from storage."), { ecdsaPrivateKey: n, ecdsaPublicKey: P };
  }
  const e = await k(), r = await y(e.privateKey), a = await y(e.publicKey), s = { ecdsaPrivateKeyJwk: r, ecdsaPublicKeyJwk: a };
  return await i.save(s), console.log("LTID: New keys generated and saved to storage."), { ecdsaPrivateKey: e.privateKey, ecdsaPublicKey: e.publicKey };
}, C = async () => {
  const t = await S(), e = await l(), [r, a] = await Promise.all([
    d(e.publicKey),
    p(t.ecdsaPublicKey)
  ]), s = await b(t.ecdsaPrivateKey, e.publicKey);
  return {
    payload: {
      ecdhPublicKey: r,
      ecdsaPublicKey: a,
      signature: s
    },
    keys: [e.privateKey, t.ecdsaPrivateKey]
  };
}, x = async (t, e) => {
  const r = await K(e.ecdhPublicKey), a = await g(e.ecdsaPublicKey);
  if (!await w(
    a,
    r,
    e.signature
  ))
    throw new Error("Remote key signature is invalid.");
  return await m(
    t,
    r
  );
}, D = (t, e) => v(t, e), A = (t, e) => f(t, e.iv, e.ciphertext), B = () => ({
  // LTID KEY MANAGEMENT
  generateLongTermIdentityKeys: S,
  // High-Level Exports
  generateLocalAuthPayload: C,
  deriveSecretFromRemotePayload: x,
  encryptMessage: D,
  decryptMessage: A,
  // Low-Level Exports
  generateKeyPair: l,
  exportPublicKeyBase64: d,
  exportSigningPublicKeyBase64: p,
  importRemotePublicKeyBase64: K,
  importRemoteSigningPublicKeyBase64: g,
  deriveSharedSecret: m,
  signPublicKey: b,
  verifySignature: w,
  encryptData: v,
  decryptData: f
});
export {
  B as useDiffieHellman
};
