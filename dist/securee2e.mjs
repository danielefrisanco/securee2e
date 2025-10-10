const c = (t) => btoa(String.fromCharCode(...new Uint8Array(t))), s = (t) => {
  const e = atob(t), r = e.length, n = new Uint8Array(r);
  for (let a = 0; a < r; a++)
    n[a] = e.charCodeAt(a);
  return n.buffer;
}, o = async () => crypto.subtle.generateKey(
  {
    name: "ECDH",
    namedCurve: "P-256"
  },
  !1,
  // Private key is non-extractable (security best practice)
  ["deriveKey", "deriveBits"]
), y = async () => crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  !0,
  // Public key must be extractable for transport; Private key can be non-extractable
  ["sign", "verify"]
), u = async (t) => {
  const e = await crypto.subtle.exportKey("spki", t);
  return c(e);
}, p = async (t) => {
  const e = await crypto.subtle.exportKey("spki", t);
  return c(e);
}, d = async (t) => {
  const e = s(t);
  return crypto.subtle.importKey(
    "spki",
    e,
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    !0,
    // Key must be extractable for the remote party to use it later
    []
  );
}, l = async (t) => {
  const e = s(t);
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
}, b = async (t, e) => {
  const r = await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      namedCurve: "P-256",
      public: e
      // Requires CryptoKey object
    },
    t,
    256
    // 256 bits for AES-256
  );
  return crypto.subtle.importKey(
    "raw",
    r,
    { name: "AES-GCM", length: 256 },
    !0,
    // Shared key is extractable for storage, though generally not needed
    ["encrypt", "decrypt"]
  );
}, m = async (t, e) => {
  const r = await crypto.subtle.exportKey("spki", e), n = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    t,
    r
  );
  return c(n);
}, K = async (t, e, r) => {
  const n = await crypto.subtle.exportKey("spki", e), a = s(r);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    t,
    a,
    n
  );
}, f = async (t, e) => {
  const r = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), a = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: r },
    t,
    n
  );
  return {
    iv: c(r.buffer),
    ciphertext: c(a)
  };
}, g = async (t, e, r) => {
  const n = s(e), a = s(r), i = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: n },
    t,
    a
  );
  return new TextDecoder().decode(i);
}, w = async () => {
  const t = await o(), e = await y(), r = await u(t.publicKey), n = await p(e.publicKey), a = await m(e.privateKey, t.publicKey);
  return {
    payload: { ecdhPublicKey: r, ecdsaPublicKey: n, signature: a },
    // [0] ECDH Private Key (for derivation), [1] ECDSA Private Key (for future signing if needed)
    keys: [t.privateKey, e.privateKey]
  };
}, v = async (t, e) => {
  const r = await d(e.ecdhPublicKey), n = await l(e.ecdsaPublicKey);
  if (!await K(
    n,
    r,
    e.signature
  ))
    throw new Error("Remote key signature is invalid.");
  return await b(
    t,
    r
    // Correctly passed as a CryptoKey
  );
}, S = (t, e) => f(t, e), h = (t, e) => g(t, e.iv, e.ciphertext), C = () => ({
  // Low-Level Exports
  generateKeyPair: o,
  generateSigningKeys: y,
  exportPublicKeyBase64: u,
  exportSigningPublicKeyBase64: p,
  importRemotePublicKeyBase64: d,
  importRemoteSigningPublicKeyBase64: l,
  deriveSharedSecret: b,
  signPublicKey: m,
  verifySignature: K,
  encryptData: f,
  decryptData: g,
  // High-Level Exports (v0.3.1 API)
  generateLocalAuthPayload: w,
  deriveSecretFromRemotePayload: v,
  encryptMessage: S,
  decryptMessage: h
});
export {
  C as useDiffieHellman
};
