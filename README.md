# securee2e

End-to-end encryption for the browser, built on the native **Web Crypto API**. Framework-agnostic core with an optional **Vue 3 composable**.

- **Authenticated key exchange** — ephemeral ECDH P-256 keys, signed by a persistent ECDSA P-256 identity key.
- **Identity pinning** — verify the remote identity by public key or fingerprint to actually stop man-in-the-middle attacks.
- **Proper key derivation** — ECDH → HKDF-SHA256 → AES-256-GCM, bound to the session transcript.
- **Non-extractable keys** — the identity private key is stored in IndexedDB as a `CryptoKey`; its bytes never leave the browser's crypto engine, even to XSS.
- **AES-256-GCM messaging** — fresh 96-bit nonce per message, optional additional authenticated data (AAD), strings or binary.
- **Typed errors**, zero runtime dependencies, ESM + CJS, full TypeScript types.

```bash
npm install securee2e
# Vue users need vue >= 3.3 (it is an optional peer dependency)
```

## Quick start (any framework)

```ts
import { createSecureE2E, IdentityMismatchError } from 'securee2e';

const e2e = createSecureE2E(); // identity is loaded/generated on first use (IndexedDB)

// 1. Each side creates a signed, ephemeral key-exchange payload and sends it to the other.
const local = await e2e.generateLocalAuthPayload();
send(local.payload); // { v: 1, ecdhPublicKey, ecdsaPublicKey, signature } — plain JSON

// 2. Verify the remote payload and derive the shared session key.
//    Pin the remote identity (key or fingerprint) so a MITM can't substitute their own.
const sessionKey = await e2e.deriveSecretFromRemotePayload(local, remotePayload, {
  expectedFingerprint: knownFingerprintOfBob, // or expectedIdentityKey: knownPublicKeyOfBob
});

// 3. Encrypt / decrypt.
const encrypted = await e2e.encryptMessage(sessionKey, 'hello', { aad: 'chat:42|seq:1' });
const plaintext = await e2e.decryptMessage(sessionKey, encrypted, { aad: 'chat:42|seq:1' });
```

### Sharing your identity so peers can pin you

```ts
await e2e.getIdentityPublicKey();   // Base64 SPKI — store it in your user directory
await e2e.getIdentityFingerprint(); // "A1B2 C3D4 …" — show it in the UI / QR code for out-of-band comparison
```

### Trust on first use (TOFU)

If you have no directory, verify first, remember the fingerprint, and pin it from then on:

```ts
const { fingerprint } = await e2e.verifyRemotePayload(remotePayload); // throws if malformed or badly signed
const known = trustStore.get(remoteUserId);
if (known && known !== fingerprint) throw new Error('Identity changed! Verify out-of-band.');
trustStore.set(remoteUserId, fingerprint);
const sessionKey = await e2e.deriveSecretFromRemotePayload(local, remotePayload, { expectedFingerprint: fingerprint });
```

## Vue 3

```ts
import { useSecureE2E } from 'securee2e/vue';

const { isReady, identityFingerprint, error, generateLocalAuthPayload, deriveSecretFromRemotePayload, encryptMessage, decryptMessage } =
  useSecureE2E();
```

```vue
<p v-if="error">{{ error.message }}</p>
<p v-else-if="!isReady">Loading identity…</p>
<code v-else>{{ identityFingerprint }}</code>
```

`useSecureE2E()` starts loading the identity immediately (pass `{ autoInit: false }` to defer) and exposes the same methods as the core plus reactive `isReady`, `isInitializing`, `error`, `identityPublicKey`, `identityFingerprint`, and `resetIdentity()`. It does not require a component instance. Run `npm run dev` for a two-peer playground.

## API

### `createSecureE2E(options?) → SecureE2E`

| Option    | Default                                       | Description                          |
| --------- | --------------------------------------------- | ------------------------------------ |
| `storage` | `IndexedDBProvider` (in-memory outside browsers) | Where the long-term identity lives. |

| Method                                                    | Description                                                                                                  |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `init()`                                                  | Loads or creates the identity. Optional — every method calls it as needed.                                   |
| `isReady`                                                 | `true` once the identity is loaded.                                                                          |
| `getIdentityPublicKey()`                                  | Identity public key (Base64 SPKI).                                                                           |
| `getIdentityFingerprint()`                                | SHA-256 fingerprint of the identity key, `XXXX XXXX …` (16 groups).                                          |
| `resetIdentity()`                                         | Deletes the identity and generates a new one.                                                                |
| `generateLocalAuthPayload()`                              | → `{ payload, ecdhPrivateKey }`. Send `payload`; keep the result for `deriveSecretFromRemotePayload`.        |
| `verifyRemotePayload(remote, options?)`                   | Checks shape, signature and (optionally) identity. → `{ identityKey, fingerprint }`.                         |
| `deriveSecretFromRemotePayload(local, remote, options?)`  | Verifies and derives the AES-256-GCM session key.                                                            |
| `encryptMessage(key, plaintext, { aad? })`                | `plaintext` is a string or `Uint8Array`. → `{ v, iv, ciphertext }`.                                          |
| `decryptMessage(key, payload, { aad? })` / `decryptBytes` | Returns a string / `Uint8Array`.                                                                             |

`VerifyOptions`: `expectedIdentityKey?: string` (Base64 SPKI) and/or `expectedFingerprint?: string` (case/spacing-insensitive).

### Errors

All errors extend `SecureE2EError` and carry a `code`:

| Class                    | Code                 | When                                                                  |
| ------------------------ | -------------------- | --------------------------------------------------------------------- |
| `InvalidPayloadError`    | `INVALID_PAYLOAD`    | Wrong shape/version, or a key that cannot be imported.                |
| `SignatureInvalidError`  | `SIGNATURE_INVALID`  | The ephemeral key was not signed by the identity key in the payload.  |
| `IdentityMismatchError`  | `IDENTITY_MISMATCH`  | Pinned identity differs (`.expected`, `.actual`). **This is the MITM alarm.** |
| `DecryptionError`        | `DECRYPTION_FAILED`  | Wrong key, wrong AAD, or tampered ciphertext.                         |
| `NotInitializedError`    | `NOT_INITIALIZED`    | `deriveSecretFromRemotePayload` before the identity loaded.           |
| `StorageError`           | `STORAGE_ERROR`      | The storage provider failed.                                          |

### Storage providers

| Provider                 | Persistent | Private key extractable | Notes                                                                                   |
| ------------------------ | ---------- | ----------------------- | --------------------------------------------------------------------------------------- |
| `IndexedDBProvider`      | ✅         | **No**                  | Default. Stores `CryptoKey` objects. Options: `dbName`, `storeName`, `recordId`, `migrateLegacyLocalStorage`. |
| `InMemoryStorageProvider`| ❌         | No                      | Tests, SSR, deliberately ephemeral identities.                                          |
| `LocalStorageProvider`   | ✅         | Yes (plaintext JWK)     | Only if IndexedDB is unavailable. Readable by any script on the origin.                 |

```ts
import { createSecureE2E, InMemoryStorageProvider } from 'securee2e';
const e2e = createSecureE2E({ storage: new InMemoryStorageProvider() });
```

Implement `IKeyStorageProvider` (`load` / `save` / `clear`, optional `requiresExtractableKeys`) to plug in anything else. Instances that share a provider share an identity; use `recordId` to keep several identities in one browser.

### Low-level primitives

Everything the high-level API is built from is exported too: `generateEphemeralKeyPair`, `generateIdentityKeyPair`, `exportPublicKeyBase64`, `importEcdhPublicKey`, `importEcdsaPublicKey`, `signEcdhPublicKey`, `verifyEcdhPublicKeySignature`, `deriveSessionKey`, `encrypt`, `decrypt`, `decryptToBytes`, `fingerprint`, `bytesToBase64`, `base64ToBytes`, and `IdentityManager`.

## Wire format (v1)

| Field                    | Encoding                                                                                |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `ecdhPublicKey`, `ecdsaPublicKey` | SPKI DER, standard Base64.                                                     |
| `signature`              | ECDSA P-256 / SHA-256, raw `r‖s` (IEEE P1363, 64 bytes — *not* DER), Base64, over `"securee2e/v1/ecdh-public-key" ‖ SPKI(ecdhPublicKey)`. |
| Session key              | `HKDF-SHA256(ECDH shared secret, salt = "", info = "securee2e/v1/aes-256-gcm|" + sorted(SPKI_A, SPKI_B))` → AES-256-GCM. |
| `iv`                     | 12 random bytes, Base64.                                                                |
| `ciphertext`             | AES-GCM output incl. 16-byte tag, Base64.                                               |

Decoding accepts URL-safe Base64 and missing padding.

## Security notes

1. **Pin identities.** The signature inside a payload only proves the sender holds the identity key *in that payload*. Without `expectedIdentityKey` / `expectedFingerprint` (or comparing fingerprints out-of-band), an attacker can simply present their own payload. `IdentityMismatchError` is the signal that something is wrong.
2. **Session keys are per handshake.** Ephemeral keys give forward secrecy between sessions, not within one. Rotate sessions as often as your threat model needs; there is no ratchet.
3. **Use AAD for replay/reorder protection.** Include a sequence number or message id in `aad` and check it on receipt — AES-GCM authenticates it without encrypting it.
4. **The identity is only as safe as the origin.** A non-extractable key cannot be exfiltrated, but malicious code on your origin could still *use* it. Standard XSS hygiene applies.
5. **`resetIdentity()` is a new identity.** Peers who pinned you will (correctly) reject the new key until they re-verify.

## Roadmap / possible future developments

Not implemented yet; open an issue if you need one of these.

- **Built-in TOFU trust store** — a small `ITrustStore` (peer id → fingerprint, persisted in IndexedDB) so trust-on-first-use is one call instead of the hand-rolled pattern shown above, with an explicit "identity changed" event.
- **Per-message ratchet** — Double-Ratchet-style key evolution for forward secrecy *within* a session, not only between handshakes.
- **Multi-device identities** — one user, several identity keys, with cross-signing so peers pin a user rather than a device.

## Upgrading from 0.4.x

- `useDiffieHellman()` is gone. Use `createSecureE2E()` (any framework) or `useSecureE2E()` from `securee2e/vue`.
- `generateLocalAuthPayload()` returns `{ payload, ecdhPrivateKey }` instead of a `keys` tuple; pass the whole result to `deriveSecretFromRemotePayload(local, remote, options)`.
- Payloads carry `v: 1`, signatures are domain-separated and the session key goes through HKDF — 0.5 peers cannot talk to 0.4 peers.
- `setCurrentStorageProvider()` is replaced by the `storage` option.
- Existing 0.4.0 identities in localStorage are migrated into IndexedDB (as non-extractable keys) on first load.

## License

MIT
