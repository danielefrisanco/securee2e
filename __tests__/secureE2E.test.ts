import { describe, expect, it, vi } from 'vitest';
import {
    createSecureE2E,
    DecryptionError,
    IdentityMismatchError,
    InMemoryStorageProvider,
    InvalidPayloadError,
    NotInitializedError,
    SignatureInvalidError,
    type IKeyStorageProvider,
    type KeyAuthPayload,
} from '../src/index';

const alice = () => createSecureE2E({ storage: new InMemoryStorageProvider() });
const bob = () => createSecureE2E({ storage: new InMemoryStorageProvider() });

async function handshake() {
    const a = alice();
    const b = bob();
    const aLocal = await a.generateLocalAuthPayload();
    const bLocal = await b.generateLocalAuthPayload();
    const aKey = await a.deriveSecretFromRemotePayload(aLocal, bLocal.payload, { expectedIdentityKey: await b.getIdentityPublicKey() });
    const bKey = await b.deriveSecretFromRemotePayload(bLocal, aLocal.payload, { expectedIdentityKey: await a.getIdentityPublicKey() });
    return { a, b, aLocal, bLocal, aKey, bKey };
}

describe('createSecureE2E — identity', () => {
    it('lazily initialises and exposes identity key + fingerprint', async () => {
        const a = alice();
        expect(a.isReady).toBe(false);
        const key = await a.getIdentityPublicKey();
        expect(a.isReady).toBe(true);
        expect(key).toMatch(/^[A-Za-z0-9+/]+=*$/);
        expect(await a.getIdentityFingerprint()).toMatch(/^([0-9A-F]{4} ){15}[0-9A-F]{4}$/);
    });

    it('generates the identity only once under concurrent initialisation', async () => {
        const storage = new InMemoryStorageProvider();
        const save = vi.spyOn(storage, 'save');
        const e2e = createSecureE2E({ storage });
        const [k1, k2, k3] = await Promise.all([e2e.getIdentityPublicKey(), e2e.generateLocalAuthPayload(), e2e.getIdentityFingerprint()]);
        expect(save).toHaveBeenCalledTimes(1);
        expect(k2.payload.ecdsaPublicKey).toBe(k1);
        expect(k3).toBeTypeOf('string');
    });

    it('instances sharing a storage share an identity; separate storages do not', async () => {
        const storage = new InMemoryStorageProvider();
        const one = createSecureE2E({ storage });
        const two = createSecureE2E({ storage });
        expect(await two.getIdentityPublicKey()).toBe(await one.getIdentityPublicKey());
        expect(await alice().getIdentityPublicKey()).not.toBe(await one.getIdentityPublicKey());
    });

    it('resetIdentity() produces a new identity that pinned peers reject', async () => {
        const { a, b, bLocal } = await handshake();
        const oldKey = await a.getIdentityPublicKey();
        await a.resetIdentity();
        expect(await a.getIdentityPublicKey()).not.toBe(oldKey);

        const aLocal2 = await a.generateLocalAuthPayload();
        await expect(b.deriveSecretFromRemotePayload(bLocal, aLocal2.payload, { expectedIdentityKey: oldKey })).rejects.toBeInstanceOf(IdentityMismatchError);
    });

    it('retries initialisation after a storage failure', async () => {
        let fail = true;
        const storage: IKeyStorageProvider = {
            load: async () => {
                if (fail) throw new Error('boom');
                return null;
            },
            save: async () => {},
            clear: async () => {},
        };
        const e2e = createSecureE2E({ storage });
        await expect(e2e.init()).rejects.toThrow('boom');
        fail = false;
        await expect(e2e.init()).resolves.toBeUndefined();
        expect(e2e.isReady).toBe(true);
    });

    it('deriveSecretFromRemotePayload requires an initialised identity', async () => {
        const a = alice();
        const bLocal = await bob().generateLocalAuthPayload();
        const fakeLocal = { payload: bLocal.payload, ecdhPrivateKey: bLocal.ecdhPrivateKey };
        await expect(a.deriveSecretFromRemotePayload(fakeLocal, bLocal.payload)).rejects.toBeInstanceOf(NotInitializedError);
    });
});

describe('createSecureE2E — handshake', () => {
    it('produces a well-formed v1 payload with a non-extractable private key', async () => {
        const { payload, ecdhPrivateKey } = await alice().generateLocalAuthPayload();
        expect(payload.v).toBe(1);
        expect(payload).toEqual({ v: 1, ecdhPublicKey: expect.any(String), ecdsaPublicKey: expect.any(String), signature: expect.any(String) });
        expect(ecdhPrivateKey.extractable).toBe(false);
        expect(JSON.parse(JSON.stringify(payload))).toEqual(payload); // serialisable
    });

    it('both parties derive an identical session key and can talk', async () => {
        const { a, b, aKey, bKey } = await handshake();
        const toBob = await a.encryptMessage(aKey, 'hi bob');
        expect(await b.decryptMessage(bKey, toBob)).toBe('hi bob');
        const toAlice = await b.encryptMessage(bKey, 'hi alice');
        expect(await a.decryptMessage(aKey, toAlice)).toBe('hi alice');
    });

    it('works after payloads went through JSON (network simulation)', async () => {
        const a = alice();
        const b = bob();
        const aLocal = await a.generateLocalAuthPayload();
        const bLocal = await b.generateLocalAuthPayload();
        const wire = JSON.parse(JSON.stringify(bLocal.payload));
        const aKey = await a.deriveSecretFromRemotePayload(aLocal, wire);
        const bKey = await b.deriveSecretFromRemotePayload(bLocal, JSON.parse(JSON.stringify(aLocal.payload)));
        const enc = JSON.parse(JSON.stringify(await a.encryptMessage(aKey, 'over the wire')));
        expect(await b.decryptMessage(bKey, enc)).toBe('over the wire');
    });

    it('verifyRemotePayload returns identity + fingerprint without deriving', async () => {
        const b = bob();
        const bLocal = await b.generateLocalAuthPayload();
        const info = await alice().verifyRemotePayload(bLocal.payload);
        expect(info.identityKey).toBe(await b.getIdentityPublicKey());
        expect(info.fingerprint).toBe(await b.getIdentityFingerprint());
    });

    it('supports binary messages and AAD through the high-level API', async () => {
        const { a, b, aKey, bKey } = await handshake();
        const bytes = crypto.getRandomValues(new Uint8Array(1024));
        const enc = await a.encryptMessage(aKey, bytes, { aad: 'seq:1' });
        expect(await b.decryptBytes(bKey, enc, { aad: 'seq:1' })).toEqual(bytes);
        await expect(b.decryptBytes(bKey, enc, { aad: 'seq:2' })).rejects.toBeInstanceOf(DecryptionError);
    });
});

describe('createSecureE2E — attacks', () => {
    it('rejects a payload whose signature was made by another identity', async () => {
        const a = alice();
        const aLocal = await a.generateLocalAuthPayload();
        const bLocal = await bob().generateLocalAuthPayload();
        const malloryLocal = await bob().generateLocalAuthPayload();

        // Mallory keeps Bob's identity key but swaps in her own ephemeral key + signature.
        const forged: KeyAuthPayload = { ...malloryLocal.payload, ecdsaPublicKey: bLocal.payload.ecdsaPublicKey };
        await expect(a.deriveSecretFromRemotePayload(aLocal, forged)).rejects.toBeInstanceOf(SignatureInvalidError);
    });

    it('rejects a substituted ephemeral key', async () => {
        const a = alice();
        const aLocal = await a.generateLocalAuthPayload();
        const bLocal = await bob().generateLocalAuthPayload();
        const other = await bob().generateLocalAuthPayload();
        const tampered: KeyAuthPayload = { ...bLocal.payload, ecdhPublicKey: other.payload.ecdhPublicKey };
        await expect(a.deriveSecretFromRemotePayload(aLocal, tampered)).rejects.toBeInstanceOf(SignatureInvalidError);
    });

    it('a full self-signed MITM payload passes without pinning but fails with expectedIdentityKey / expectedFingerprint', async () => {
        const a = alice();
        const b = bob();
        const mallory = bob();
        const aLocal = await a.generateLocalAuthPayload();
        const malloryLocal = await mallory.generateLocalAuthPayload();

        // Without pinning this is indistinguishable from a legitimate first contact.
        await expect(a.deriveSecretFromRemotePayload(aLocal, malloryLocal.payload)).resolves.toBeInstanceOf(CryptoKey);

        const bobKey = await b.getIdentityPublicKey();
        await expect(a.deriveSecretFromRemotePayload(aLocal, malloryLocal.payload, { expectedIdentityKey: bobKey })).rejects.toBeInstanceOf(IdentityMismatchError);

        const bobFp = await b.getIdentityFingerprint();
        const err = await a.deriveSecretFromRemotePayload(aLocal, malloryLocal.payload, { expectedFingerprint: bobFp }).catch((e) => e);
        expect(err).toBeInstanceOf(IdentityMismatchError);
        expect(err.expected).toBe(bobFp);
        expect(err.actual).toBe(await mallory.getIdentityFingerprint());
    });

    it('fingerprint comparison ignores case, spacing and separators', async () => {
        const a = alice();
        const b = bob();
        const aLocal = await a.generateLocalAuthPayload();
        const bLocal = await b.generateLocalAuthPayload();
        const fp = (await b.getIdentityFingerprint()).toLowerCase().replace(/ /g, '-');
        await expect(a.deriveSecretFromRemotePayload(aLocal, bLocal.payload, { expectedFingerprint: fp })).resolves.toBeInstanceOf(CryptoKey);
    });

    it('rejects malformed payloads with InvalidPayloadError', async () => {
        const a = alice();
        const aLocal = await a.generateLocalAuthPayload();
        const good = (await bob().generateLocalAuthPayload()).payload;

        for (const bad of [null, 'string', {}, { ...good, v: 2 }, { ...good, signature: undefined }]) {
            await expect(a.deriveSecretFromRemotePayload(aLocal, bad)).rejects.toBeInstanceOf(InvalidPayloadError);
        }
        await expect(a.deriveSecretFromRemotePayload(aLocal, { ...good, ecdsaPublicKey: 'AAAA' })).rejects.toBeInstanceOf(InvalidPayloadError);
        await expect(a.deriveSecretFromRemotePayload(aLocal, { ...good, ecdsaPublicKey: 'not base64!' })).rejects.toBeInstanceOf(InvalidPayloadError);
        await expect(a.decryptMessage(await a.deriveSecretFromRemotePayload(aLocal, good), { iv: 'x' })).rejects.toBeInstanceOf(InvalidPayloadError);
    });

    it('messages for one session cannot be read in another', async () => {
        const s1 = await handshake();
        const s2 = await handshake();
        const enc = await s1.a.encryptMessage(s1.aKey, 'session 1');
        await expect(s2.b.decryptMessage(s2.bKey, enc)).rejects.toBeInstanceOf(DecryptionError);
    });
});
