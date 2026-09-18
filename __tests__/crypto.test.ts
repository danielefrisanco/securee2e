import { describe, expect, it } from 'vitest';
import {
    decrypt,
    decryptToBytes,
    deriveSessionKey,
    encrypt,
    exportPublicKeyBase64,
    fingerprint,
    generateEphemeralKeyPair,
    generateIdentityKeyPair,
    importEcdhPublicKey,
    importEcdsaPublicKey,
    normalizeFingerprint,
    signEcdhPublicKey,
    verifyEcdhPublicKeySignature,
} from '../src/core/crypto';
import { DecryptionError } from '../src/core/errors';
import { bytesToBase64 } from '../src/core/base64';
import { randomBytes } from './helpers';

async function sessionKeyPair() {
    const a = await generateEphemeralKeyPair();
    const b = await generateEphemeralKeyPair();
    const aPub = await exportPublicKeyBase64(a.publicKey);
    const bPub = await exportPublicKeyBase64(b.publicKey);
    const keyA = await deriveSessionKey(a.privateKey, await importEcdhPublicKey(bPub), aPub, bPub);
    const keyB = await deriveSessionKey(b.privateKey, await importEcdhPublicKey(aPub), bPub, aPub);
    return { keyA, keyB, a, b, aPub, bPub };
}

describe('key generation', () => {
    it('generates non-extractable ephemeral ECDH keys with deriveBits usage only', async () => {
        const pair = await generateEphemeralKeyPair();
        expect(pair.privateKey.extractable).toBe(false);
        expect(pair.privateKey.algorithm).toMatchObject({ name: 'ECDH', namedCurve: 'P-256' });
        expect(pair.privateKey.usages).toEqual(['deriveBits']);
    });

    it('generates non-extractable identity keys by default', async () => {
        const pair = await generateIdentityKeyPair();
        expect(pair.privateKey.extractable).toBe(false);
        expect(pair.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
        expect((await generateIdentityKeyPair(true)).privateKey.extractable).toBe(true);
    });

    it('exports/imports public keys as SPKI Base64', async () => {
        const pair = await generateEphemeralKeyPair();
        const b64 = await exportPublicKeyBase64(pair.publicKey);
        expect(b64).toMatch(/^[A-Za-z0-9+/]+=*$/);
        const imported = await importEcdhPublicKey(b64);
        expect(await exportPublicKeyBase64(imported)).toBe(b64);
        await expect(importEcdhPublicKey('AAAA')).rejects.toThrow();
    });
});

describe('signatures', () => {
    it('signs and verifies an ephemeral public key with the identity key', async () => {
        const identity = await generateIdentityKeyPair();
        const ephemeralPub = await exportPublicKeyBase64((await generateEphemeralKeyPair()).publicKey);
        const sig = await signEcdhPublicKey(identity.privateKey, ephemeralPub);
        expect(await verifyEcdhPublicKeySignature(identity.publicKey, ephemeralPub, sig)).toBe(true);
    });

    it('rejects a signature from a different identity, over a different key, or corrupted', async () => {
        const identity = await generateIdentityKeyPair();
        const other = await generateIdentityKeyPair();
        const ephemeralPub = await exportPublicKeyBase64((await generateEphemeralKeyPair()).publicKey);
        const otherPub = await exportPublicKeyBase64((await generateEphemeralKeyPair()).publicKey);
        const sig = await signEcdhPublicKey(identity.privateKey, ephemeralPub);

        expect(await verifyEcdhPublicKeySignature(other.publicKey, ephemeralPub, sig)).toBe(false);
        expect(await verifyEcdhPublicKeySignature(identity.publicKey, otherPub, sig)).toBe(false);
        expect(await verifyEcdhPublicKeySignature(identity.publicKey, ephemeralPub, 'not base64!!')).toBe(false);
        expect(await verifyEcdhPublicKeySignature(identity.publicKey, ephemeralPub, bytesToBase64(new Uint8Array(64)))).toBe(false);
    });

    it('is domain separated: a raw signature over the SPKI bytes alone does not verify', async () => {
        const identity = await generateIdentityKeyPair();
        const ephemeralPub = await exportPublicKeyBase64((await generateEphemeralKeyPair()).publicKey);
        const rawSig = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            identity.privateKey,
            Uint8Array.from(atob(ephemeralPub), (c) => c.charCodeAt(0)),
        );
        expect(await verifyEcdhPublicKeySignature(identity.publicKey, ephemeralPub, bytesToBase64(rawSig))).toBe(false);
    });

    it('verifies with a re-imported public key', async () => {
        const identity = await generateIdentityKeyPair();
        const idPub = await exportPublicKeyBase64(identity.publicKey);
        const ephemeralPub = await exportPublicKeyBase64((await generateEphemeralKeyPair()).publicKey);
        const sig = await signEcdhPublicKey(identity.privateKey, ephemeralPub);
        expect(await verifyEcdhPublicKeySignature(await importEcdsaPublicKey(idPub), ephemeralPub, sig)).toBe(true);
    });
});

describe('fingerprint', () => {
    it('is deterministic, 64 hex chars in 16 groups', async () => {
        const pub = await exportPublicKeyBase64((await generateIdentityKeyPair()).publicKey);
        const fp = await fingerprint(pub);
        expect(fp).toMatch(/^([0-9A-F]{4} ){15}[0-9A-F]{4}$/);
        expect(await fingerprint(pub)).toBe(fp);
        expect(normalizeFingerprint(fp.toLowerCase().replace(/ /g, ':'))).toBe(fp.replace(/ /g, ''));
    });
});

describe('session key derivation', () => {
    it('both sides derive the same key, non-extractable, usable for encrypt/decrypt', async () => {
        const { keyA, keyB } = await sessionKeyPair();
        expect(keyA.extractable).toBe(false);
        expect(keyA.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
        const enc = await encrypt(keyA, 'ping');
        expect(await decrypt(keyB, enc)).toBe('ping');
    });

    it('different peers derive different keys', async () => {
        const { a, aPub } = await sessionKeyPair();
        const c = await generateEphemeralKeyPair();
        const cPub = await exportPublicKeyBase64(c.publicKey);
        const keyAC = await deriveSessionKey(a.privateKey, await importEcdhPublicKey(cPub), aPub, cPub);
        const { keyA } = await sessionKeyPair();
        const enc = await encrypt(keyAC, 'x');
        await expect(decrypt(keyA, enc)).rejects.toBeInstanceOf(DecryptionError);
    });

    it('binds the key to the public keys in the transcript (HKDF info)', async () => {
        const { a, b, aPub, bPub } = await sessionKeyPair();
        const bogusPub = await exportPublicKeyBase64((await generateEphemeralKeyPair()).publicKey);
        const keyA = await deriveSessionKey(a.privateKey, await importEcdhPublicKey(bPub), aPub, bPub);
        // Same ECDH secret, but B believes A's public key is something else.
        const keyBWrongInfo = await deriveSessionKey(b.privateKey, await importEcdhPublicKey(aPub), bPub, bogusPub);
        await expect(decrypt(keyBWrongInfo, await encrypt(keyA, 'x'))).rejects.toBeInstanceOf(DecryptionError);
    });
});

describe('AES-GCM encrypt/decrypt', () => {
    it('round-trips strings, bytes, unicode and empty input', async () => {
        const { keyA, keyB } = await sessionKeyPair();
        expect(await decrypt(keyB, await encrypt(keyA, 'héllo 🌍'))).toBe('héllo 🌍');
        expect(await decrypt(keyB, await encrypt(keyA, ''))).toBe('');
        const bytes = randomBytes(300_000);
        expect(await decryptToBytes(keyB, await encrypt(keyA, bytes))).toEqual(bytes);
    });

    it('uses a fresh 12-byte IV per message', async () => {
        const { keyA } = await sessionKeyPair();
        const e1 = await encrypt(keyA, 'same');
        const e2 = await encrypt(keyA, 'same');
        expect(e1.iv).not.toBe(e2.iv);
        expect(e1.ciphertext).not.toBe(e2.ciphertext);
        expect(atob(e1.iv).length).toBe(12);
        expect(e1.v).toBe(1);
    });

    it('detects tampering with ciphertext or IV', async () => {
        const { keyA, keyB } = await sessionKeyPair();
        const enc = await encrypt(keyA, 'authentic');
        const flipped = bytesToBase64(Uint8Array.from(atob(enc.ciphertext), (c, i) => (i === 0 ? c.charCodeAt(0) ^ 1 : c.charCodeAt(0))));
        await expect(decrypt(keyB, { ...enc, ciphertext: flipped })).rejects.toBeInstanceOf(DecryptionError);
        await expect(decrypt(keyB, { ...enc, iv: bytesToBase64(new Uint8Array(12)) })).rejects.toBeInstanceOf(DecryptionError);
    });

    it('binds additional authenticated data', async () => {
        const { keyA, keyB } = await sessionKeyPair();
        const enc = await encrypt(keyA, 'msg', { aad: 'conversation:42|seq:7' });
        expect(await decrypt(keyB, enc, { aad: 'conversation:42|seq:7' })).toBe('msg');
        await expect(decrypt(keyB, enc, { aad: 'conversation:42|seq:8' })).rejects.toBeInstanceOf(DecryptionError);
        await expect(decrypt(keyB, enc)).rejects.toBeInstanceOf(DecryptionError);
    });
});
