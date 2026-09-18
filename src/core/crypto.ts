/**
 * Low-level Web Crypto primitives. Framework-agnostic and stateless.
 *
 * Construction (v1):
 *   identity  : ECDSA P-256, non-extractable, persisted as a CryptoKey
 *   ephemeral : ECDH  P-256, non-extractable, one per session
 *   signature : ECDSA/SHA-256 over  "securee2e/v1/ecdh-public-key" || SPKI(ephemeral pub)
 *   session   : HKDF-SHA256( ECDH(shared), salt = "", info = "securee2e/v1/aes-256-gcm|" + sorted SPKIs )
 *   messages  : AES-256-GCM, 96-bit random nonce, optional AAD
 */

import { base64ToBytes, bytesToBase64, concatBytes, toBytes } from './base64';
import { DecryptionError } from './errors';
import { PROTOCOL_VERSION, type CipherOptions, type EncryptedPayload } from './types';

const EC_CURVE = 'P-256';
const ECDH_ALGORITHM = { name: 'ECDH', namedCurve: EC_CURVE } as const;
const ECDSA_ALGORITHM = { name: 'ECDSA', namedCurve: EC_CURVE } as const;
const ECDSA_SIGN_PARAMS = { name: 'ECDSA', hash: 'SHA-256' } as const;
const AES_ALGORITHM = { name: 'AES-GCM', length: 256 } as const;
const AES_GCM_IV_BYTES = 12;

/** Domain-separation prefix mixed into every signature, so a signature can't be reused in another protocol. */
const SIGNING_CONTEXT = toBytes(`securee2e/v${PROTOCOL_VERSION}/ecdh-public-key`);
const HKDF_INFO_PREFIX = `securee2e/v${PROTOCOL_VERSION}/aes-256-gcm`;

function subtle(): SubtleCrypto {
    const c = globalThis.crypto;
    if (!c?.subtle) {
        throw new Error('Web Crypto API (crypto.subtle) is not available in this environment.');
    }
    return c.subtle;
}

// --- Key generation ---------------------------------------------------------

/** Generates a fresh, non-extractable ephemeral ECDH P-256 key pair. */
export function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
    return subtle().generateKey(ECDH_ALGORITHM, false, ['deriveBits']);
}

/**
 * Generates a long-term ECDSA P-256 identity key pair.
 * Non-extractable by default; only set `extractable` when the storage provider
 * cannot persist CryptoKey objects (e.g. localStorage) and needs JWK export.
 */
export function generateIdentityKeyPair(extractable = false): Promise<CryptoKeyPair> {
    return subtle().generateKey(ECDSA_ALGORITHM, extractable, ['sign', 'verify']);
}

// --- Import / export --------------------------------------------------------

/** Exports any public key as Base64-encoded SPKI DER. */
export async function exportPublicKeyBase64(publicKey: CryptoKey): Promise<string> {
    return bytesToBase64(await subtle().exportKey('spki', publicKey));
}

export function importEcdhPublicKey(base64Spki: string): Promise<CryptoKey> {
    return subtle().importKey('spki', base64ToBytes(base64Spki), ECDH_ALGORITHM, true, []);
}

export function importEcdsaPublicKey(base64Spki: string): Promise<CryptoKey> {
    return subtle().importKey('spki', base64ToBytes(base64Spki), ECDSA_ALGORITHM, true, ['verify']);
}

export function exportKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
    return subtle().exportKey('jwk', key);
}

/** Imports an ECDSA JWK. Private keys are imported non-extractable unless told otherwise. */
export function importEcdsaJwk(jwk: JsonWebKey, extractable = false): Promise<CryptoKey> {
    const isPrivate = typeof jwk.d === 'string';
    return subtle().importKey('jwk', jwk, ECDSA_ALGORITHM, extractable, isPrivate ? ['sign'] : ['verify']);
}

// --- Fingerprints -----------------------------------------------------------

/**
 * SHA-256 fingerprint of a Base64 SPKI public key, formatted as 16 groups of
 * 4 hex characters (e.g. `A1B2 C3D4 ...`) for humans to compare out-of-band.
 */
export async function fingerprint(base64Spki: string): Promise<string> {
    const digest = new Uint8Array(await subtle().digest('SHA-256', base64ToBytes(base64Spki)));
    const hex = Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hex.match(/.{4}/g)!.join(' ');
}

/** Normalises a fingerprint for comparison (ignores whitespace and case). */
export function normalizeFingerprint(fp: string): string {
    return fp.replace(/[\s:-]/g, '').toUpperCase();
}

// --- Signatures -------------------------------------------------------------

/** Signs `SIGNING_CONTEXT || SPKI(ecdhPublicKey)` with the identity private key. Returns Base64. */
export async function signEcdhPublicKey(identityPrivateKey: CryptoKey, ecdhPublicKeyBase64: string): Promise<string> {
    const message = concatBytes(SIGNING_CONTEXT, base64ToBytes(ecdhPublicKeyBase64));
    return bytesToBase64(await subtle().sign(ECDSA_SIGN_PARAMS, identityPrivateKey, message));
}

/** Verifies a signature produced by `signEcdhPublicKey`. Never throws on a bad signature; returns false. */
export async function verifyEcdhPublicKeySignature(
    identityPublicKey: CryptoKey,
    ecdhPublicKeyBase64: string,
    signatureBase64: string,
): Promise<boolean> {
    try {
        const message = concatBytes(SIGNING_CONTEXT, base64ToBytes(ecdhPublicKeyBase64));
        return await subtle().verify(ECDSA_SIGN_PARAMS, identityPublicKey, base64ToBytes(signatureBase64), message);
    } catch {
        return false;
    }
}

// --- Key agreement ----------------------------------------------------------

/**
 * Derives the AES-256-GCM session key: ECDH → HKDF-SHA256.
 *
 * The HKDF `info` binds the key to both ephemeral public keys (sorted, so both
 * sides compute the same value) and to the protocol version.
 */
export async function deriveSessionKey(
    localEcdhPrivateKey: CryptoKey,
    remoteEcdhPublicKey: CryptoKey,
    localEcdhPublicKeyBase64: string,
    remoteEcdhPublicKeyBase64: string,
): Promise<CryptoKey> {
    const s = subtle();
    const sharedBits = await s.deriveBits({ name: 'ECDH', public: remoteEcdhPublicKey }, localEcdhPrivateKey, 256);
    const hkdfKey = await s.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);

    const [a, b] = [localEcdhPublicKeyBase64, remoteEcdhPublicKeyBase64].sort();
    const info = toBytes(`${HKDF_INFO_PREFIX}|${a}|${b}`);

    return s.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
        hkdfKey,
        AES_ALGORITHM,
        false,
        ['encrypt', 'decrypt'],
    );
}

// --- Symmetric encryption ---------------------------------------------------

/** Encrypts a string or bytes with AES-256-GCM. A fresh 96-bit nonce is generated per call. */
export async function encrypt(
    sessionKey: CryptoKey,
    plaintext: string | Uint8Array,
    options: CipherOptions = {},
): Promise<EncryptedPayload> {
    const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
    const params: AesGcmParams = { name: 'AES-GCM', iv };
    if (options.aad !== undefined) params.additionalData = toBytes(options.aad);

    const ciphertext = await subtle().encrypt(params, sessionKey, toBytes(plaintext));
    return { v: PROTOCOL_VERSION, iv: bytesToBase64(iv), ciphertext: bytesToBase64(ciphertext) };
}

/** Decrypts to raw bytes. Throws `DecryptionError` on any failure (wrong key, wrong AAD, tampering). */
export async function decryptToBytes(
    sessionKey: CryptoKey,
    payload: EncryptedPayload,
    options: CipherOptions = {},
): Promise<Uint8Array<ArrayBuffer>> {
    try {
        const params: AesGcmParams = { name: 'AES-GCM', iv: base64ToBytes(payload.iv) };
        if (options.aad !== undefined) params.additionalData = toBytes(options.aad);
        const plaintext = await subtle().decrypt(params, sessionKey, base64ToBytes(payload.ciphertext));
        return new Uint8Array(plaintext);
    } catch (cause) {
        throw new DecryptionError(cause);
    }
}

/** Decrypts to a UTF-8 string. */
export async function decrypt(
    sessionKey: CryptoKey,
    payload: EncryptedPayload,
    options: CipherOptions = {},
): Promise<string> {
    return new TextDecoder().decode(await decryptToBytes(sessionKey, payload, options));
}
