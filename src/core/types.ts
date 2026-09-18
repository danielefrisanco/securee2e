/** Wire-format version. Bump when the payload shape or crypto construction changes. */
export const PROTOCOL_VERSION = 1 as const;

/**
 * The authenticated key-exchange payload sent over the network.
 * All binary fields are standard Base64 (SPKI DER for keys, raw `r||s` IEEE P1363 for the signature).
 */
export interface KeyAuthPayload {
    /** Protocol version (always 1 for now). */
    v: typeof PROTOCOL_VERSION;
    /** Ephemeral ECDH P-256 public key (SPKI, Base64). */
    ecdhPublicKey: string;
    /** Long-term ECDSA P-256 identity public key (SPKI, Base64). */
    ecdsaPublicKey: string;
    /** ECDSA/SHA-256 signature over `"securee2e/v1/ecdh-public-key" || SPKI(ecdhPublicKey)` (Base64). */
    signature: string;
}

/** An encrypted message ready for network transmission. */
export interface EncryptedPayload {
    v: typeof PROTOCOL_VERSION;
    /** 96-bit AES-GCM nonce (Base64). Unique per message; not secret. */
    iv: string;
    /** AES-GCM ciphertext including the 128-bit auth tag (Base64). */
    ciphertext: string;
}

/** Result of `generateLocalAuthPayload()`: the payload to send plus the private half kept locally. */
export interface LocalAuthResult {
    payload: KeyAuthPayload;
    /** Non-extractable ephemeral ECDH private key. Never leaves this device. */
    ecdhPrivateKey: CryptoKey;
}

/** Information about a verified remote party. */
export interface RemoteIdentity {
    /** Remote identity public key (SPKI, Base64). */
    identityKey: string;
    /** SHA-256 fingerprint of the identity key, formatted for out-of-band comparison. */
    fingerprint: string;
}

export interface VerifyOptions {
    /**
     * Pin the remote identity to this Base64 SPKI public key (e.g. from a
     * previous session, a directory, or a QR code). If the payload carries a
     * different identity key, `IdentityMismatchError` is thrown.
     */
    expectedIdentityKey?: string;
    /** Same as `expectedIdentityKey` but compares the formatted fingerprint. Whitespace/case-insensitive. */
    expectedFingerprint?: string;
}

export interface CipherOptions {
    /**
     * Additional authenticated data: bound to the ciphertext but not encrypted.
     * Use it for things like a message counter or conversation id so that
     * replayed / re-ordered ciphertexts fail to decrypt.
     */
    aad?: string | Uint8Array;
}

export function isKeyAuthPayload(value: unknown): value is KeyAuthPayload {
    if (typeof value !== 'object' || value === null) return false;
    const p = value as Record<string, unknown>;
    return (
        p.v === PROTOCOL_VERSION &&
        typeof p.ecdhPublicKey === 'string' &&
        typeof p.ecdsaPublicKey === 'string' &&
        typeof p.signature === 'string'
    );
}

export function isEncryptedPayload(value: unknown): value is EncryptedPayload {
    if (typeof value !== 'object' || value === null) return false;
    const p = value as Record<string, unknown>;
    return p.v === PROTOCOL_VERSION && typeof p.iv === 'string' && typeof p.ciphertext === 'string';
}
