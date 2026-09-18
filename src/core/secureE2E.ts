import {
    decrypt,
    decryptToBytes,
    deriveSessionKey,
    encrypt,
    exportPublicKeyBase64,
    fingerprint,
    generateEphemeralKeyPair,
    importEcdhPublicKey,
    importEcdsaPublicKey,
    normalizeFingerprint,
    signEcdhPublicKey,
    verifyEcdhPublicKeySignature,
} from './crypto';
import { IdentityMismatchError, InvalidPayloadError, NotInitializedError, SignatureInvalidError } from './errors';
import { IdentityManager } from './identity';
import {
    PROTOCOL_VERSION,
    isEncryptedPayload,
    isKeyAuthPayload,
    type CipherOptions,
    type EncryptedPayload,
    type KeyAuthPayload,
    type LocalAuthResult,
    type RemoteIdentity,
    type VerifyOptions,
} from './types';
import { getDefaultStorageProvider } from '../storage/index';
import type { IKeyStorageProvider } from '../storage/types';

export interface SecureE2EOptions {
    /** Where the long-term identity lives. Defaults to IndexedDB (in-memory outside browsers). */
    storage?: IKeyStorageProvider;
}

export interface SecureE2E {
    /**
     * Loads or generates the long-term identity. Called automatically by every
     * method that needs it, but awaiting it up front lets you surface errors early.
     */
    init(): Promise<void>;
    /** `true` once the identity is loaded. */
    readonly isReady: boolean;
    /** Identity public key (SPKI, Base64). Share it so peers can pin you. */
    getIdentityPublicKey(): Promise<string>;
    /** Fingerprint of the identity public key, for out-of-band comparison. */
    getIdentityFingerprint(): Promise<string>;
    /** Deletes the identity and creates a fresh one. Peers that pinned the old key will reject the new one. */
    resetIdentity(): Promise<void>;

    /** Step 1: create an ephemeral key pair and sign its public half with the identity key. */
    generateLocalAuthPayload(): Promise<LocalAuthResult>;
    /**
     * Checks a remote payload: shape, signature, and (if `options` pins one)
     * identity. Useful for trust-on-first-use flows where you want to show the
     * fingerprint before committing to a session.
     */
    verifyRemotePayload(remote: unknown, options?: VerifyOptions): Promise<RemoteIdentity>;
    /**
     * Step 2: verify the remote payload and derive the shared AES-256-GCM session key.
     * Throws `SignatureInvalidError` / `IdentityMismatchError` / `InvalidPayloadError`.
     *
     * ⚠️ Without `expectedIdentityKey` / `expectedFingerprint` this only proves
     * the payload is self-consistent. Pin the identity (or compare
     * fingerprints out-of-band) to actually rule out a man-in-the-middle.
     */
    deriveSecretFromRemotePayload(local: LocalAuthResult, remote: unknown, options?: VerifyOptions): Promise<CryptoKey>;

    encryptMessage(sessionKey: CryptoKey, plaintext: string | Uint8Array, options?: CipherOptions): Promise<EncryptedPayload>;
    decryptMessage(sessionKey: CryptoKey, payload: unknown, options?: CipherOptions): Promise<string>;
    decryptBytes(sessionKey: CryptoKey, payload: unknown, options?: CipherOptions): Promise<Uint8Array>;
}

/**
 * Creates an independent E2E instance bound to one identity storage.
 * Framework-agnostic; the Vue composable in `securee2e/vue` wraps this.
 */
export function createSecureE2E(options: SecureE2EOptions = {}): SecureE2E {
    const identity = new IdentityManager(options.storage ?? getDefaultStorageProvider());

    const requireIdentity = () => {
        const current = identity.identity;
        if (!current) throw new NotInitializedError();
        return current;
    };

    async function verifyRemotePayload(remote: unknown, verifyOptions: VerifyOptions = {}): Promise<RemoteIdentity> {
        if (!isKeyAuthPayload(remote)) {
            throw new InvalidPayloadError(`Expected a v${PROTOCOL_VERSION} KeyAuthPayload with ecdhPublicKey, ecdsaPublicKey and signature.`);
        }

        let remoteIdentityKey: CryptoKey;
        try {
            remoteIdentityKey = await importEcdsaPublicKey(remote.ecdsaPublicKey);
        } catch {
            throw new InvalidPayloadError('Remote identity public key could not be imported.');
        }

        const valid = await verifyEcdhPublicKeySignature(remoteIdentityKey, remote.ecdhPublicKey, remote.signature);
        if (!valid) throw new SignatureInvalidError();

        const remoteFingerprint = await fingerprint(remote.ecdsaPublicKey);

        if (verifyOptions.expectedIdentityKey !== undefined && verifyOptions.expectedIdentityKey !== remote.ecdsaPublicKey) {
            throw new IdentityMismatchError(verifyOptions.expectedIdentityKey, remote.ecdsaPublicKey);
        }
        if (
            verifyOptions.expectedFingerprint !== undefined &&
            normalizeFingerprint(verifyOptions.expectedFingerprint) !== normalizeFingerprint(remoteFingerprint)
        ) {
            throw new IdentityMismatchError(verifyOptions.expectedFingerprint, remoteFingerprint);
        }

        return { identityKey: remote.ecdsaPublicKey, fingerprint: remoteFingerprint };
    }

    const api: SecureE2E = {
        async init() {
            await identity.load();
        },

        get isReady() {
            return identity.identity !== null;
        },

        async getIdentityPublicKey() {
            return (await identity.load()).publicKeyBase64;
        },

        async getIdentityFingerprint() {
            return (await identity.load()).fingerprint;
        },

        async resetIdentity() {
            await identity.reset();
        },

        async generateLocalAuthPayload() {
            const me = await identity.load();
            const ephemeral = await generateEphemeralKeyPair();
            const ecdhPublicKey = await exportPublicKeyBase64(ephemeral.publicKey);
            const signature = await signEcdhPublicKey(me.privateKey, ecdhPublicKey);
            return {
                payload: { v: PROTOCOL_VERSION, ecdhPublicKey, ecdsaPublicKey: me.publicKeyBase64, signature },
                ecdhPrivateKey: ephemeral.privateKey,
            };
        },

        verifyRemotePayload,

        async deriveSecretFromRemotePayload(local, remote, verifyOptions) {
            requireIdentity();
            await verifyRemotePayload(remote, verifyOptions);
            const remotePayload = remote as KeyAuthPayload;

            let remoteEcdhKey: CryptoKey;
            try {
                remoteEcdhKey = await importEcdhPublicKey(remotePayload.ecdhPublicKey);
            } catch {
                throw new InvalidPayloadError('Remote ECDH public key could not be imported.');
            }
            return deriveSessionKey(local.ecdhPrivateKey, remoteEcdhKey, local.payload.ecdhPublicKey, remotePayload.ecdhPublicKey);
        },

        encryptMessage: (sessionKey, plaintext, cipherOptions) => encrypt(sessionKey, plaintext, cipherOptions),

        async decryptMessage(sessionKey, payload, cipherOptions) {
            if (!isEncryptedPayload(payload)) throw new InvalidPayloadError('Expected an EncryptedPayload with iv and ciphertext.');
            return decrypt(sessionKey, payload, cipherOptions);
        },

        async decryptBytes(sessionKey, payload, cipherOptions) {
            if (!isEncryptedPayload(payload)) throw new InvalidPayloadError('Expected an EncryptedPayload with iv and ciphertext.');
            return decryptToBytes(sessionKey, payload, cipherOptions);
        },
    };

    return api;
}
