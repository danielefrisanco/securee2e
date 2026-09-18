/**
 * securee2e — framework-agnostic entry point.
 * Vue users: `import { useSecureE2E } from 'securee2e/vue'`.
 */

// High-level API
export { createSecureE2E, type SecureE2E, type SecureE2EOptions } from './core/secureE2E';

// Wire types
export {
    PROTOCOL_VERSION,
    isKeyAuthPayload,
    isEncryptedPayload,
    type KeyAuthPayload,
    type EncryptedPayload,
    type LocalAuthResult,
    type RemoteIdentity,
    type VerifyOptions,
    type CipherOptions,
} from './core/types';

// Errors
export {
    SecureE2EError,
    NotInitializedError,
    InvalidPayloadError,
    SignatureInvalidError,
    IdentityMismatchError,
    DecryptionError,
    StorageError,
    type SecureE2EErrorCode,
} from './core/errors';

// Storage providers
export {
    getDefaultStorageProvider,
    InMemoryStorageProvider,
    IndexedDBProvider,
    LocalStorageProvider,
    LEGACY_LOCAL_STORAGE_KEY,
    type IKeyStorageProvider,
    type StoredIdentity,
    type IndexedDBProviderOptions,
    type LocalStorageProviderOptions,
} from './storage/index';

// Low-level primitives, for people who want to build their own protocol on top
export {
    generateEphemeralKeyPair,
    generateIdentityKeyPair,
    exportPublicKeyBase64,
    importEcdhPublicKey,
    importEcdsaPublicKey,
    exportKeyJwk,
    importEcdsaJwk,
    fingerprint,
    normalizeFingerprint,
    signEcdhPublicKey,
    verifyEcdhPublicKeySignature,
    deriveSessionKey,
    encrypt,
    decrypt,
    decryptToBytes,
} from './core/crypto';
export { bytesToBase64, base64ToBytes } from './core/base64';
export { IdentityManager, type LoadedIdentity } from './core/identity';
