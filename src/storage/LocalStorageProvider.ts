import { exportKeyJwk, importEcdsaJwk } from '../core/crypto';
import { StorageError } from '../core/errors';
import type { IKeyStorageProvider, StoredIdentity } from './types';

/** Key used by securee2e 0.4.0; still read so existing identities survive the upgrade. */
export const LEGACY_LOCAL_STORAGE_KEY = 'securee2e-ltid-v0-4-0';
const DEFAULT_STORAGE_KEY = 'securee2e/identity/v1';

interface SerializedIdentity {
    ecdsaPrivateKeyJwk: JsonWebKey;
    ecdsaPublicKeyJwk: JsonWebKey;
}

export interface LocalStorageProviderOptions {
    /** localStorage key to use. Defaults to `securee2e/identity/v1`. */
    storageKey?: string;
}

/**
 * Persists the identity in `window.localStorage` as JWK.
 *
 * ⚠️ localStorage can only hold strings, so the private key has to be exported.
 * That means the key material sits in plaintext where any script on the origin
 * can read it. Prefer `IndexedDBProvider` (the default), which stores a
 * non-extractable `CryptoKey`. This provider exists for environments without
 * IndexedDB or for backwards compatibility.
 */
export class LocalStorageProvider implements IKeyStorageProvider {
    readonly requiresExtractableKeys = true;
    private readonly storageKey: string;

    constructor(options: LocalStorageProviderOptions = {}) {
        this.storageKey = options.storageKey ?? DEFAULT_STORAGE_KEY;
    }

    static isAvailable(): boolean {
        try {
            return typeof localStorage !== 'undefined';
        } catch {
            return false;
        }
    }

    async load(): Promise<StoredIdentity | null> {
        if (!LocalStorageProvider.isAvailable()) return null;

        const raw = localStorage.getItem(this.storageKey) ?? localStorage.getItem(LEGACY_LOCAL_STORAGE_KEY);
        if (!raw) return null;

        let parsed: SerializedIdentity;
        try {
            parsed = JSON.parse(raw) as SerializedIdentity;
        } catch {
            // Corrupted entry: drop it rather than failing forever.
            localStorage.removeItem(this.storageKey);
            return null;
        }
        try {
            // Re-import as extractable so the identity can be re-saved under the new key if it came from the legacy one.
            const [privateKey, publicKey] = await Promise.all([
                importEcdsaJwk(parsed.ecdsaPrivateKeyJwk, true),
                importEcdsaJwk(parsed.ecdsaPublicKeyJwk, true),
            ]);
            return { privateKey, publicKey };
        } catch (cause) {
            throw new StorageError('Failed to import identity from localStorage.', cause);
        }
    }

    async save(identity: StoredIdentity): Promise<void> {
        if (!LocalStorageProvider.isAvailable()) {
            throw new StorageError('localStorage is not available.');
        }
        const serialized: SerializedIdentity = {
            ecdsaPrivateKeyJwk: await exportKeyJwk(identity.privateKey),
            ecdsaPublicKeyJwk: await exportKeyJwk(identity.publicKey),
        };
        localStorage.setItem(this.storageKey, JSON.stringify(serialized));
    }

    async clear(): Promise<void> {
        if (!LocalStorageProvider.isAvailable()) return;
        localStorage.removeItem(this.storageKey);
        localStorage.removeItem(LEGACY_LOCAL_STORAGE_KEY);
    }
}
