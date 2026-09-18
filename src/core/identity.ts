import { exportPublicKeyBase64, fingerprint, generateIdentityKeyPair } from './crypto';
import type { IKeyStorageProvider, StoredIdentity } from '../storage/types';

export interface LoadedIdentity extends StoredIdentity {
    /** Identity public key (SPKI, Base64). */
    publicKeyBase64: string;
    /** Human-comparable SHA-256 fingerprint of the public key. */
    fingerprint: string;
}

/**
 * Loads-or-creates the long-term identity from a storage provider exactly once.
 *
 * The initialisation promise is memoised so concurrent callers share one
 * load/generate cycle (otherwise two callers could both see "no identity",
 * both generate, and one of them would end up holding keys that were never
 * persisted). A failed initialisation is forgotten so the next call retries.
 */
export class IdentityManager {
    private readonly storage: IKeyStorageProvider;
    private pending: Promise<LoadedIdentity> | null = null;
    private current: LoadedIdentity | null = null;

    constructor(storage: IKeyStorageProvider) {
        this.storage = storage;
    }

    /** The identity if it has finished loading, otherwise `null`. Synchronous. */
    get identity(): LoadedIdentity | null {
        return this.current;
    }

    load(): Promise<LoadedIdentity> {
        if (!this.pending) {
            this.pending = this.loadOrCreate().then(
                (identity) => {
                    this.current = identity;
                    return identity;
                },
                (error) => {
                    this.pending = null;
                    throw error;
                },
            );
        }
        return this.pending;
    }

    /** Deletes the stored identity and generates a new one. */
    async reset(): Promise<LoadedIdentity> {
        await this.storage.clear();
        this.pending = null;
        this.current = null;
        return this.load();
    }

    private async loadOrCreate(): Promise<LoadedIdentity> {
        let stored = await this.storage.load();
        if (!stored) {
            const pair = await generateIdentityKeyPair(this.storage.requiresExtractableKeys === true);
            stored = { privateKey: pair.privateKey, publicKey: pair.publicKey };
            await this.storage.save(stored);
        }
        const publicKeyBase64 = await exportPublicKeyBase64(stored.publicKey);
        return { ...stored, publicKeyBase64, fingerprint: await fingerprint(publicKeyBase64) };
    }
}
