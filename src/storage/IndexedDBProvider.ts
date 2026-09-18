import { importEcdsaJwk } from '../core/crypto';
import { StorageError } from '../core/errors';
import { LEGACY_LOCAL_STORAGE_KEY } from './LocalStorageProvider';
import type { IKeyStorageProvider, StoredIdentity } from './types';

export interface IndexedDBProviderOptions {
    /** Database name. Defaults to `securee2e-db`. */
    dbName?: string;
    /** Object store name. Defaults to `identity`. */
    storeName?: string;
    /** Record key inside the store. Defaults to `default`. Use different values for multiple identities. */
    recordId?: string;
    /**
     * When no identity is found, look for a 0.4.0 identity in localStorage,
     * import it (non-extractable), persist it here and delete the old entry.
     * Defaults to `true`.
     */
    migrateLegacyLocalStorage?: boolean;
}

const DB_VERSION = 1;

/**
 * Default provider. Stores `CryptoKey` objects directly via IndexedDB's
 * structured clone, so the private key can stay **non-extractable**: it can be
 * used by this origin but its bytes can never be read out, even by XSS.
 */
export class IndexedDBProvider implements IKeyStorageProvider {
    private readonly dbName: string;
    private readonly storeName: string;
    private readonly recordId: string;
    private readonly migrateLegacy: boolean;

    constructor(options: IndexedDBProviderOptions = {}) {
        this.dbName = options.dbName ?? 'securee2e-db';
        this.storeName = options.storeName ?? 'identity';
        this.recordId = options.recordId ?? 'default';
        this.migrateLegacy = options.migrateLegacyLocalStorage ?? true;
    }

    static isAvailable(): boolean {
        try {
            return typeof indexedDB !== 'undefined' && indexedDB !== null;
        } catch {
            return false;
        }
    }

    async load(): Promise<StoredIdentity | null> {
        const stored = await this.withStore('readonly', (store) => store.get(this.recordId));
        if (isStoredIdentity(stored)) return stored;

        if (this.migrateLegacy) {
            const migrated = await this.migrateFromLocalStorage();
            if (migrated) return migrated;
        }
        return null;
    }

    async save(identity: StoredIdentity): Promise<void> {
        await this.withStore('readwrite', (store) => store.put(identity, this.recordId));
    }

    async clear(): Promise<void> {
        await this.withStore('readwrite', (store) => store.delete(this.recordId));
    }

    // --- internals ---

    private async migrateFromLocalStorage(): Promise<StoredIdentity | null> {
        let raw: string | null;
        try {
            raw = typeof localStorage === 'undefined' ? null : localStorage.getItem(LEGACY_LOCAL_STORAGE_KEY);
        } catch {
            return null;
        }
        if (!raw) return null;

        try {
            const parsed = JSON.parse(raw) as { ecdsaPrivateKeyJwk: JsonWebKey; ecdsaPublicKeyJwk: JsonWebKey };
            const identity: StoredIdentity = {
                privateKey: await importEcdsaJwk(parsed.ecdsaPrivateKeyJwk, false),
                publicKey: await importEcdsaJwk(parsed.ecdsaPublicKeyJwk, true),
            };
            await this.save(identity);
            localStorage.removeItem(LEGACY_LOCAL_STORAGE_KEY);
            return identity;
        } catch {
            // Unreadable legacy data: leave it alone and start fresh.
            return null;
        }
    }

    private openDatabase(): Promise<IDBDatabase> {
        return new Promise((resolve, reject) => {
            if (!IndexedDBProvider.isAvailable()) {
                return reject(new StorageError('IndexedDB is not available in this environment.'));
            }
            const request = indexedDB.open(this.dbName, DB_VERSION);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    db.createObjectStore(this.storeName);
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new StorageError('Failed to open IndexedDB.', request.error));
            request.onblocked = () => reject(new StorageError('IndexedDB open request was blocked.'));
        });
    }

    /** Runs one request inside a transaction, closes the connection, and maps errors to StorageError. */
    private async withStore<T>(
        mode: IDBTransactionMode,
        operation: (store: IDBObjectStore) => IDBRequest<T>,
    ): Promise<T> {
        const db = await this.openDatabase();
        try {
            return await new Promise<T>((resolve, reject) => {
                const tx = db.transaction(this.storeName, mode);
                const request = operation(tx.objectStore(this.storeName));
                tx.oncomplete = () => resolve(request.result);
                tx.onerror = () => reject(new StorageError('IndexedDB transaction failed.', tx.error));
                tx.onabort = () => reject(new StorageError('IndexedDB transaction aborted.', tx.error));
            });
        } finally {
            db.close();
        }
    }
}

function isStoredIdentity(value: unknown): value is StoredIdentity {
    if (typeof value !== 'object' || value === null) return false;
    const v = value as Record<string, unknown>;
    return v.privateKey instanceof CryptoKey && v.publicKey instanceof CryptoKey;
}
