
import type {
    IKeyStorageProvider,
    LTIDKeySet, 
} from './index';

/**
 * InMemoryStorageProvider: The default fallback provider. Keys are lost on page refresh.
 * It is synchronous in execution but wrapped in Promises to satisfy the IKeyStorageProvider interface.
 */
export class InMemoryStorageProvider implements IKeyStorageProvider {
    // This is a private, in-memory variable that holds the keys for the current session.
    private store: LTIDKeySet | null = null;
    private storageKey: string = 'securee2e-ltid-inmemory-mock'; // Placeholder key

    async load(): Promise<LTIDKeySet | null> {
        // Return a deep clone to prevent direct manipulation of the stored object
        return this.store ? JSON.parse(JSON.stringify(this.store)) : null;
    }

    async save(keys: LTIDKeySet): Promise<void> {
        this.store = keys;
    }

    async clear(): Promise<void> {
        this.store = null;
    }
}

/**
 * LocalStorageProvider (Synchronous Persistence): Persists keys using the browser's localStorage.
 * It is provided for environments where IndexedDB is unavailable or not desired.
 */
export class LocalStorageProvider implements IKeyStorageProvider {
    private storageKey: string = 'securee2e-ltid-v0-4-0';

    async load(): Promise<LTIDKeySet | null> {
        const stored = localStorage.getItem(this.storageKey);
        if (stored) {
            try {
                // Parse the JSON string back into the LTIDKeySet object
                return JSON.parse(stored) as LTIDKeySet;
            } catch (e) {
                console.error("Failed to parse stored LTID key set from localStorage:", e);
                // Clear corrupted data to prevent future errors
                localStorage.removeItem(this.storageKey);
                return null;
            }
        }
        return null;
    }

    async save(keys: LTIDKeySet): Promise<void> {
        // Since CryptoKey objects were exported as JWKs, they are now plain JS objects
        // and safe to serialize as JSON for storage.
        localStorage.setItem(this.storageKey, JSON.stringify(keys));
    }

    async clear(): Promise<void> {
        localStorage.removeItem(this.storageKey);
    }
}
