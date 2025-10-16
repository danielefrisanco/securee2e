import type {
    LTIDKeySet, IKeyStorageProvider
} from './index';
/**
 * Configuration for the IndexedDB store.
 */
const DB_NAME = 'securee2e-db'; // This is the name the provider will ALWAYS use.
const DB_VERSION = 1;
const STORE_NAME = 'ltid_keys';
const KEY_RECORD_ID = 'user_ltid_keys';

/**
 * IndexedDB Key Storage Provider implementation.
 * Handles the asynchronous persistence of the Long-Term Identity (LTID) keys.
 */
export class IndexedDBProvider implements IKeyStorageProvider {

    /**
     * Opens a connection to the IndexedDB database.
     * If the database or object store does not exist, it creates them.
     * @returns A Promise that resolves to an IDBDatabase instance.
     */
    private openDatabase(): Promise<IDBDatabase> {
        return new Promise((resolve, reject) => {
            if (typeof window === 'undefined' || !window.indexedDB) {
                // If the polyfill failed or not in a browser/test environment
                console.error("IndexedDB is not supported or available.");
                return reject(new Error("IndexedDB not supported."));
            }

            const request = indexedDB.open(DB_NAME, DB_VERSION);

            // This fires when a version change is needed (creation or upgrade)
            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result;
                // Create the object store where key data will be saved
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME);
                    console.debug(`IndexedDB: Created object store ${STORE_NAME}`);
                }
            };

            // Success handler: database is ready
            request.onsuccess = (event) => {
                resolve((event.target as IDBOpenDBRequest).result);
            };

            // Error handler
            request.onerror = (event) => {
                console.error("IndexedDB Error:", (event.target as IDBOpenDBRequest).error);
                reject((event.target as IDBOpenDBRequest).error);
            };
        });
    }

    /**
     * Helper to check if IndexedDB is available (useful for the fallback logic).
     */
    public isAvailable(): boolean {
        return typeof window !== 'undefined' && !!window.indexedDB;
    }


    /**
     * Reads the LTID keys from the IndexedDB.
     * @returns A Promise that resolves to the LTIDKeySet or null if not found.
     */
    public async load(): Promise<LTIDKeySet | null> {
        if (!this.isAvailable()) return null; // Defensive check

        try {
            const db = await this.openDatabase();
            return new Promise((resolve) => {
                const transaction = db.transaction([STORE_NAME], 'readonly');
                const store = transaction.objectStore(STORE_NAME);

                const request = store.get(KEY_RECORD_ID);

                request.onsuccess = () => {
                    db.close();
                    const data = request.result;
                    resolve(data ? (data as LTIDKeySet) : null);
                };

                request.onerror = () => {
                    db.close();
                    console.warn("IndexedDB Load Warning: Failed to retrieve key, treating as null.");
                    resolve(null);
                };
            });
        } catch (error) {
            console.error("IndexedDB Load Critical Error:", error);
            return null;
        }
    }

    /**
     * Writes the LTID keys to the IndexedDB.
     * @param keyset The LTIDKeySet object to save.
     * @returns A Promise that resolves when the save is complete.
     */
    public async save(keyset: LTIDKeySet): Promise<void> {
        if (!this.isAvailable()) return; // Defensive check

        try {
            const db = await this.openDatabase();
            return new Promise((resolve, reject) => {
                const transaction = db.transaction([STORE_NAME], 'readwrite');
                const store = transaction.objectStore(STORE_NAME);

                const request = store.put(keyset, KEY_RECORD_ID);

                request.onsuccess = () => {
                    db.close();
                    console.debug("IndexedDB: LTID keys saved successfully.");
                    resolve();
                };

                request.onerror = (event) => {
                    db.close();
                    const error = (event.target as IDBRequest).error;
                    console.error("IndexedDB Save Error:", error);
                    reject(error);
                };
            });
        } catch (error) {
            console.error("IndexedDB Save Critical Error:", error);
            throw error;
        }
    }

    /**
     * Clears the LTID keys from the IndexedDB store.
     * @returns A Promise that resolves when the clear operation is complete.
     */
    public async clear(): Promise<void> {
        if (!this.isAvailable()) return; // Defensive check
        
        try {
            const db = await this.openDatabase();
            return new Promise((resolve, reject) => {
                const transaction = db.transaction([STORE_NAME], 'readwrite');
                const store = transaction.objectStore(STORE_NAME);

                const request = store.delete(KEY_RECORD_ID);

                request.onsuccess = () => {
                    db.close();
                    console.debug("IndexedDB: LTID keys cleared successfully.");
                    resolve();
                };

                request.onerror = (event) => {
                    db.close();
                    const error = (event.target as IDBRequest).error;
                    console.error("IndexedDB Clear Error:", error);
                    reject(error);
                };
            });
        } catch (error) {
            console.error("IndexedDB Clear Critical Error:", error);
            throw error;
        }
    }
}
