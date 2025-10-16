/**
 * LTIDKeySet: Defines the structure for serializing and storing the Long-Term Identity (LTID) keys.
 * Keys are stored as JWK strings since they must be exported from CryptoKey objects 
 * for persistence (CryptoKey objects cannot be stored directly).
 */
export interface LTIDKeySet {
    // The ECDSA Private Key (non-extractable by default, but required to be extractable for storage)
    ecdsaPrivateKeyJwk: JsonWebKey; 
    // The ECDSA Public Key
    ecdsaPublicKeyJwk: JsonWebKey;
}

/**
 * IKeyStorageProvider: The interface that all storage providers must implement.
 * This enables swappable persistence logic (In-Memory, LocalStorage, IndexedDB, etc.).
 */
export interface IKeyStorageProvider {
    // Load the key set from storage. Returns null if no key is found.
    load(): Promise<LTIDKeySet | null>;
    // Save the key set to storage.
    save(keys: LTIDKeySet): Promise<void>;
    // Clears the key set from storage (used for resetting identity).
    clear(): Promise<void>; 
}

/**
 * InMemoryStorageProvider: The default fallback provider. Keys are lost on page refresh.
 */
export class InMemoryStorageProvider implements IKeyStorageProvider {
    private store: LTIDKeySet | null = null;
    private storageKey: string = 'securee2e-ltid-inmemory-mock'; // Just a placeholder key

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
 * LocalStorageProvider (New v0.4.0 Default): Persists keys using the browser's localStorage.
 */
export class LocalStorageProvider implements IKeyStorageProvider {
    private storageKey: string = 'securee2e-ltid-v0-4-0'; 

    async load(): Promise<LTIDKeySet | null> {
        const stored = localStorage.getItem(this.storageKey);
        if (stored) {
            try {
                return JSON.parse(stored) as LTIDKeySet;
            } catch (e) {
                console.error("Failed to parse stored LTID key set from localStorage:", e);
                // Clear corrupted data
                localStorage.removeItem(this.storageKey);
                return null;
            }
        }
        return null;
    }

    async save(keys: LTIDKeySet): Promise<void> {
        // Since CryptoKey objects were exported as JWKs, they are now plain JS objects 
        // and safe to serialize as JSON.
        localStorage.setItem(this.storageKey, JSON.stringify(keys));
    }
    
    async clear(): Promise<void> {
        localStorage.removeItem(this.storageKey);
    }
}


// --- Swappable Provider System ---

// Set LocalStorageProvider as the new default
export let currentStorageProvider: IKeyStorageProvider = new LocalStorageProvider();

/**
 * Allows the user to inject a custom storage provider (e.g., IndexedDB, Firestore, or back to In-Memory).
 * This must be called before the first use of useDiffieHellman().
 * @param provider An instance of a class implementing IKeyStorageProvider.
 */
export function setCurrentStorageProvider(provider: IKeyStorageProvider): void {
    if (!provider || typeof provider.load !== 'function' || typeof provider.save !== 'function') {
        throw new Error("Invalid storage provider provided. Must implement IKeyStorageProvider.");
    }
    currentStorageProvider = provider;
}

export { IndexedDBProvider } from './storage/IndexedDBProvider'; 