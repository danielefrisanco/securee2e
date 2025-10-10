/**
 * Defines the storable format for the Long-Term Identity Key (LTID) set.
 * Keys must be stored in the standardized JSON Web Key (JWK) format 
 * so they can be securely exported and imported from Web Crypto objects.
 */
export interface LTIDKeySet {
    /** The ECDSA Signing Private Key (JWK format for storage). */
    ecdsaPrivateKeyJwk: JsonWebKey;
    /** The ECDSA Signing Public Key (JWK format for storage). */
    ecdsaPublicKeyJwk: JsonWebKey;
}

/**
 * Interface for the secure key storage provider.
 * This abstraction layer allows the library consumer (the developer)
 * to plug in their preferred persistence mechanism (e.g., localStorage, 
 * IndexedDB, Firestore) for long-term keys.
 */
export interface IKeyStorageProvider {
    /**
     * Saves the long-term identity key set.
     * @param keySet The LTID keys in storable JWK format.
     */
    save(keySet: LTIDKeySet): Promise<void>;

    /**
     * Loads the long-term identity key set.
     * @returns The LTID keys in storable JWK format, or null if not found.
     */
    load(): Promise<LTIDKeySet | null>;
}

/**
 * A simple, default implementation for the key storage provider that uses 
 * an in-memory variable. This is suitable for testing or sessions where
 * persistence is not required (keys are lost on refresh/page close).
 */
export class InMemoryStorageProvider implements IKeyStorageProvider {
    private keys: LTIDKeySet | null = null;

    async save(keySet: LTIDKeySet): Promise<void> {
        this.keys = JSON.parse(JSON.stringify(keySet));
        console.log("LTID Keys saved to in-memory store.");
    }

    async load(): Promise<LTIDKeySet | null> {
        if (this.keys) {
            console.log("LTID Keys loaded from in-memory store.");
            return JSON.parse(JSON.stringify(this.keys));
        }
        return null;
    }
}

// Global state variable holding the currently active storage implementation.
// Defaults to the in-memory provider.
export let currentStorageProvider: IKeyStorageProvider = new InMemoryStorageProvider();

/**
 * Public function exposed by the library to allow developers to set 
 * their custom persistence mechanism (e.g., Firestore, localStorage).
 * This function is now defined here for better testability.
 * @param provider The new storage provider implementation.
 */
export const setCurrentStorageProvider = (provider: IKeyStorageProvider) => {
    currentStorageProvider = provider;
    console.log("securee2e: Storage provider updated.");
};
