/**
 * LTIDKeySet: Defines the structure for serializing and storing the Long-Term Identity (LTID) keys.
 * Keys are stored as JWK objects since they must be exported from CryptoKey objects
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
    /**
     * Load the key set from storage.
     * @returns Promise resolving to the stored key set, or null if no key is found.
     */
    load(): Promise<LTIDKeySet | null>;

    /**
     * Save the key set to storage.
     * @param keys The LTIDKeySet to be persisted.
     * @returns Promise resolving when the save is complete.
     */
    save(keys: LTIDKeySet): Promise<void>;

    /**
     * Clears the key set from storage (used for resetting identity).
     * @returns Promise resolving when the clear operation is complete.
     */
    clear(): Promise<void>;
}
