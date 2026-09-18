/**
 * The persisted long-term identity. Both halves are `CryptoKey` objects; the
 * private key is non-extractable whenever the provider can store it that way
 * (IndexedDB and in-memory can, localStorage cannot).
 */
export interface StoredIdentity {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

/**
 * Interface all storage providers implement. Swap it via
 * `createSecureE2E({ storage })` / `useSecureE2E({ storage })`.
 */
export interface IKeyStorageProvider {
    /** Loads the identity, or `null` if none has been saved yet. */
    load(): Promise<StoredIdentity | null>;
    /** Persists the identity. */
    save(identity: StoredIdentity): Promise<void>;
    /** Removes the identity (used to reset / rotate identity). */
    clear(): Promise<void>;
    /**
     * `true` if this provider can only persist exported key material (JWK) and
     * therefore needs the private key to be generated extractable.
     * Leave undefined/false for providers that can store `CryptoKey` objects.
     */
    readonly requiresExtractableKeys?: boolean;
}
