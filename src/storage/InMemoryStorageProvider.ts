import type { IKeyStorageProvider, StoredIdentity } from './types';

/**
 * Keeps the identity in memory only. It is lost on page reload, which makes it
 * suitable for tests, SSR, or deliberately ephemeral identities.
 */
export class InMemoryStorageProvider implements IKeyStorageProvider {
    private identity: StoredIdentity | null = null;

    async load(): Promise<StoredIdentity | null> {
        return this.identity;
    }

    async save(identity: StoredIdentity): Promise<void> {
        this.identity = identity;
    }

    async clear(): Promise<void> {
        this.identity = null;
    }
}
