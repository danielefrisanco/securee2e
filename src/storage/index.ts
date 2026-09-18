import { IndexedDBProvider } from './IndexedDBProvider';
import { InMemoryStorageProvider } from './InMemoryStorageProvider';
import type { IKeyStorageProvider } from './types';

export type { IKeyStorageProvider, StoredIdentity } from './types';
export { InMemoryStorageProvider } from './InMemoryStorageProvider';
export { IndexedDBProvider, type IndexedDBProviderOptions } from './IndexedDBProvider';
export {
    LocalStorageProvider,
    LEGACY_LOCAL_STORAGE_KEY,
    type LocalStorageProviderOptions,
} from './LocalStorageProvider';

let defaultProvider: IKeyStorageProvider | undefined;

/**
 * The storage used when none is passed explicitly: IndexedDB in browsers,
 * in-memory elsewhere (SSR, tests without a polyfill). Selected lazily on first
 * use so importing the library has no side effects.
 */
export function getDefaultStorageProvider(): IKeyStorageProvider {
    if (!defaultProvider) {
        defaultProvider = IndexedDBProvider.isAvailable() ? new IndexedDBProvider() : new InMemoryStorageProvider();
    }
    return defaultProvider;
}
