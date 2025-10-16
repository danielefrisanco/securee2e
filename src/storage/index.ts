import type { IKeyStorageProvider, LTIDKeySet } from '../types/storage';
import { InMemoryStorageProvider, LocalStorageProvider } from './LocalStorageProvider';
import { IndexedDBProvider } from './IndexedDBProvider'; // <--- NEW IMPORT

// /**
//  * Default storage provider selection.
//  * We now default to the IndexedDBProvider for robust, asynchronous, and persistent storage.
//  */
// const currentStorageProvider: IKeyStorageProvider = new IndexedDBProvider();
// Assuming IKeyStorageProvider, IndexedDBProvider, and InMemoryStorageProvider 
// are defined and imported in this file.

/**
 * Checks for IndexedDB support and returns the appropriate storage provider.
 * Falls back to InMemoryStorageProvider if IndexedDB is unavailable (e.g., in a Node.js test environment).
 */
function selectStorageProvider(): IKeyStorageProvider {
    // Check if we are in a browser environment AND IndexedDB is available.
    // This check prevents the IndexedDBProvider constructor from failing in Node.
    if (typeof window !== 'undefined' && window.indexedDB) {
        console.log("STORAGE: Using IndexedDBProvider for persistent storage.");
        return new IndexedDBProvider();
    } else {
        // Fallback to in-memory store for environments like Node.js/Vitest.
        console.warn("STORAGE: IndexedDB not available. Falling back to InMemoryStorageProvider.");
        return new InMemoryStorageProvider();
    }
}

// Default storage provider selection.
// This now executes the safe fallback logic immediately on module load.
const currentStorageProvider: IKeyStorageProvider = selectStorageProvider();

/**
 * Re-export all storage-related types and providers for easy, modular access.
 * This simplifies imports in the main composable.
 */
export {
    IKeyStorageProvider,
    LTIDKeySet,
    InMemoryStorageProvider,
    LocalStorageProvider,
    IndexedDBProvider,
    currentStorageProvider,
};
