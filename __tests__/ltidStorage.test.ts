import { describe, it, expect, beforeEach } from 'vitest';
// Assuming your IndexedDB implementation class and types are exported from '../src/storage'
import { IndexedDBProvider, LTIDKeySet } from '../src/storage/index'; 
// The fake-indexeddb/auto polyfill handles the global 'indexedDB' object setup.

// --- Mock Data ---

const MOCK_PRIVATE_JWK: JsonWebKey = {
    kty: 'EC', 
    crv: 'P-256', 
    x: 'mockX_private', 
    y: 'mockY_private', 
    d: 'mockD_private'
};

const MOCK_PUBLIC_JWK: JsonWebKey = {
    kty: 'EC', 
    crv: 'P-256', 
    x: 'mockX_public', 
    y: 'mockY_public', 
};

const MOCK_KEY_SET: LTIDKeySet = {
    ecdsaPrivateKeyJwk: MOCK_PRIVATE_JWK,
    ecdsaPublicKeyJwk: MOCK_PUBLIC_JWK,
};

// Define the database name used by the IndexedDBProvider internally.
// NOTE: This must match the name used inside your actual provider implementation.
const DB_NAME = 'securee2e-keys';

describe('IndexedDBProvider (Persistence Tests)', () => {
    
    // Clear the database before each test to ensure tests are isolated
    beforeEach(async () => {
        return new Promise((resolve) => {
            // fake-indexeddb keeps state in memory, so deleting the database effectively clears it.
            const req = indexedDB.deleteDatabase(DB_NAME);
            req.onsuccess = () => resolve(true);
            req.onerror = () => {
                console.error('Failed to delete database during cleanup.');
                resolve(false); 
            };
        });
    });

    it('should report that storage is available', () => {
        // Since fake-indexeddb is loaded, the provider should confirm availability.
        const provider = new IndexedDBProvider(DB_NAME);
        expect(provider.isAvailable()).toBe(true);
    });

    it('should return null when loading keys from an empty database', async () => {
        const provider = new IndexedDBProvider(DB_NAME);
        const keys = await provider.load();
        expect(keys).toBeNull();
    });

    it('should successfully save keys and load them back in the same instance', async () => {
        const provider = new IndexedDBProvider(DB_NAME);
        
        await provider.save(MOCK_KEY_SET);
        
        const loadedKeys = await provider.load();
        
        expect(loadedKeys).toEqual(MOCK_KEY_SET);
    });

    it('should maintain persistence across new provider instances (simulated restart)', async () => {
        // 1. Save data using the first instance
        const provider1 = new IndexedDBProvider(DB_NAME);
        await provider1.save(MOCK_KEY_SET);

        // 2. Create a second instance (simulates app restart/module reload)
        // Since fake-indexeddb is in memory, this will access the existing data store.
        const provider2 = new IndexedDBProvider(DB_NAME); 
        
        // 3. Load data using the second instance
        const loadedKeys = await provider2.load();

        expect(loadedKeys).toEqual(MOCK_KEY_SET);
    });

    it('should return null after keys are saved and then deleted (if deletion is implemented)', async () => {
        const provider = new IndexedDBProvider(DB_NAME);
        
        // Save
        await provider.save(MOCK_KEY_SET);
        let loadedKeys = await provider.load();
        expect(loadedKeys).toEqual(MOCK_KEY_SET);

        // Assuming your provider has a 'delete' or 'clear' method
        // If not, you may need to add it or skip this test.
        // For security, an LTID provider often doesn't need a public delete method, 
        // but testing the persistence layer is useful.
        // If your provider uses 'save(null)' to clear, replace deleteKeys() below.
        if (typeof provider.deleteKeys === 'function') {
            await provider.deleteKeys(); 
            loadedKeys = await provider.load();
            expect(loadedKeys).toBeNull();
        } else {
            // Optional: Log a warning if the delete method is missing
            console.warn("Skipping persistence deletion test: IndexedDBProvider.deleteKeys() method is missing.");
        }
    });
});
