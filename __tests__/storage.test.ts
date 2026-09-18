import { beforeEach, describe, expect, it } from 'vitest';
import { exportKeyJwk, exportPublicKeyBase64, generateIdentityKeyPair } from '../src/core/crypto';
import {
    getDefaultStorageProvider,
    IndexedDBProvider,
    InMemoryStorageProvider,
    LEGACY_LOCAL_STORAGE_KEY,
    LocalStorageProvider,
    type IKeyStorageProvider,
} from '../src/storage/index';

async function identity(extractable = false) {
    const pair = await generateIdentityKeyPair(extractable);
    return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

function deleteDatabase(name: string) {
    return new Promise<void>((resolve) => {
        const req = indexedDB.deleteDatabase(name);
        req.onsuccess = req.onerror = req.onblocked = () => resolve();
    });
}

/** Behaviour every provider must share. */
function providerContract(name: string, make: () => IKeyStorageProvider, extractable: boolean) {
    describe(`${name} contract`, () => {
        it('returns null when empty', async () => {
            expect(await make().load()).toBeNull();
        });

        it('saves, loads and clears', async () => {
            const provider = make();
            const id = await identity(extractable);
            await provider.save(id);

            const loaded = await provider.load();
            expect(loaded).not.toBeNull();
            expect(await exportPublicKeyBase64(loaded!.publicKey)).toBe(await exportPublicKeyBase64(id.publicKey));
            expect(loaded!.privateKey.usages).toContain('sign');

            await provider.clear();
            expect(await provider.load()).toBeNull();
        });

        it('overwrites on save', async () => {
            const provider = make();
            await provider.save(await identity(extractable));
            const second = await identity(extractable);
            await provider.save(second);
            const loaded = await provider.load();
            expect(await exportPublicKeyBase64(loaded!.publicKey)).toBe(await exportPublicKeyBase64(second.publicKey));
        });
    });
}

describe('InMemoryStorageProvider', () => {
    providerContract('InMemoryStorageProvider', () => new InMemoryStorageProvider(), false);

    it('does not share state between instances', async () => {
        const a = new InMemoryStorageProvider();
        await a.save(await identity());
        expect(await new InMemoryStorageProvider().load()).toBeNull();
    });
});

describe('IndexedDBProvider', () => {
    const DB = 'securee2e-test-db';
    beforeEach(async () => {
        await deleteDatabase(DB);
        localStorage.clear();
    });

    providerContract('IndexedDBProvider', () => new IndexedDBProvider({ dbName: DB }), false);

    it('reports availability', () => {
        expect(IndexedDBProvider.isAvailable()).toBe(true);
    });

    it('persists non-extractable CryptoKeys across instances (simulated reload)', async () => {
        const id = await identity(false);
        await new IndexedDBProvider({ dbName: DB }).save(id);

        const loaded = await new IndexedDBProvider({ dbName: DB }).load();
        expect(loaded!.privateKey).toBeInstanceOf(CryptoKey);
        expect(loaded!.privateKey.extractable).toBe(false);
        expect(await exportPublicKeyBase64(loaded!.publicKey)).toBe(await exportPublicKeyBase64(id.publicKey));
    });

    it('isolates identities by recordId', async () => {
        const a = new IndexedDBProvider({ dbName: DB, recordId: 'alice' });
        const b = new IndexedDBProvider({ dbName: DB, recordId: 'bob' });
        await a.save(await identity());
        expect(await b.load()).toBeNull();
    });

    it('migrates a 0.4.0 localStorage identity into IndexedDB as non-extractable and removes the old entry', async () => {
        const pair = await generateIdentityKeyPair(true);
        localStorage.setItem(
            LEGACY_LOCAL_STORAGE_KEY,
            JSON.stringify({
                ecdsaPrivateKeyJwk: await exportKeyJwk(pair.privateKey),
                ecdsaPublicKeyJwk: await exportKeyJwk(pair.publicKey),
            }),
        );

        const loaded = await new IndexedDBProvider({ dbName: DB }).load();
        expect(loaded).not.toBeNull();
        expect(loaded!.privateKey.extractable).toBe(false);
        expect(await exportPublicKeyBase64(loaded!.publicKey)).toBe(await exportPublicKeyBase64(pair.publicKey));
        expect(localStorage.getItem(LEGACY_LOCAL_STORAGE_KEY)).toBeNull();

        // Now persisted in IDB: a provider with migration disabled still finds it.
        const again = await new IndexedDBProvider({ dbName: DB, migrateLegacyLocalStorage: false }).load();
        expect(await exportPublicKeyBase64(again!.publicKey)).toBe(await exportPublicKeyBase64(pair.publicKey));
    });

    it('ignores corrupt legacy data', async () => {
        localStorage.setItem(LEGACY_LOCAL_STORAGE_KEY, '{not json');
        expect(await new IndexedDBProvider({ dbName: DB }).load()).toBeNull();
    });
});

describe('LocalStorageProvider', () => {
    beforeEach(() => localStorage.clear());

    providerContract('LocalStorageProvider', () => new LocalStorageProvider(), true);

    it('requires extractable keys and stores JWK', async () => {
        const provider = new LocalStorageProvider();
        expect(provider.requiresExtractableKeys).toBe(true);
        await provider.save(await identity(true));
        const raw = JSON.parse(localStorage.getItem('securee2e/identity/v1')!);
        expect(raw.ecdsaPrivateKeyJwk.d).toBeTypeOf('string');
    });

    it('cannot save a non-extractable key', async () => {
        await expect(new LocalStorageProvider().save(await identity(false))).rejects.toThrow();
    });

    it('reads a 0.4.0 identity from the legacy key', async () => {
        const pair = await generateIdentityKeyPair(true);
        localStorage.setItem(
            LEGACY_LOCAL_STORAGE_KEY,
            JSON.stringify({
                ecdsaPrivateKeyJwk: await exportKeyJwk(pair.privateKey),
                ecdsaPublicKeyJwk: await exportKeyJwk(pair.publicKey),
            }),
        );
        const loaded = await new LocalStorageProvider().load();
        expect(await exportPublicKeyBase64(loaded!.publicKey)).toBe(await exportPublicKeyBase64(pair.publicKey));
    });

    it('drops corrupt data instead of failing forever', async () => {
        localStorage.setItem('securee2e/identity/v1', '{oops');
        expect(await new LocalStorageProvider().load()).toBeNull();
        expect(localStorage.getItem('securee2e/identity/v1')).toBeNull();
    });
});

describe('getDefaultStorageProvider', () => {
    it('prefers IndexedDB when available and is a singleton', () => {
        const p = getDefaultStorageProvider();
        expect(p).toBeInstanceOf(IndexedDBProvider);
        expect(getDefaultStorageProvider()).toBe(p);
    });
});
