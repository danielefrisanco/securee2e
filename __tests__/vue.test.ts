import { describe, expect, it, vi } from 'vitest';
import { defineComponent, h, nextTick } from 'vue';
import { mount } from '@vue/test-utils';
import { InMemoryStorageProvider, useSecureE2E, type IKeyStorageProvider } from '../src/vue';

const flush = () => new Promise((r) => setTimeout(r, 0));

describe('useSecureE2E (Vue)', () => {
    it('auto-initialises and exposes reactive identity state', async () => {
        const e2e = useSecureE2E({ storage: new InMemoryStorageProvider() });
        expect(e2e.isReady.value).toBe(false);
        expect(e2e.isInitializing.value).toBe(true);
        expect(e2e.identityFingerprint.value).toBeNull();

        await e2e.init();
        expect(e2e.isReady.value).toBe(true);
        expect(e2e.isInitializing.value).toBe(false);
        expect(e2e.error.value).toBeNull();
        expect(e2e.identityPublicKey.value).toBeTypeOf('string');
        expect(e2e.identityFingerprint.value).toMatch(/^([0-9A-F]{4} ){15}[0-9A-F]{4}$/);
    });

    it('can defer initialisation with autoInit: false', async () => {
        const e2e = useSecureE2E({ storage: new InMemoryStorageProvider(), autoInit: false });
        await flush();
        expect(e2e.isReady.value).toBe(false);
        expect(e2e.isInitializing.value).toBe(false);
        await e2e.init();
        expect(e2e.isReady.value).toBe(true);
    });

    it('surfaces initialisation errors through `error` without unhandled rejections', async () => {
        const broken: IKeyStorageProvider = {
            load: async () => {
                throw new Error('storage down');
            },
            save: async () => {},
            clear: async () => {},
        };
        const e2e = useSecureE2E({ storage: broken });
        await flush();
        expect(e2e.isReady.value).toBe(false);
        expect(e2e.error.value?.message).toBe('storage down');
        await expect(e2e.init()).rejects.toThrow('storage down');
    });

    it('two composable instances complete a pinned handshake and exchange messages', async () => {
        const alice = useSecureE2E({ storage: new InMemoryStorageProvider() });
        const bob = useSecureE2E({ storage: new InMemoryStorageProvider() });
        await Promise.all([alice.init(), bob.init()]);

        const aLocal = await alice.generateLocalAuthPayload();
        const bLocal = await bob.generateLocalAuthPayload();
        const aKey = await alice.deriveSecretFromRemotePayload(aLocal, bLocal.payload, { expectedFingerprint: bob.identityFingerprint.value! });
        const bKey = await bob.deriveSecretFromRemotePayload(bLocal, aLocal.payload, { expectedFingerprint: alice.identityFingerprint.value! });

        expect(await bob.decryptMessage(bKey, await alice.encryptMessage(aKey, 'hello from vue'))).toBe('hello from vue');
    });

    it('resetIdentity() updates the reactive fingerprint', async () => {
        const e2e = useSecureE2E({ storage: new InMemoryStorageProvider() });
        await e2e.init();
        const before = e2e.identityFingerprint.value;
        await e2e.resetIdentity();
        expect(e2e.isReady.value).toBe(true);
        expect(e2e.identityFingerprint.value).not.toBe(before);
    });

    it('renders reactive state inside a component', async () => {
        const Comp = defineComponent({
            setup() {
                const { isReady, identityFingerprint } = useSecureE2E({ storage: new InMemoryStorageProvider() });
                return () => h('p', isReady.value ? (identityFingerprint.value ?? '') : 'loading');
            },
        });
        const wrapper = mount(Comp);
        expect(wrapper.text()).toBe('loading');
        await vi.waitFor(async () => {
            await nextTick();
            expect(wrapper.text()).toMatch(/^([0-9A-F]{4} ){15}[0-9A-F]{4}$/);
        });
    });
});
