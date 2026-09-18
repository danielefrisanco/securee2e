/**
 * securee2e/vue — a thin reactive wrapper around `createSecureE2E()`.
 *
 * Everything cryptographic lives in the framework-agnostic core; this file only
 * adds Vue refs for the bits a template cares about (readiness, identity,
 * errors) and kicks off initialisation for you.
 */
import { computed, readonly, ref, shallowRef, type Ref } from 'vue';
import { createSecureE2E, type SecureE2E, type SecureE2EOptions } from './core/secureE2E';
import type { CipherOptions, EncryptedPayload, LocalAuthResult, RemoteIdentity, VerifyOptions } from './core/types';

export type * from './core/types';
export * from './core/errors';
export { createSecureE2E, type SecureE2E, type SecureE2EOptions } from './core/secureE2E';
export {
    InMemoryStorageProvider,
    IndexedDBProvider,
    LocalStorageProvider,
    type IKeyStorageProvider,
} from './storage/index';

export interface UseSecureE2EOptions extends SecureE2EOptions {
    /** Start loading the identity immediately. Defaults to `true`. */
    autoInit?: boolean;
}

export interface UseSecureE2EReturn {
    /** `true` once the identity has been loaded or generated. */
    isReady: Readonly<Ref<boolean>>;
    /** `true` while the identity is loading. */
    isInitializing: Readonly<Ref<boolean>>;
    /** Last initialisation / reset error, or `null`. */
    error: Readonly<Ref<Error | null>>;
    /** This device's identity public key (SPKI, Base64), or `null` until ready. */
    identityPublicKey: Readonly<Ref<string | null>>;
    /** This device's identity fingerprint, or `null` until ready. */
    identityFingerprint: Readonly<Ref<string | null>>;

    /** Loads the identity. Safe to call repeatedly; resolves once ready. */
    init(): Promise<void>;
    /** Deletes the identity and generates a new one. */
    resetIdentity(): Promise<void>;

    generateLocalAuthPayload(): Promise<LocalAuthResult>;
    verifyRemotePayload(remote: unknown, options?: VerifyOptions): Promise<RemoteIdentity>;
    deriveSecretFromRemotePayload(local: LocalAuthResult, remote: unknown, options?: VerifyOptions): Promise<CryptoKey>;
    encryptMessage(sessionKey: CryptoKey, plaintext: string | Uint8Array, options?: CipherOptions): Promise<EncryptedPayload>;
    decryptMessage(sessionKey: CryptoKey, payload: unknown, options?: CipherOptions): Promise<string>;
    decryptBytes(sessionKey: CryptoKey, payload: unknown, options?: CipherOptions): Promise<Uint8Array>;

    /** The underlying framework-agnostic instance. */
    e2e: SecureE2E;
}

/**
 * Vue 3 composable. Works inside `setup()` or anywhere else (it does not depend
 * on a component instance). Each call creates its own instance; instances that
 * share a storage provider share an identity.
 */
export function useSecureE2E(options: UseSecureE2EOptions = {}): UseSecureE2EReturn {
    const e2e = createSecureE2E(options);

    const isReady = ref(false);
    const isInitializing = ref(false);
    const error = shallowRef<Error | null>(null);
    const identityPublicKey = ref<string | null>(null);
    const identityFingerprint = ref<string | null>(null);

    async function init(): Promise<void> {
        if (isReady.value) return;
        isInitializing.value = true;
        error.value = null;
        try {
            await e2e.init();
            identityPublicKey.value = await e2e.getIdentityPublicKey();
            identityFingerprint.value = await e2e.getIdentityFingerprint();
            isReady.value = true;
        } catch (e) {
            error.value = e instanceof Error ? e : new Error(String(e));
            throw error.value;
        } finally {
            isInitializing.value = false;
        }
    }

    async function resetIdentity(): Promise<void> {
        isReady.value = false;
        await e2e.resetIdentity();
        await init();
    }

    if (options.autoInit ?? true) {
        // Errors are surfaced through `error`; an unhandled rejection here would just be noise.
        init().catch(() => {});
    }

    return {
        isReady: readonly(isReady),
        isInitializing: readonly(isInitializing),
        error: computed(() => error.value),
        identityPublicKey: readonly(identityPublicKey),
        identityFingerprint: readonly(identityFingerprint),
        init,
        resetIdentity,
        generateLocalAuthPayload: () => e2e.generateLocalAuthPayload(),
        verifyRemotePayload: (remote, o) => e2e.verifyRemotePayload(remote, o),
        deriveSecretFromRemotePayload: (local, remote, o) => e2e.deriveSecretFromRemotePayload(local, remote, o),
        encryptMessage: (key, plaintext, o) => e2e.encryptMessage(key, plaintext, o),
        decryptMessage: (key, payload, o) => e2e.decryptMessage(key, payload, o),
        decryptBytes: (key, payload, o) => e2e.decryptBytes(key, payload, o),
        e2e,
    };
}
