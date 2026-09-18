<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useSecureE2E, IndexedDBProvider, SecureE2EError } from 'securee2e/vue';
import type { EncryptedPayload, KeyAuthPayload, LocalAuthResult } from 'securee2e/vue';

const props = defineProps<{
    name: string;
    /** Payload received from the other peer (auto-delivered by the parent). */
    incomingPayload: KeyAuthPayload | null;
    /** Encrypted message received from the other peer. */
    incomingMessage: EncryptedPayload | null;
}>();

const emit = defineEmits<{
    payload: [payload: KeyAuthPayload];
    message: [message: EncryptedPayload];
}>();

// Each peer gets its own identity record so both can live in one browser.
const e2e = useSecureE2E({ storage: new IndexedDBProvider({ recordId: props.name.toLowerCase() }) });

const local = ref<LocalAuthResult | null>(null);
const sessionKey = ref<CryptoKey | null>(null);
const expectedFingerprint = ref('');
const remoteFingerprint = ref<string | null>(null);
const status = ref('');
const draft = ref('');
const log = ref<{ from: string; text: string }[]>([]);

const canDerive = computed(() => local.value !== null && props.incomingPayload !== null && !sessionKey.value);

async function generate() {
    local.value = await e2e.generateLocalAuthPayload();
    sessionKey.value = null;
    emit('payload', local.value.payload);
    status.value = 'Payload sent to the other peer.';
}

async function derive() {
    if (!local.value || !props.incomingPayload) return;
    try {
        const options = expectedFingerprint.value.trim() ? { expectedFingerprint: expectedFingerprint.value } : {};
        const info = await e2e.verifyRemotePayload(props.incomingPayload, options);
        remoteFingerprint.value = info.fingerprint;
        sessionKey.value = await e2e.deriveSecretFromRemotePayload(local.value, props.incomingPayload, options);
        status.value = options.expectedFingerprint ? 'Session established (identity pinned ✔).' : 'Session established (⚠ identity NOT pinned).';
    } catch (err) {
        status.value = err instanceof SecureE2EError ? `${err.name}: ${err.message}` : String(err);
    }
}

async function send() {
    if (!sessionKey.value || !draft.value) return;
    const encrypted = await e2e.encryptMessage(sessionKey.value, draft.value);
    log.value.push({ from: props.name, text: draft.value });
    emit('message', encrypted);
    draft.value = '';
}

watch(
    () => props.incomingMessage,
    async (message) => {
        if (!message || !sessionKey.value) return;
        try {
            log.value.push({ from: 'them', text: await e2e.decryptMessage(sessionKey.value, message) });
        } catch (err) {
            log.value.push({ from: 'error', text: err instanceof Error ? err.message : String(err) });
        }
    },
);

async function reset() {
    await e2e.resetIdentity();
    local.value = null;
    sessionKey.value = null;
    remoteFingerprint.value = null;
    log.value = [];
    status.value = 'Identity reset. Peers that pinned the old fingerprint will now reject you.';
}
</script>

<template>
    <section class="peer">
        <h2>{{ name }}</h2>

        <p v-if="e2e.error.value" class="error">{{ e2e.error.value.message }}</p>
        <p v-else-if="!e2e.isReady.value">Loading identity…</p>
        <template v-else>
            <p class="fp">
                <strong>My fingerprint</strong><br />
                <code>{{ e2e.identityFingerprint.value }}</code>
            </p>

            <div class="row">
                <button @click="generate">1. Generate &amp; send payload</button>
                <button @click="reset" class="secondary">Reset identity</button>
            </div>

            <label>
                Expected remote fingerprint (paste from the other side to pin; leave empty to skip)
                <input v-model="expectedFingerprint" placeholder="ABCD 1234 …" />
            </label>

            <button :disabled="!canDerive" @click="derive">2. Verify &amp; derive session key</button>
            <p v-if="remoteFingerprint" class="fp"><strong>Remote fingerprint</strong><br /><code>{{ remoteFingerprint }}</code></p>
            <p class="status">{{ status }}</p>

            <div v-if="sessionKey" class="chat">
                <ul>
                    <li v-for="(m, i) in log" :key="i" :class="m.from"><b>{{ m.from }}:</b> {{ m.text }}</li>
                </ul>
                <form @submit.prevent="send">
                    <input v-model="draft" placeholder="Type a message" />
                    <button type="submit">Send</button>
                </form>
            </div>
        </template>
    </section>
</template>

<style scoped>
.peer { flex: 1; min-width: 320px; padding: 1rem; border: 1px solid #ddd; border-radius: 8px; background: #fff; }
h2 { margin-top: 0; }
.row { display: flex; gap: 0.5rem; margin: 0.5rem 0; }
button { padding: 0.5rem 0.75rem; cursor: pointer; }
button.secondary { background: transparent; }
button:disabled { cursor: not-allowed; opacity: 0.5; }
label { display: block; font-size: 0.85rem; margin: 0.75rem 0; }
input { width: 100%; box-sizing: border-box; padding: 0.4rem; margin-top: 0.25rem; }
.fp code { font-size: 0.8rem; word-break: break-all; }
.status { min-height: 1.2em; font-size: 0.9rem; color: #444; }
.error { color: #b00020; }
.chat ul { list-style: none; padding: 0; max-height: 200px; overflow: auto; }
.chat li.them { color: #1a5fb4; }
.chat li.error { color: #b00020; }
.chat form { display: flex; gap: 0.5rem; }
</style>
