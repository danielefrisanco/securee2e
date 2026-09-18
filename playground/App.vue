<script setup lang="ts">
import { ref } from 'vue';
import type { EncryptedPayload, KeyAuthPayload } from 'securee2e/vue';
import Peer from './Peer.vue';

// Simulates the network: whatever one peer emits is delivered to the other.
const toBob = ref<KeyAuthPayload | null>(null);
const toAlice = ref<KeyAuthPayload | null>(null);
const msgToBob = ref<EncryptedPayload | null>(null);
const msgToAlice = ref<EncryptedPayload | null>(null);
</script>

<template>
    <main>
        <h1>securee2e playground</h1>
        <p>
            Two peers in one page. Click <em>Generate</em> on both sides, optionally paste the other side's fingerprint to pin it,
            then <em>Verify &amp; derive</em> on both. Identities are stored in IndexedDB and survive a reload.
            Try <em>Reset identity</em> on one side after pinning to see the mismatch error.
        </p>
        <div class="peers">
            <Peer name="Alice" :incoming-payload="toAlice" :incoming-message="msgToAlice" @payload="toBob = $event" @message="msgToBob = $event" />
            <Peer name="Bob" :incoming-payload="toBob" :incoming-message="msgToBob" @payload="toAlice = $event" @message="msgToAlice = $event" />
        </div>
    </main>
</template>

<style>
body { margin: 0; font-family: system-ui, sans-serif; background: #f4f7f6; color: #222; }
main { max-width: 1000px; margin: 0 auto; padding: 2rem 1rem; }
.peers { display: flex; gap: 1rem; flex-wrap: wrap; }
</style>
