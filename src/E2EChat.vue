<script setup lang="ts">
import { ref, computed } from 'vue';
// Assuming your composable is available via this path
import { useDiffieHellman } from '../src/composables/useDiffieHellman'; 
import type { CryptoKey } from 'node:crypto'; // Use the correct global type

// Initialize the composable
const { 
  generateKeyPair, 
  exportPublicKeyBase64, 
  importRemotePublicKeyBase64,
  deriveSharedSecret,
  encryptData,
  decryptData
} = useDiffieHellman();

// --- State Management ---
// Simulation of two users, Alice and Bob
const alice = ref({
  keyPair: null as CryptoKeyPair | null,
  sharedKey: null as CryptoKey | null,
  publicKeyBase64: '',
});

const bob = ref({
  keyPair: null as CryptoKeyPair | null,
  sharedKey: null as CryptoKey | null,
  publicKeyBase64: '',
});

const chatHistory = ref<{ sender: 'Alice' | 'Bob', message: string }[]>([]);
const currentMessage = ref('');
const statusMessage = ref('Ready. Click "Start Key Exchange" to begin.');

const isEncrypted = computed(() => !!alice.value.sharedKey && !!bob.value.sharedKey);

// --- 1. Key Generation and Export ---
async function generateKeys() {
  try {
    statusMessage.value = 'Generating key pairs...';
    alice.value.keyPair = await generateKeyPair();
    bob.value.keyPair = await generateKeyPair();
  
    statusMessage.value = 'Alice: Exporting public key...';
    alice.value.publicKeyBase64 = await exportPublicKeyBase64(alice.value.keyPair.publicKey);

    statusMessage.value = 'Bob: Exporting public key...';
    bob.value.publicKeyBase64 = await exportPublicKeyBase64(bob.value.keyPair.publicKey);
    
    statusMessage.value = 'Public keys serialized. Ready for derivation.';
    return true;
  } catch (error) {
    console.error("Key Generation/Export Error:", error);
    statusMessage.value = `❌ FAILED at Key Generation: ${error instanceof Error ? error.message : String(error)}`;
    return false;
  }
}

// --- 2. Shared Secret Derivation ---
async function deriveSecrets() {
  if (!alice.value.keyPair || !bob.value.keyPair) {
    statusMessage.value = 'Keys not generated. Start key exchange first.';
    return;
  }
  
  try {
    statusMessage.value = 'Alice: Importing remote public key...';
    const bobPublicKey = await importRemotePublicKeyBase64(bob.value.publicKeyBase64);
    
    statusMessage.value = 'Alice: Deriving shared secret...';
    alice.value.sharedKey = await deriveSharedSecret(alice.value.keyPair.privateKey, bobPublicKey);

    statusMessage.value = 'Bob: Importing remote public key...';
    const alicePublicKey = await importRemotePublicKeyBase64(alice.value.publicKeyBase64);
    
    statusMessage.value = 'Bob: Deriving shared secret...';
    bob.value.sharedKey = await deriveSharedSecret(bob.value.keyPair.privateKey, alicePublicKey);

    statusMessage.value = '✅ Key exchange complete! Shared secret derived. Chat is secure.';
  } catch (error) {
    console.error("Key Derivation Error:", error);
    // This logs the raw browser error from the composable for detailed debugging
    statusMessage.value = `❌ FAILED at Derivation: ${error instanceof Error ? error.message : String(error)}. Check console for details.`;
  }
}

// --- 3. Encrypt and Decrypt Message ---
async function sendMessage(sender: 'Alice' | 'Bob') {
  if (!currentMessage.value || !isEncrypted.value) return;

  const key = sender === 'Alice' ? alice.value.sharedKey : bob.value.sharedKey;
  const messageText = currentMessage.value;

  try {
    // 1. Encrypt (Simulated sending)
    const { iv, ciphertext } = await encryptData(key as CryptoKey, messageText);

    // 2. Decrypt (Simulated receiving)
    // The receiver uses their own shared key (which should be identical)
    const receiverKey = sender === 'Alice' ? bob.value.sharedKey : alice.value.sharedKey;
    const decryptedText = await decryptData(receiverKey as CryptoKey, iv, ciphertext);

    // 3. Add to history
    chatHistory.value.push({ sender: sender, message: messageText });
    console.log(`[${sender} Sent] Encrypted data size: ${ciphertext.byteLength} bytes.`);
    console.log(`[Receiver] Decrypted text: "${decryptedText}"`);
    
    currentMessage.value = ''; // Clear input

  } catch (error) {
    statusMessage.value = `❌ Message failed to send/decrypt: ${error instanceof Error ? error.message : String(error)}`;
    console.error("Encryption/Decryption Error:", error);
  }
}

// --- Execution Flow ---
async function startKeyExchange() {
  const success = await generateKeys();
  if (success) {
    await deriveSecrets();
  }
}
</script>

<template>
  <div class="e2e-chat-demo">
    <h2>securee2e Diffie-Hellman Demo</h2>
    <div :class="['status-bar', { 'secure': isEncrypted, 'error': statusMessage.includes('❌') }]">
      {{ statusMessage }}
    </div>

    <button @click="startKeyExchange" :disabled="isEncrypted" class="exchange-btn">
      {{ isEncrypted ? 'Keys Derived' : 'Start Key Exchange' }}
    </button>
    
    <hr>

    <div class="key-info-grid">
      <div class="key-info">
        <h3>Alice's Keys</h3>
        <p>Public Key (Base64): {{ alice.publicKeyBase64 ? alice.publicKeyBase64.slice(0, 30) + '...' : 'N/A' }}</p>
        <p :class="{ 'secret': isEncrypted }">Shared Key: {{ isEncrypted ? '✅ DERIVED' : 'Waiting...' }}</p>
      </div>
      <div class="key-info">
        <h3>Bob's Keys</h3>
        <p>Public Key (Base64): {{ bob.publicKeyBase64 ? bob.publicKeyBase64.slice(0, 30) + '...' : 'N/A' }}</p>
        <p :class="{ 'secret': isEncrypted }">Shared Key: {{ isEncrypted ? '✅ DERIVED' : 'Waiting...' }}</p>
      </div>
    </div>
    
    <hr>
    
    <div class="chat-window">
      <div v-for="(item, index) in chatHistory" :key="index" :class="['message', item.sender.toLowerCase()]">
        <strong>{{ item.sender }}:</strong> {{ item.message }}
      </div>
      <div v-if="!chatHistory.length" class="empty-chat">
        Start the exchange and send a message!
      </div>
    </div>
    
    <div class="input-area">
      <input 
        v-model="currentMessage" 
        placeholder="Type a message..." 
        :disabled="!isEncrypted"
        @keyup.enter="sendMessage('Alice')"
      />
      <button @click="sendMessage('Alice')" :disabled="!isEncrypted">Send (Alice)</button>
      <button @click="sendMessage('Bob')" :disabled="!isEncrypted" class="bob-send">Send (Bob)</button>
    </div>

  </div>
</template>

<style scoped>
.e2e-chat-demo {
  max-width: 600px;
  margin: 40px auto;
  padding: 20px;
  border: 1px solid #ccc;
  border-radius: 8px;
  box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
  font-family: 'Inter', sans-serif;
}
h2 {
    font-weight: 700;
    color: #333;
    text-align: center;
    margin-bottom: 20px;
}
.status-bar {
  padding: 12px;
  margin-bottom: 15px;
  border-radius: 6px;
  background-color: #f0f0f0;
  color: #333;
  font-weight: 600;
  transition: background-color 0.3s, color 0.3s;
}
.status-bar.secure {
  background-color: #d4edda;
  color: #155724;
  border: 1px solid #c3e6cb;
}
.status-bar.error {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}
.exchange-btn {
  padding: 10px 15px;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  margin-bottom: 20px;
  transition: background-color 0.2s, box-shadow 0.2s;
}
.exchange-btn:hover:not(:disabled) {
    background-color: #0056b3;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
}
.exchange-btn:disabled {
    background-color: #999;
    cursor: not-allowed;
}
.key-info-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 20px;
}
.key-info {
  background: #f9f9f9;
  padding: 15px;
  border-radius: 6px;
  border: 1px solid #eee;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}
.key-info h3 {
    font-size: 1.1em;
    margin-top: 0;
    margin-bottom: 8px;
    color: #444;
}
.key-info p {
  font-size: 0.8em;
  word-break: break-all;
  margin: 5px 0;
  color: #666;
}
.key-info .secret {
  color: #155724;
  font-weight: 700;
}
.chat-window {
  height: 250px;
  border: 1px solid #ddd;
  overflow-y: auto;
  padding: 10px;
  margin-bottom: 15px;
  border-radius: 6px;
  background: #fff;
}
.message {
  padding: 8px 10px;
  margin: 5px 0;
  border-radius: 4px;
  max-width: 85%;
}
.message.alice {
  background-color: #e6f3ff;
  text-align: left;
  margin-right: auto;
}
.message.bob {
  background-color: #f0f0f0;
  text-align: right;
  margin-left: auto;
}
.message strong {
    font-weight: 700;
}
.empty-chat {
  color: #999;
  text-align: center;
  padding-top: 80px;
}
.input-area {
  display: flex;
  gap: 10px;
}
.input-area input {
  flex-grow: 1;
  padding: 10px;
  border: 1px solid #ccc;
  border-radius: 6px;
}
.input-area button {
  padding: 10px 15px;
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  transition: background-color 0.2s;
}
.input-area button:disabled {
    background-color: #ccc !important;
    cursor: not-allowed;
}
.input-area button:hover:not(:disabled) {
    opacity: 0.9;
}
.input-area button:nth-of-type(1) { /* Alice Send */
  background-color: #28a745;
}
.input-area button:nth-of-type(2) { /* Bob Send */
  background-color: #6c757d;
}
</style>
