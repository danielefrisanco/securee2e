<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useDiffieHellman } from './composables/useDiffieHellman';

// --- Types ---
interface KeyExchangePayload {
    ecdhPublicKey: string;
    ecdsaPublicKey: string;
    signature: string;
}

interface EncryptedMessage {
    iv: string;
    ciphertext: string;
    sender: 'local' | 'remote';
    decryptedText?: string; 
}

// --- State Management ---
const dh = useDiffieHellman();

// Local Identity (Purely for context, not network authentication)
const localId = ref(crypto.randomUUID().substring(0, 8)); 

// Key Pairs (Private keys are non-extractable CryptoKey objects)
const ecdhKeyPair = ref<CryptoKeyPair | null>(null);
const ecdsaKeyPair = ref<CryptoKeyPair | null>(null);

// Shared Secret and Connection Status
const sharedSecret = ref<CryptoKey | null>(null);
const connectionStatus = ref<'disconnected' | 'awaiting-key' | 'connected' | 'error'>('disconnected');
const statusMessage = ref('Click "Generate Keys" to start the handshake.');

// Data for Exchange
const localEcdhPublicKey = ref('');
const localEcdsaPublicKey = ref('');
const localSignature = ref('');

const remoteKeyExchangePayload = ref<KeyExchangePayload | null>(null);

// Chat State
const messages = ref<EncryptedMessage[]>([]);
const inputMessage = ref('');
const chatLog = ref<string[]>([]);

// Manual Decryption State
const manualCiphertext = ref('');
const manualIv = ref('');
const manualDecryptedResult = ref('');


// --- Computed Properties ---
const isConnected = computed(() => connectionStatus.value === 'connected');
const isAwaitingKey = computed(() => connectionStatus.value === 'awaiting-key');

// --- Key Management and Handshake Functions ---

/**
 * Step 1: Generate all keys (ECDH for encryption, ECDSA for signing)
 */
const generateKeys = async () => {
    try {
        connectionStatus.value = 'disconnected';
        statusMessage.value = 'Generating keys...';

        // 1. Generate ECDH Key Pair for encryption/derivation
        const dhKeys = await dh.generateKeyPair();
        ecdhKeyPair.value = dhKeys;

        // 2. Generate ECDSA Key Pair for authentication/signatures
        const signKeys = await dh.generateSigningKeys();
        ecdsaKeyPair.value = signKeys;

        // 3. Export Public Keys for transmission
        localEcdhPublicKey.value = await dh.exportPublicKeyBase64(dhKeys.publicKey);
        localEcdsaPublicKey.value = await dh.exportSigningPublicKeyBase64(signKeys.publicKey);
        
        // 4. Sign the ECDH public key using the ECDSA private key
        if (ecdsaKeyPair.value.privateKey) {
            localSignature.value = await dh.signPublicKey(
                ecdsaKeyPair.value.privateKey,
                dhKeys.publicKey
            );
        } else {
            throw new Error('ECDSA Private Key not generated.');
        }

        connectionStatus.value = 'awaiting-key';
        statusMessage.value = `Keys generated! Share the following payload with the remote party. Your Local ID: ${localId.value}`;
        chatLog.value.push('--- Keys Generated. Awaiting remote key. ---');

    } catch (error) {
        console.error('Key generation error:', error);
        statusMessage.value = `Error generating keys: ${error.message}`;
        connectionStatus.value = 'error';
    }
};

/**
 * Step 2: Handle receiving the remote party's key exchange payload
 */
const handleRemoteKey = async (payload: KeyExchangePayload) => {
    try {
        if (!ecdhKeyPair.value || !ecdsaKeyPair.value) {
            statusMessage.value = 'ERROR: Local keys must be generated first!';
            connectionStatus.value = 'error';
            return;
        }

        if (typeof payload !== 'object' || !payload.ecdhPublicKey || !payload.ecdsaPublicKey || !payload.signature) {
             statusMessage.value = 'ERROR: Invalid key exchange payload format.';
             return;
        }

        remoteKeyExchangePayload.value = payload;
        statusMessage.value = 'Received remote key payload. Verifying signature...';

        // 1. Import Remote Keys
        const importedRemoteEcdhKey = await dh.importRemotePublicKeyBase64(payload.ecdhPublicKey);
        const importedRemoteEcdsaKey = await dh.importRemoteSigningPublicKeyBase64(payload.ecdsaPublicKey);

        // 2. CRITICAL SECURITY STEP: Verify the signature
        const isSignatureValid = await dh.verifySignature(
            importedRemoteEcdsaKey,
            importedRemoteEcdhKey,
            payload.signature
        );

        if (!isSignatureValid) {
            connectionStatus.value = 'error';
            statusMessage.value = 'SECURITY WARNING: Signature verification FAILED. Key exchange aborted (MITM attack possible).';
            chatLog.value.push('!!! SECURITY FAIL: Remote key signature is INVALID. ABORTING HANDSHAKE. !!!');
            return;
        }

        // 3. If valid, derive shared secret
        const secret = await dh.deriveSharedSecret(
            ecdhKeyPair.value.privateKey,
            importedRemoteEcdhKey
        );
        sharedSecret.value = secret;

        connectionStatus.value = 'connected';
        statusMessage.value = 'Key verified and Shared Secret derived! Connection secured. Start chatting!';
        chatLog.value.push('--- SIGNATURE VERIFIED. Connection is SECURE. ---');
    } catch (error) {
        console.error('Handshake error:', error);
        statusMessage.value = `Error during handshake: ${error.message}`;
        connectionStatus.value = 'error';
    }
};

/**
 * Step 3: Handle sending and receiving encrypted messages
 */
const sendMessage = async () => {
    if (!isConnected.value || !sharedSecret.value || !inputMessage.value.trim()) return;

    try {
        const textToSend = inputMessage.value;
        const encrypted = await dh.encryptData(sharedSecret.value, textToSend);
        
        // Log full IV and Ciphertext for manual relay testing (FIXED: showing full ciphertext)
        chatLog.value.push(`[SENT/ENCRYPTED]: IV: ${encrypted.iv}, Ciphertext: ${encrypted.ciphertext}`);
       
        // Add local message to messages state for display immediately
         messages.value.push({
            iv: encrypted.iv,
            ciphertext: encrypted.ciphertext,
            sender: 'local',
            decryptedText: textToSend // Show the decrypted text immediately for the local user
        });

        inputMessage.value = '';

    } catch (error) {
        console.error('Send message error:', error);
        statusMessage.value = `Encryption/Send error: ${error.message}`;
    }
};

/**
 * Manually decrypts a ciphertext string after completing the handshake
 */
const manualDecrypt = async () => {
    manualDecryptedResult.value = '';

    if (!isConnected.value || !sharedSecret.value) {
        manualDecryptedResult.value = 'ERROR: Must be connected (shared secret derived) to decrypt.';
        return;
    }
    if (!manualCiphertext.value || !manualIv.value) {
        manualDecryptedResult.value = 'ERROR: Ciphertext and IV are required.';
        return;
    }

    try {
        const text = await dh.decryptData(sharedSecret.value, manualIv.value, manualCiphertext.value);
        manualDecryptedResult.value = `DECRYPT SUCCESS: ${text}`;
        chatLog.value.push(`[MANUAL DECRYPT SUCCESS]: "${text}"`);

         messages.value.push({
            iv: manualIv.value,
            ciphertext: manualCiphertext.value,
            sender: 'remote',
            decryptedText: text
        });

        // Clear the fields after successful decryption
        manualIv.value = '';
        manualCiphertext.value = '';

    } catch (e) {
        console.error('Manual decryption failed:', e);
        manualDecryptedResult.value = `DECRYPTION FAILED: ${e.message}`;
        chatLog.value.push('[MANUAL DECRYPTION FAILED]');
    }
};

// --- Utilities ---

const keyExchangePayload = computed(() => {
    // This runs as long as the local public keys exist
    if (localEcdhPublicKey.value && localEcdsaPublicKey.value && localSignature.value) {
        return JSON.stringify({
            ecdhPublicKey: localEcdhPublicKey.value,
            ecdsaPublicKey: localEcdsaPublicKey.value,
            signature: localSignature.value,
        }, null, 2);
    }
    return '';
});

const reset = () => {
    // Clear all state
    ecdhKeyPair.value = null;
    ecdsaKeyPair.value = null;
    sharedSecret.value = null;
    messages.value = [];
    chatLog.value = [];
    remoteKeyExchangePayload.value = null;
    inputMessage.value = '';
    localEcdhPublicKey.value = '';
    localEcdsaPublicKey.value = '';
    localSignature.value = '';
    manualCiphertext.value = '';
    manualIv.value = '';
    manualDecryptedResult.value = '';

    // Reset status
    connectionStatus.value = 'disconnected';
    statusMessage.value = 'Key exchange reset. Click "Generate Keys" to start over.';
};
</script>

<template>
    <div class="chat-container">
        <h1 class="text-3xl font-bold mb-4 text-gray-800">Pure E2E Crypto Demo</h1>
        <p class="text-sm mb-4 text-gray-600">This demo uses client-side encryption only. Messages must be manually relayed.</p>
        <p class="text-xs mb-2 text-gray-400">Your Local ID: {{ localId }}</p>

        <!-- Status Bar -->
        <div class="status-bar" :class="{
            'bg-green-100 border-green-500 text-green-700': isConnected,
            'bg-yellow-100 border-yellow-500 text-yellow-700': isAwaitingKey,
            'bg-red-100 border-red-500 text-red-700': connectionStatus === 'error',
            'bg-gray-100 border-gray-400 text-gray-700': connectionStatus === 'disconnected' && !isConnected,
        }">
            <strong class="capitalize">{{ connectionStatus }}</strong>: {{ statusMessage }}
        </div>

        <!-- Connection Controls -->
        <div class="flex space-x-4 mb-6">
            <button
                @click="generateKeys"
                :disabled="isAwaitingKey || isConnected"
                class="btn-primary"
            >
                Generate Keys
            </button>
            <button
                @click="reset"
                :disabled="connectionStatus === 'disconnected' && !ecdhKeyPair"
                class="btn-secondary"
            >
                Reset Connection
            </button>
        </div>
        
        <!-- Key Exchange Section -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <!-- Local Payload (To share) -->
            <div v-if="ecdhKeyPair" class="key-card">
                <h3 class="text-lg font-semibold mb-2 text-blue-600">Your Key Exchange Payload (Send this)</h3>
                <textarea
                    :value="keyExchangePayload"
                    rows="8"
                    readonly
                    class="w-full p-2 border border-gray-300 rounded-lg font-mono text-xs bg-gray-50 resize-none"
                    placeholder="Payload will appear here after key generation..."
                ></textarea>
                <p class="mt-2 text-xs text-gray-500">Includes: ECDH Public Key, ECDSA Public Key, and Signature.</p>
            </div>
            <!-- Display a placeholder message if keys haven't been generated yet -->
            <div v-else class="key-card text-center p-8 bg-gray-100 text-gray-500 flex items-center justify-center h-full">
                Generate keys to see your local key payload.
            </div>

            <!-- Remote Payload (To receive) -->
            <div class="key-card">
                <h3 class="text-lg font-semibold mb-2 text-purple-600">Remote Payload (Paste Here)</h3>
                <textarea
                    @input="event => { try { handleRemoteKey(JSON.parse(event.target.value)) } catch (e) { /* Ignore invalid JSON during typing */ } }"
                    rows="8"
                    class="w-full p-2 border border-gray-300 rounded-lg font-mono text-xs bg-white resize-none"
                    placeholder="Paste the remote party's payload JSON here to start derivation..."
                ></textarea>
                <p class="mt-2 text-xs text-gray-500">Pasting a valid payload triggers key verification and secret derivation.</p>
            </div>
        </div>
        
        <!-- Manual Decryption Tool -->
        <div class="p-4 border border-indigo-300 rounded-lg bg-indigo-50 mb-6">
            <h3 class="text-lg font-semibold mb-2 text-indigo-700">Manual Ciphertext Decryptor</h3>
            <p class="text-sm mb-2 text-indigo-600">Paste the IV and Ciphertext generated by the other party after encryption.</p>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-2 mb-2">
                <input
                    v-model="manualIv"
                    type="text"
                    placeholder="Paste IV (Initialization Vector)"
                    :disabled="!isConnected"
                    class="col-span-1 p-2 border border-indigo-300 rounded-lg text-xs"
                />
                 <input
                    v-model="manualCiphertext"
                    type="text"
                    placeholder="Paste Ciphertext"
                    :disabled="!isConnected"
                    class="col-span-2 p-2 border border-indigo-300 rounded-lg text-xs"
                />
            </div>
            <div class="flex items-center space-x-4">
                <button
                    @click="manualDecrypt"
                    :disabled="!isConnected || !manualCiphertext || !manualIv"
                    class="btn-primary-indigo"
                >
                    Decrypt Message
                </button>
                <p v-if="manualDecryptedResult" :class="{ 'text-red-600': manualDecryptedResult.startsWith('ERROR') }" class="text-sm font-semibold">{{ manualDecryptedResult }}</p>
            </div>
        </div>
        
        <!-- Chat Window -->
        <div class="chat-window mb-4">
            <!-- System/Security Log -->
            <div v-for="(log, index) in chatLog" :key="`log-${index}`" class="log-entry">
                <p class="text-xs font-mono text-gray-500 italic">{{ log }}</p>
            </div>
            
            <div 
                v-for="(msg, index) in messages" 
                :key="index" 
                class="message-bubble" 
                :class="{ 
                    'self-end bg-blue-600 text-white': msg.sender === 'local', 
                    'self-start bg-gray-200 text-gray-800': msg.sender === 'remote' 
                }"
            >
                <p class="text-sm break-words">{{ msg.decryptedText || '*** Encrypted/Undecipherable Message ***' }}</p>
            </div>
            
            <div v-if="messages.length === 0 && chatLog.length === 0" class="text-center text-gray-400 p-4">
                Chat is currently disconnected.
            </div>
        </div>

        <!-- Message Input -->
        <form @submit.prevent="sendMessage" class="flex">
            <input
                v-model="inputMessage"
                type="text"
                placeholder="Type a secured message..."
                :disabled="!isConnected"
                class="flex-grow p-3 border border-gray-300 rounded-l-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
            />
            <button
                type="submit"
                :disabled="!isConnected"
                class="btn-send"
            >
                Encrypt & Send
            </button>
        </form>
    </div>
</template>

<style scoped>
/* Tailwind CSS utilities are used heavily, but custom styles for layout */
.chat-container {
    @apply max-w-4xl mx-auto w-full p-6 bg-white shadow-xl rounded-xl;
}

.status-bar {
    @apply p-3 mb-4 rounded-lg border-l-4 font-medium text-sm;
}

.chat-window {
    @apply h-64 overflow-y-auto border border-gray-200 p-4 mb-4 rounded-lg flex flex-col space-y-2;
    background-color: #f9fafb;
}

.message-bubble {
    /* Use margin auto to push bubbles to the correct side */
    @apply max-w-xs p-3 rounded-xl shadow-md text-sm;
    word-wrap: break-word;
}
.message-bubble.self-end {
    margin-left: auto;
}
.message-bubble.self-start {
    margin-right: auto;
}

.log-entry {
    @apply mt-1;
    word-break: break-all; /* Ensures long strings wrap instead of causing horizontal scroll */
}

/* Custom button styles */
.btn-primary {
    @apply bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg transition duration-150 ease-in-out shadow-md disabled:opacity-50;
}

.btn-secondary {
    @apply bg-gray-300 hover:bg-gray-400 text-gray-800 font-semibold py-2 px-4 rounded-lg transition duration-150 ease-in-out shadow-md disabled:opacity-50;
}

.btn-send {
    @apply bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 px-6 rounded-r-lg transition duration-150 ease-in-out disabled:opacity-50;
}

.key-card {
    @apply p-4 border border-dashed border-gray-300 rounded-lg bg-gray-50;
}

.btn-primary-indigo {
    @apply bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-4 rounded-lg transition duration-150 ease-in-out shadow-md disabled:opacity-50;
}

/* Base styles for the entire app */
:global(body) {
    font-family: 'Inter', sans-serif;
}
</style>
