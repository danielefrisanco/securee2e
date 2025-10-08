## securee2e: Vue Composable for End-to-End Encryption

`securee2e` is a straightforward Vue 3 composable built on the native **Web Cryptography API** to facilitate secure **Diffie-Hellman Key Exchange (ECDH)** and **AES-GCM** symmetric encryption. It is designed for applications where two users need to establish a shared secret key over an insecure channel.

## ✨ Features

* **ECDH P-256 Key Exchange:** Uses the standard Elliptic Curve Diffie-Hellman with the P-256 curve for robust key agreement.

* **AES-256 GCM Encryption:** Employs the highly secure AES-GCM (256-bit) algorithm for encrypting messages.

* **Security Focused:** Private keys are generated as **non-extractable** (cannot be read or exported) by default, forcing derivation logic.

* **Base64 Serialization:** Helper functions for easy export/import of public keys via Base64 strings, making them ready for network transmission.

## 📦 Installation and Setup

Since this is intended to be a reusable library, you would typically install it using a package manager:

```bash
# Using npm
npm install securee2e

# Using yarn
yarn add securee2e
```
## Usage in Project
Import and use the composable directly in any Vue component or JavaScript file:

```typescript
import { useDiffieHellman } from 'securee2e'; 
// ...

```
## 📖 Usage: The E2E Exchange Workflow

The E2E encryption process requires five sequential steps:

1. **Generate Keys:** Both parties generate their own public/private ECDH key pair.

2. **Exchange Public Keys:** Parties send their respective public keys (as Base64 strings) to each other.

3. **Derive Secret:** Each party combines their private key with the remote party's public key to derive an identical, shared symmetric secret (AES-GCM Key).

4. **Encrypt:** Use the shared secret to encrypt the plaintext message.

5. **Decrypt:** The recipient uses their identical shared secret key to decrypt the received ciphertext and IV.

### Example: Alice Sends a Secure Message to Bob

This example demonstrates the core functionality from Alice's perspective. Bob's steps to receive the message are mirrored.

```typescript
import { useDiffieHellman } from 'securee2e';

const {
generateKeyPair,
exportPublicKeyBase64,
importRemotePublicKeyBase64,
deriveSharedSecret,
encryptData,
decryptData
} = useDiffieHellman();

async function runSecureExchange(bobPublicKeyBase64: string) {
// --- 1. & 2. ALICE'S SETUP & EXCHANGE ---
// Alice generates her own key pair
const aliceKeyPair = await generateKeyPair();

// Alice exports her public key (to be sent to Bob)
const alicePublicKeyBase64 = await exportPublicKeyBase64(aliceKeyPair.publicKey);
console.log("Alice's Key to Share:", alicePublicKeyBase64);

// --- 3. DERIVE SHARED SECRET ---
// Alice uses Bob's key (received over the wire) and her private key
const bobPublicKey = await importRemotePublicKeyBase64(bobPublicKeyBase64);

const aliceSharedKey = await deriveSharedSecret(
    aliceKeyPair.privateKey, 
    bobPublicKey
);
console.log("Shared Secret Derived Successfully.");

// --- 4. ENCRYPT MESSAGE (ALICE SENDS) ---
const plaintext = "This is a truly secret message.";

// Encrypts and generates a unique IV (Initialization Vector)
const encryptedPayload = await encryptData(aliceSharedKey, plaintext);

// The recipient needs BOTH the IV and the ciphertext
const { iv, ciphertext } = encryptedPayload;

// --- 5. DECRYPT MESSAGE (BOB RECEIVES - SIMULATED) ---
// Assuming Bob has also derived the *identical* shared secret (bobSharedKey)
// For this demo, we use aliceSharedKey to prove the keys match.
const decryptedMessage = await decryptData(
    aliceSharedKey, // Bob uses his shared key
    iv, 
    ciphertext
);

console.log("Decrypted Message:", decryptedMessage); // Logs: "This is a truly secret message."

// Example usage (replace with actual network communication)
// runSecureExchange(bob_key_received_from_network);
```

## ⚠️ Security Notes

1. **Non-Extractable Private Keys:** The `generateKeyPair` function sets the private key as non-extractable (`false`). This is a security best practice, preventing accidental exposure of the key material through functions like `exportKey`.

2. **Initialization Vector (IV) is Mandatory:** For AES-GCM encryption, a unique 12-byte IV is generated for **every single message**. This IV is not secret and must be transmitted along with the ciphertext, but reusing the same IV for multiple messages will fatally compromise security. The `encryptData` function handles the generation and inclusion of the IV in the return object.

3. **No Authentication:** This library handles key *agreement*, but not key *authentication*. To prevent Man-in-the-Middle (MITM) attacks, the public keys must be validated (e.g., using a certificate, signing them with an independent RSA key, or through a trust-on-first-use mechanism).
