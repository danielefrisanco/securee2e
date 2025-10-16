## securee2e: Vue Composable for End-to-End Encryption

`securee2e` is a straightforward Vue 3 composable built on the native **Web Cryptography API** to facilitate secure **Diffie-Hellman Key Exchange (ECDH)** and **AES-GCM** symmetric encryption, **now with ECDSA signature for public key authentication.**

✨ Features
----------

*   **ECDH P-256 Key Agreement:** Uses the standard Elliptic Curve Diffie-Hellman with the P-256 curve for robust key agreement.
    
*   **ECDSA P-256 Key Authentication:** Uses Elliptic Curve Digital Signature Algorithm with the P-256 curve to sign and verify public keys, **preventing Man-in-the-Middle (MITM) attacks.**
    
*   **High-Level API Wrappers (v0.3.1):** Simplified functions (`generateLocalAuthPayload`, `deriveSecretFromRemotePayload`, etc.) abstract the 6-step handshake into two simple calls, dramatically simplifying integration.

*   **AES-256 GCM Encryption:** Employs the highly secure AES-GCM (256-bit) algorithm for encrypting messages.
    
*   **Security Focused:** Private keys are generated as **non-extractable** by default.
    
*   **Base64 Serialization:** Helper functions for easy, network-ready transmission of keys, signatures, IVs, and ciphertext via URL-safe Base64 strings.
    
📦 Installation and Setup
-------------------------

Since this is intended to be a reusable library, you would typically install it using a package manager:

```Bash
# Using npm  
npm install securee2e
# Using yarn
yarn add securee2e
```

Usage in Project
----------------

Import and use the composable directly in any Vue component or JavaScript file:

```TypeScript
import { useDiffieHellman } from 'securee2e';
// ...
```
## ⚙️ Data Structures and Payloads

The library exchanges data using these required structures:

| Type | Structure | Description | 
 | ----- | ----- | ----- | 
| **KeyAuthPayload** | `{ ecdhPublicKey: string, ecdsaPublicKey: string, signature: string }` | The full payload transmitted during the key exchange handshake. | 
| **EncryptedPayload** | `{ iv: string, ciphertext: string }` | The result of `encryptData`. Both fields are Base64 strings and are required for decryption. |
| **LocalAuthResult** | `{ payload: KeyAuthPayload, ecdhPrivateKey: CryptoKey }` | Return object from the high-level key generation function. Contains the sharable payload and local ephemeral private key. |

🚀 High-Level Usage: Simplified E2E Workflow (v0.3.4)
-------------------------------------------------------
With the introduction of the high-level wrappers, the entire authenticated key exchange is reduced to a few calls. This approach enforces authentication (LTID signing) to prevent Man-in-the-Middle attacks.

```typescript
import { useDiffieHellman, KeyAuthPayload } from 'securee2e';

const {
  // High-Level functions:
  generateLocalAuthPayload,
  deriveSecretFromRemotePayload,
  encryptMessage,
  decryptMessage
} = useDiffieHellman();


async function runSimplifiedExchange(bobPayload: KeyAuthPayload) {

  // 1. ALICE'S AUTHENTICATED KEY GENERATION (1 call)
  // The LTID key is automatically loaded/generated and used to sign the payload.
  // The LTID key is automatically loaded/generated using the IndexedDBProvider`
  const aliceLocalAuth = await generateLocalAuthPayload(); 

  // Extract the ephemeral private key and the public payload to send
  const aliceEcdhPrivateKey = aliceLocalAuth.keys[0]; // Access key from the returned 'keys' array
  const alicePayload = aliceLocalAuth.payload;

  // 3. BOB'S PAYLOAD IS RECEIVED
  // (Assuming bobPayload is a valid KeyAuthPayload received from the network)

  // 4. DERIVE SHARED SECRET (1 call: imports, verifies, and derives)
  // This function uses the LTID public key inside 'bobPayload' to verify the signature.
  const aliceSharedSecret = await deriveSecretFromRemotePayload(
      aliceEcdhPrivateKey,
      bobPayload
  );
  
  // NOTE: If the signature verification fails, this function throws an error 
  // and the handshake is aborted, protecting against MITM attacks.

  // 5. ENCRYPT & DECRYPT
  const plaintext = "This is the simplified secure message.";
  const encryptedPayload = await encryptMessage(aliceSharedSecret, plaintext);

  // Simulate Bob decrypting using his identical shared secret
  // (Assuming Bob has his identical sharedSecret derived from Alice's payload)
  const decryptedMessage = await decryptMessage(aliceSharedSecret, encryptedPayload);

  console.log("Decrypted Message:", decryptedMessage); 
}
```
### 💾 Persistence and Key Management
Your Long-Term Identity (LTID) keys are now **persistently stored using IndexedDB** by default, meaning they survive page refreshes and browser restarts.

The library achieves this using the **Provider Pattern** based on the `IKeyStorageProvider` interface, allowing you to swap out storage mechanisms easily.

| Default Provider | Persistence | Notes | 
 | ----- | ----- | ----- | 
| **IndexedDBProvider** (NEW DEFAULT) | **Persistent** | Uses the asynchronous IndexedDB API for highly secure, robust persistence of LTID keys. | 
| **LocalStorageProvider** (Option) | Persistent | Saves LTID keys to `window.localStorage`. Available as an alternative. | 
| **InMemoryStorageProvider** (Option) | Transient | Keys are lost when the page is closed/refreshed. |

#### Swapping Storage Providers
While the default is the `IndexedDBProvider`, you can inject any custom storage solution that implements `IKeyStorageProvider`.

To switch providers, import `setCurrentStorageProvider` and your chosen provider class *before* calling `useDiffieHellman()`.

```typescript
import { setCurrentStorageProvider, InMemoryStorageProvider, IKeyStorageProvider } from 'securee2e';

// Example: Switch to non-persistent, in-memory storage
setCurrentStorageProvider(new InMemoryStorageProvider());

// Example: If you wrote a custom provider
// class IndexedDBProvider implements IKeyStorageProvider { ... }
// setCurrentStorageProvider(new IndexedDBProvider());

// Now, useDiffieHellman() will use the new provider instance
const { generateLocalAuthPayload } = useDiffieHellman();

```
📖 Low-Level Usage: The Authenticated E2E Workflow (6 Steps)
-------------------------------------------------------

The E2E process now requires key generation for _both_ encryption (ECDH) and authentication (ECDSA) and involves six sequential steps:

1.  **Generate Keys:** Both parties generate their own public/private **ECDH key pair** (for encryption) and **ECDSA key pair** (for authentication).
    
2.  **Sign Public Key:** Each party uses their **ECDSA private key** to sign their **ECDH public key**.
    
3.  **Exchange Payloads:** Parties send a complete payload containing their **ECDH public key**, **ECDSA public key**, and the **Signature** to each other.
    
4.  **Verify Signature:** The recipient uses the remote party's **ECDSA public key** to verify the signature on the **ECDH public key**. If validation fails, the exchange is aborted (MITM protection).
    
5.  **Derive Secret:** If verified, each party combines their **ECDH private key** with the remote party's **ECDH public key** to derive an identical, shared symmetric secret (AES-GCM Key).
    
6.  **Encrypt/Decrypt:** Use the shared secret to encrypt and decrypt messages.
    
### Example: Alice Sends a Secure Message to Bob (Authenticated)

This example demonstrates the full, secure workflow including key signing and verification.

```TypeScript

import { useDiffieHellman, KeyAuthPayload } from 'securee2e';

const {
generateKeyPair, 
generateLongTermIdentityKeys, // Added for consistency 
exportPublicKeyBase64,
exportSigningPublicKeyBase64,
importRemotePublicKeyBase64,
importRemoteSigningPublicKeyBase64,
signPublicKey,
verifySignature,
deriveSharedSecret,
encryptData,
decryptData
} = useDiffieHellman();

// KeyAuthPayload definition (as an interface for clarity)
// NOTE: This interface is already included via 'import { KeyAuthPayload } from 'securee2e''
/*
interface KeyAuthPayload {
    ecdhPublicKey: string; // Alice's ECDH key
    ecdsaPublicKey: string; // Alice's ECDSA key (LTID Public Key)
    signature: string; // Signature over the ECDH key
}
*/

async function runAuthenticatedExchange(bobPayload: KeyAuthPayload) {
  // --- 1. LOAD/GENERATE LTID KEYS & EPHEMERAL ECDH KEYS ---
  // Alice loads her persistent identity (signing) keys
  const aliceLtidKeys = await generateLongTermIdentityKeys(); // Now uses IndexedDBProvider internally
  
  // Alice generates her session (encryption) keys
  const aliceEcdhKeys = await generateKeyPair();

  // --- 2. SIGN PUBLIC KEY & 3. PREPARE PAYLOAD ---
  const ecdhPubKeyBase64 = await exportPublicKeyBase64(aliceEcdhKeys.publicKey);

  // Alice signs her *ephemeral* ECDH public key using her *LTID* private key
  const signature = await signPublicKey(
      aliceLtidKeys.ecdsaPrivateKey, // Use LTID Private Key for signing
      aliceEcdhKeys.publicKey
  );

  const alicePayload: KeyAuthPayload = {
      ecdhPublicKey: ecdhPubKeyBase64,
      ecdsaPublicKey: await exportSigningPublicKeyBase64(aliceLtidKeys.ecdsaPublicKey), // Use LTID Public Key
      signature: signature
  };

  // --- 4. BOB RECEIVES & ALICE VERIFIES BOB'S KEY (SIMULATED) ---
  const bobEcdhKey = await importRemotePublicKeyBase64(bobPayload.ecdhPublicKey);
  // Import the remote party's LTID public key
  const bobEcdsaKey = await importRemoteSigningPublicKeyBase64(bobPayload.ecdsaPublicKey); 

  const isSignatureValid = await verifySignature(
      bobEcdsaKey, // Use Bob's LTID Public Key for verification
      bobEcdhKey,
      bobPayload.signature
  );

  if (!isSignatureValid) {
      throw new Error("MITM ALERT: Remote key signature is invalid.");
  }
  console.log("Key Verified Successfully. Connection is authenticated.");

  // --- 5. DERIVE SHARED SECRET ---
  const aliceSharedKey = await deriveSharedSecret(
      aliceEcdhKeys.privateKey, 
      bobEcdhKey 
  );

  // --- 6. ENCRYPT & DECRYPT (ALICE SENDS) ---
  const plaintext = "This message is secretly authenticated.";
  const encryptedPayload = await encryptData(aliceSharedKey, plaintext);
  const { iv, ciphertext } = encryptedPayload; // Both are URL-safe Base64 strings

  // Simulate Bob decrypting using his identical shared secret
  const decryptedMessage = await decryptData(aliceSharedKey, iv, ciphertext);

  console.log("Decrypted Message:", decryptedMessage); 
}

```

⚠️ Security Notes
-----------------

1.  **Authentication is Crucial:** This library now includes ECDSA signature and verification to prevent **Man-in-the-Middle (MITM) attacks**. Always verify the remote party's key using verifySignature before deriving the shared secret.
    
2.  **Non-Extractable Private Keys:** The generateKeyPair and generateSigningKeys functions set the private keys as non-extractable. This is a security best practice, preventing accidental exposure of the key material through functions like exportKey.
    
3.  **Initialization Vector (IV) is Mandatory:** For AES-GCM encryption, a unique 12-byte IV is generated for **every single message**. This IV is not secret and must be transmitted along with the ciphertext. Reusing the same IV will fatally compromise security, typically as part of the **EncryptedPayload** object. Reusing the same IV will fatally compromise security.