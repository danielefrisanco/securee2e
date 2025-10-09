## securee2e: Vue Composable for End-to-End Encryption (v0.3.0)

`securee2e` is a straightforward Vue 3 composable built on the native **Web Cryptography API** to facilitate secure **Diffie-Hellman Key Exchange (ECDH)** and **AES-GCM** symmetric encryption, **now with ECDSA signature for public key authentication.**

✨ Features
----------

*   **ECDH P-256 Key Agreement:** Uses the standard Elliptic Curve Diffie-Hellman with the P-256 curve for robust key agreement.
    
*   **ECDSA P-256 Key Authentication (New!):** Uses Elliptic Curve Digital Signature Algorithm with the P-256 curve to sign and verify public keys, **preventing Man-in-the-Middle (MITM) attacks.**
    
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

📖 Usage:The Authenticated E2E Workflow
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

import { useDiffieHellman } from 'securee2e';

const {
generateKeyPair, 
generateSigningKeys, 
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
interface KeyAuthPayload {
    ecdhPublicKey: string; // Alice's ECDH key
    ecdsaPublicKey: string; // Alice's ECDSA key
    signature: string; // Signature over the ECDH key
}

async function runAuthenticatedExchange(bobPayload: KeyAuthPayload) {
  // --- 1. ALICE'S KEY GENERATION ---
  const aliceEcdhKeys = await generateKeyPair();
  const aliceEcdsaKeys = await generateSigningKeys();

  // --- 2. SIGN PUBLIC KEY & 3. PREPARE PAYLOAD ---
  const ecdhPubKeyBase64 = await exportPublicKeyBase64(aliceEcdhKeys.publicKey);

  // Alice signs her ECDH public key using her ECDSA private key
  const signature = await signPublicKey(
      aliceEcdsaKeys.privateKey, 
      aliceEcdhKeys.publicKey
  );

  const alicePayload: KeyAuthPayload = {
      ecdhPublicKey: ecdhPubKeyBase64,
      ecdsaPublicKey: await exportSigningPublicKeyBase64(aliceEcdsaKeys.publicKey),
      signature: signature
  };

  // --- 4. BOB RECEIVES & ALICE VERIFIES BOB'S KEY (SIMULATED) ---
  const bobEcdhKey = await importRemotePublicKeyBase64(bobPayload.ecdhPublicKey);
  const bobEcdsaKey = await importRemoteSigningPublicKeyBase64(bobPayload.ecdsaPublicKey);

  const isSignatureValid = await verifySignature(
      bobEcdsaKey, 
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