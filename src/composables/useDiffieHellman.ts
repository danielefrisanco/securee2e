// --- Constants for Web Crypto API ---
// ECDH P-256 is the standard recommended algorithm for modern D-H key exchange
const ECDH_ALGORITHM: EcKeyGenParams = { name: "ECDH", namedCurve: "P-256" };
// AES-GCM 256-bit is used for symmetric encryption of the message data
const AES_GCM_ALGORITHM: AesKeyGenParams = { name: "AES-GCM", length: 256 };

/**
 * Defines the structure and types for the 'securee2e' Diffie-Hellman composable.
 */
interface DiffieHellmanComposable {
    generateKeyPair: () => Promise<CryptoKeyPair>;
    
    // Key Exchange (ArrayBuffer format for internal CryptoKey handling)
    exportPublicKey: (publicKey: CryptoKey) => Promise<ArrayBuffer>;
    importRemotePublicKey: (remoteKeyBuffer: ArrayBuffer) => Promise<CryptoKey>;
    deriveSharedSecret: (privateKey: CryptoKey, remotePublicKey: CryptoKey) => Promise<CryptoKey>;
    
    // Serialization (Base64 format for network transfer/storage)
    exportPublicKeyBase64: (publicKey: CryptoKey) => Promise<string>;
    importRemotePublicKeyBase64: (base64Key: string) => Promise<CryptoKey>;
    
    // Encryption/Decryption
    encryptData: (sharedKey: CryptoKey, plaintext: string) => Promise<{ iv: ArrayBuffer, ciphertext: ArrayBuffer }>;
    decryptData: (sharedKey: CryptoKey, iv: ArrayBuffer, ciphertext: ArrayBuffer) => Promise<string>;
}

export function useDiffieHellman(): DiffieHellmanComposable {

    // --- Utility Functions ---

    // Converts string to ArrayBuffer (required for crypto operations)
    function str2ab(str: string): ArrayBuffer {
        return new TextEncoder().encode(str);
    }
    // Converts ArrayBuffer to string (required after decryption)
    function ab2str(buf: ArrayBuffer): string {
        return new TextDecoder().decode(buf);
    }
    // Converts ArrayBuffer to a Base64 string
    function ab2base64(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        const binary = bytes.reduce((acc, byte) => acc + String.fromCharCode(byte), '');
        return btoa(binary);
    }
    // Converts a Base64 string back to ArrayBuffer
    function base642ab(base64: string): ArrayBuffer {
        const binary = atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // --- Core Key Exchange Functions (CryptoKey <-> ArrayBuffer) ---

    /**
     * Generates an ECDH key pair. Private key is explicitly non-extractable for security.
     */
    async function generateKeyPair(): Promise<CryptoKeyPair> {
        return window.crypto.subtle.generateKey(
            ECDH_ALGORITHM,
            false, // IMPORTANT: Private key is non-extractable for better security
            ["deriveBits"] // usage for D-H key generation (applies to private key)
        ) as Promise<CryptoKeyPair>;
    }

    /**
     * Exports the public key into an SPKI ArrayBuffer format.
     */
    async function exportPublicKey(publicKey: CryptoKey): Promise<ArrayBuffer> {
        return window.crypto.subtle.exportKey("spki", publicKey);
    }

    /**
     * Imports a public key from an SPKI ArrayBuffer format.
     */
    async function importRemotePublicKey(remoteKeyBuffer: ArrayBuffer): Promise<CryptoKey> {
        try {
            return await window.crypto.subtle.importKey(
                "spki",
                remoteKeyBuffer,
                ECDH_ALGORITHM,
                true, // Public key is extractable so we can export/share it
                [] // key usages (only needed for derivation, not for encryption/decryption)
            );
        } catch (e) {
             console.error("Critical Import Error:", e);
             throw new Error("SECUREE2E: Public key import failed.");
        }
    }

    /**
     * Derives the shared secret key using the local private key and the remote public key.
     * FIX: Uses deriveBits + importKey for higher browser compatibility and reliability.
     */
    async function deriveSharedSecret(privateKey: CryptoKey, remotePublicKey: CryptoKey): Promise<CryptoKey> {
        try {
            // 1. Derive the raw shared secret bits (256 bits = 32 bytes)
            const derivedBits = await window.crypto.subtle.deriveBits(
                { name: "ECDH", public: remotePublicKey }, // Algorithm parameters for D-H
                privateKey, // Local private key (must have 'deriveBits' usage)
                256 // Length in bits
            );

            // 2. Import the raw bits as an AES-GCM 256-bit key
            return await window.crypto.subtle.importKey(
                "raw", // The format is 'raw' when importing key material bytes
                derivedBits,
                AES_GCM_ALGORITHM, // The algorithm the resulting key will be used for
                true, // extractable (for testing/storage/debugging)
                ["encrypt", "decrypt"] // Key usages for the final derived key
            );
        } catch (e) {
            // Log the raw browser error to the console for detailed analysis
            console.error("Critical Derivation Error (Raw):", e);
            // Throw a custom error that is friendlier to the Vue app
            throw new Error("SECUREE2E: Shared secret derivation failed.");
        }
    }

    // --- Serialization Functions (CryptoKey <-> Base64 String) ---

    /**
     * Exports a public key to a Base64 string for transmission.
     */
    async function exportPublicKeyBase64(publicKey: CryptoKey): Promise<string> {
        const keyBuffer = await exportPublicKey(publicKey);
        return ab2base64(keyBuffer);
    }

    /**
     * Imports a public key from a Base64 string received from a remote user.
     */
    async function importRemotePublicKeyBase64(base64Key: string): Promise<CryptoKey> {
        const keyBuffer = base642ab(base64Key);
        return importRemotePublicKey(keyBuffer);
    }
    
    // --- Symmetric Encryption Functions ---

    /**
     * Encrypts plaintext data using the derived shared key (AES-GCM).
     */
    async function encryptData(sharedKey: CryptoKey, plaintext: string): Promise<{ iv: ArrayBuffer, ciphertext: ArrayBuffer }> {
        // Generate a fresh 12-byte IV for every encryption
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedPlaintext = str2ab(plaintext);

        const encryptionParams: AesGcmParams = { name: "AES-GCM", iv };

        const ciphertext = await window.crypto.subtle.encrypt(
            encryptionParams,
            sharedKey,
            encodedPlaintext
        );

        return { 
            iv: iv.buffer as ArrayBuffer, // Return the IV as ArrayBuffer
            ciphertext: ciphertext 
        };
    }

    /**
     * Decrypts ciphertext data using the derived shared key (AES-GCM).
     */
    async function decryptData(sharedKey: CryptoKey, iv: ArrayBuffer, ciphertext: ArrayBuffer): Promise<string> {
        const encryptionParams: AesGcmParams = { name: "AES-GCM", iv };

        const decryptedData = await window.crypto.subtle.decrypt(
            encryptionParams,
            sharedKey,
            ciphertext
        );
        
        return ab2str(decryptedData);
    }


    return {
        generateKeyPair,
        exportPublicKey,
        importRemotePublicKey,
        deriveSharedSecret,
        exportPublicKeyBase64,
        importRemotePublicKeyBase64,
        encryptData,
        decryptData,
    };
}
