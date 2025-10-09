import { computed } from 'vue';

const ECH_ALGO_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
const SIGN_ALGO_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_HASH_ALGO = 'SHA-256';
const AES_ALGO_PARAMS = { name: 'AES-GCM', length: 256 };
const IV_LENGTH = 12; // 12 bytes / 96 bits is standard for AES-GCM

// ===============================================
// === GENERAL UTILITIES (ArrayBuffer <-> Base64) ===
// ===============================================

/**
 * Converts an ArrayBuffer to a Base64URL string (URL-safe version of Base64).
 * This is used for exchanging public keys and signatures over the network.
 */
const arrayBufferToBase64Url = (buffer: ArrayBuffer): string => {
    // Standard Base64
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    // Convert to Base64URL
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/**
 * Converts a Base64URL string back to an ArrayBuffer.
 */
const base64UrlToArrayBuffer = (base64: string): ArrayBuffer => {
    // Convert Base64URL back to standard Base64
    let base64Standard = base64.replace(/-/g, '+').replace(/_/g, '/');
    // Pad with '=' to make it valid Base64 length
    while (base64Standard.length % 4) {
        base64Standard += '=';
    }
    const binaryString = atob(base64Standard);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
};

// =================================================================
// === CORE DIFFIE-HELLMAN & AES-GCM LOGIC (Key Agreement/Encrypt) ===
// =================================================================

export const useDiffieHellman = () => {

    // --- ECDH KEY MANAGEMENT ---

    /**
     * Generates a new ECDH P-256 public/private key pair.
     * The private key is set as non-extractable for security.
     */
    const generateKeyPair = async (): Promise<CryptoKeyPair> => {
        return crypto.subtle.generateKey(
            ECH_ALGO_PARAMS,
            false, // Non-extractable private key
            ['deriveKey', 'deriveBits']
        );
    };

    /**
     * Imports a remote party's public key from a Base64URL string.
     */
    const importRemotePublicKeyBase64 = async (publicKeyBase64: string): Promise<CryptoKey> => {
        const keyBuffer = base64UrlToArrayBuffer(publicKeyBase64);
        return crypto.subtle.importKey(
            'spki', // SubjectPublicKeyInfo format for public keys
            keyBuffer,
            ECH_ALGO_PARAMS,
            true, // Public keys are extractable
            [] // Cannot be used for derivation
        );
    };

    /**
     * Exports a local public key to a Base64URL string for network transmission.
     */
    const exportPublicKeyBase64 = async (publicKey: CryptoKey): Promise<string> => {
        const buffer = await crypto.subtle.exportKey('spki', publicKey);
        return arrayBufferToBase64Url(buffer);
    };

    /**
     * Derives a shared secret key (AES-GCM) using the local private key and remote public key.
     */
    const deriveSharedSecret = async (
        localPrivateKey: CryptoKey,
        remotePublicKey: CryptoKey
    ): Promise<CryptoKey> => {
        // Step 1: Derive shared key bits
        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: remotePublicKey },
            localPrivateKey,
            256 // 256 bits for AES-256
        );

        // Step 2: Import the bits as an AES-GCM key
        return crypto.subtle.importKey(
            'raw',
            derivedBits,
            AES_ALGO_PARAMS,
            true, // Shared key should be usable but not necessarily exportable
            ['encrypt', 'decrypt']
        );
    };

    // --- AES ENCRYPTION/DECRYPTION ---

    /**
     * Encrypts plaintext data using the shared secret key.
     * Automatically generates a unique IV for each encryption.
     */
    const encryptData = async (sharedKey: CryptoKey, plaintext: string) => {
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH)); // Unique 12-byte IV
        const data = encoder.encode(plaintext);

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            sharedKey,
            data
        );

        return {
            iv: arrayBufferToBase64Url(iv.buffer),
            ciphertext: arrayBufferToBase64Url(ciphertext),
        };
    };

    /**
     * Decrypts ciphertext using the shared secret key and the transmitted IV.
     */
    const decryptData = async (
        sharedKey: CryptoKey,
        ivBase64: string,
        ciphertextBase64: string
    ): Promise<string> => {
        const iv = base64UrlToArrayBuffer(ivBase64);
        const ciphertext = base64UrlToArrayBuffer(ciphertextBase64);

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            sharedKey,
            ciphertext
        );

        const decoder = new TextEncoder();
        return new TextDecoder().decode(decryptedBuffer);
    };

    // ==========================================================
    // === NEW ECDSA LOGIC (Key Authentication/MITM Protection) ===
    // ==========================================================

    /**
     * Generates a new ECDSA P-256 public/private key pair for digital signatures.
     */
    const generateSigningKeys = async (): Promise<CryptoKeyPair> => {
        return crypto.subtle.generateKey(
            { ...SIGN_ALGO_PARAMS, hash: SIGN_HASH_ALGO },
            false, // Private key is non-extractable by default
            ['sign']
        );
    };

    /**
     * Exports a signing public key to a Base64URL string for network transmission.
     */
    const exportSigningPublicKeyBase64 = async (publicKey: CryptoKey): Promise<string> => {
        const buffer = await crypto.subtle.exportKey('spki', publicKey);
        return arrayBufferToBase64Url(buffer);
    };

    /**
     * Imports a remote party's signing public key from a Base64URL string.
     */
    const importRemoteSigningPublicKeyBase64 = async (publicKeyBase64: string): Promise<CryptoKey> => {
        const keyBuffer = base64UrlToArrayBuffer(publicKeyBase64);
        return crypto.subtle.importKey(
            'spki',
            keyBuffer,
            { ...SIGN_ALGO_PARAMS, hash: SIGN_HASH_ALGO },
            true, // Public keys are extractable
            ['verify']
        );
    };


    /**
     * Creates a digital signature over the local ECDH public key using the ECDSA private key.
     * The data being signed is the raw buffer of the ECDH public key (SPKI format).
     * This proves key ownership.
     */
    const signPublicKey = async (
        ecdsaPrivateKey: CryptoKey,
        ecdhPublicKey: CryptoKey
    ): Promise<string> => {
        // The data we sign is the raw public key buffer (SPKI format)
        const dataToSign = await crypto.subtle.exportKey('spki', ecdhPublicKey);

        const signatureBuffer = await crypto.subtle.sign(
            { name: 'ECDSA', hash: SIGN_HASH_ALGO },
            ecdsaPrivateKey,
            dataToSign
        );

        return arrayBufferToBase64Url(signatureBuffer);
    };

    /**
     * Verifies a digital signature against a remote ECDH public key using the remote ECDSA public key.
     * This confirms the received ECDH key is authentic.
     */
    const verifySignature = async (
        ecdsaPublicKey: CryptoKey,
        ecdhPublicKey: CryptoKey,
        signatureBase64: string
    ): Promise<boolean> => {
        const dataToVerify = await crypto.subtle.exportKey('spki', ecdhPublicKey);
        const signatureBuffer = base64UrlToArrayBuffer(signatureBase64);

        return crypto.subtle.verify(
            { name: 'ECDSA', hash: SIGN_HASH_ALGO },
            ecdsaPublicKey,
            signatureBuffer,
            dataToVerify
        );
    };

    // ===============================================
    // === COMPOSABLE RETURN ===
    // ===============================================

    return {
        // ECDH Key Agreement & Encryption
        generateKeyPair,
        exportPublicKeyBase64,
        importRemotePublicKeyBase64,
        deriveSharedSecret,
        encryptData,
        decryptData,
        
        // ECDSA Key Authentication (MITM Protection)
        generateSigningKeys,
        exportSigningPublicKeyBase64,
        importRemoteSigningPublicKeyBase64,
        signPublicKey,
        verifySignature,
    };
};