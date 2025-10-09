import type { KeyAuthPayload, EncryptedPayload } from '../types/keyExchange';

// --- Utility Functions ---

/**
 * Converts ArrayBuffer to Base64 string.
 * @param buffer - The ArrayBuffer to encode.
 */
const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
};

/**
 * Converts Base64 string to ArrayBuffer.
 * @param base64 - The Base64 string to decode.
 */
const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
};

// --- Low-Level Crypto Functions ---

/**
 * Generates an ECDH P-256 key pair.
 */
const generateKeyPair = async (): Promise<CryptoKeyPair> => {
    return crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        false, // Private key is non-extractable (security best practice)
        ["deriveKey", "deriveBits"]
    );
};

/**
 * Generates an ECDSA P-256 key pair for signing and verification.
 */
const generateSigningKeys = async (): Promise<CryptoKeyPair> => {
    return crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        true, // Public key must be extractable for transport; Private key can be non-extractable
        ["sign", "verify"]
    );
};

/**
 * Exports an ECDH public key to a Base64 string (SPKI format).
 * @param publicKey - The ECDH public key (CryptoKey).
 */
const exportPublicKeyBase64 = async (publicKey: CryptoKey): Promise<string> => {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    return arrayBufferToBase64(exported);
};

/**
 * Exports an ECDSA public key to a Base64 string (SPKI format).
 * @param publicKey - The ECDSA public key (CryptoKey).
 */
const exportSigningPublicKeyBase64 = async (publicKey: CryptoKey): Promise<string> => {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    return arrayBufferToBase64(exported);
};

/**
 * Imports a remote ECDH public key from a Base64 string (SPKI format).
 * @param base64Key - The Base64 encoded ECDH public key string.
 */
const importRemotePublicKeyBase64 = async (base64Key: string): Promise<CryptoKey> => {
    const keyBuffer = base64ToArrayBuffer(base64Key);
    return crypto.subtle.importKey(
        "spki",
        keyBuffer,
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        true, // Key must be extractable for the remote party to use it later
        []
    );
};

/**
 * Imports a remote ECDSA public key from a Base64 string (SPKI format).
 * @param base64Key - The Base64 encoded ECDSA public key string.
 */
const importRemoteSigningPublicKeyBase64 = async (base64Key: string): Promise<CryptoKey> => {
    const keyBuffer = base64ToArrayBuffer(base64Key);
    return crypto.subtle.importKey(
        "spki",
        keyBuffer,
        {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        true,
        ["verify"]
    );
};

/**
 * Derives the shared AES-256-GCM secret key using ECDH.
 * @param localPrivateKey - The local ECDH private key.
 * @param remotePublicKey - The remote ECDH public key (CryptoKey object).
 */
const deriveSharedSecret = async (
    localPrivateKey: CryptoKey,
    remotePublicKey: CryptoKey
): Promise<CryptoKey> => {
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            namedCurve: "P-256",
            public: remotePublicKey, // Requires CryptoKey object
        },
        localPrivateKey,
        256 // 256 bits for AES-256
    );

    return crypto.subtle.importKey(
        "raw",
        derivedBits,
        { name: "AES-GCM", length: 256 },
        true, // Shared key is extractable for storage, though generally not needed
        ["encrypt", "decrypt"]
    );
};

/**
 * Signs a target public key using the local ECDSA private key.
 * @param privateKey - The local ECDSA private key.
 * @param publicKeyToSign - The ECDH public key (CryptoKey) being signed.
 */
const signPublicKey = async (
    privateKey: CryptoKey,
    publicKeyToSign: CryptoKey
): Promise<string> => {
    // Export the ECDH public key to sign its raw data
    const keyData = await crypto.subtle.exportKey("spki", publicKeyToSign);
    
    const signatureBuffer = await crypto.subtle.sign(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        privateKey,
        keyData
    );

    return arrayBufferToBase64(signatureBuffer);
};

/**
 * Verifies the signature of a remote ECDH public key using the remote ECDSA public key.
 * @param remoteSigningKey - The remote ECDSA public key (CryptoKey).
 * @param remoteEcdhKey - The remote ECDH public key (CryptoKey) that was signed.
 * @param signatureBase64 - The Base64 encoded signature.
 */
const verifySignature = async (
    remoteSigningKey: CryptoKey,
    remoteEcdhKey: CryptoKey,
    signatureBase64: string
): Promise<boolean> => {
    const keyData = await crypto.subtle.exportKey("spki", remoteEcdhKey);
    const signatureBuffer = base64ToArrayBuffer(signatureBase64);

    return crypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        remoteSigningKey,
        signatureBuffer,
        keyData
    );
};

/**
 * Encrypts plaintext data using the shared secret key (AES-256 GCM).
 * @param sharedSecret - The shared AES-GCM key.
 * @param plaintext - The string to encrypt.
 */
const encryptData = async (sharedSecret: CryptoKey, plaintext: string): Promise<EncryptedPayload> => {
    // Generate a new unique 12-byte IV for every message (CRITICAL)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedText = new TextEncoder().encode(plaintext);

    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        sharedSecret,
        encodedText
    );

    return {
        iv: arrayBufferToBase64(iv.buffer),
        ciphertext: arrayBufferToBase64(ciphertextBuffer),
    };
};

/**
 * Decrypts ciphertext data using the shared secret key (AES-256 GCM).
 * @param sharedSecret - The shared AES-GCM key.
 * @param ivBase64 - The Base64 encoded Initialization Vector.
 * @param ciphertextBase64 - The Base64 encoded ciphertext.
 */
const decryptData = async (
    sharedSecret: CryptoKey,
    ivBase64: string,
    ciphertextBase64: string
): Promise<string> => {
    const iv = base64ToArrayBuffer(ivBase64);
    const ciphertext = base64ToArrayBuffer(ciphertextBase64);

    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        sharedSecret,
        ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
};


// --- High-Level API Functions (v0.3.1) ---

/**
 * High-level function to generate ECDH and ECDSA keys, sign the ECDH public key, and package the payload.
 * Returns the payload and the private keys needed for future derivation/signing.
 */
const generateLocalAuthPayload = async (): Promise<{ payload: KeyAuthPayload, keys: [CryptoKey, CryptoKey] }> => {
    // 1. Generate keys
    const ecdhKeys = await generateKeyPair();
    const ecdsaKeys = await generateSigningKeys();

    // 2. Export public keys
    const ecdhPublicKey = await exportPublicKeyBase64(ecdhKeys.publicKey);
    const ecdsaPublicKey = await exportSigningPublicKeyBase64(ecdsaKeys.publicKey);

    // 3. Sign the ECDH public key
    const signature = await signPublicKey(ecdsaKeys.privateKey, ecdhKeys.publicKey);

    // 4. Return payload and private keys
    return {
        payload: { ecdhPublicKey, ecdsaPublicKey, signature },
        // [0] ECDH Private Key (for derivation), [1] ECDSA Private Key (for future signing if needed)
        keys: [ecdhKeys.privateKey, ecdsaKeys.privateKey]
    };
};


/**
 * High-level function to handle a remote payload: import keys, verify signature, and derive shared secret.
 */
const deriveSecretFromRemotePayload = async (
    localPrivateKey: CryptoKey, 
    payload: KeyAuthPayload
): Promise<CryptoKey> => {
    // 1. Import Remote ECDH Public Key from Base64 string into a CryptoKey object
    const importedRemoteEcdhKey = await importRemotePublicKeyBase64(payload.ecdhPublicKey);
    const importedRemoteEcdsaKey = await importRemoteSigningPublicKeyBase64(payload.ecdsaPublicKey);

    // 2. Verify the signature (MITM check)
    const isSignatureValid = await verifySignature(
        importedRemoteEcdsaKey,
        importedRemoteEcdhKey,
        payload.signature
    );

    if (!isSignatureValid) {
        throw new Error('Remote key signature is invalid.');
    }

    // 3. Derive shared secret, passing the correctly imported CryptoKey object
    const sharedSecret = await deriveSharedSecret(
        localPrivateKey,
        importedRemoteEcdhKey // Correctly passed as a CryptoKey
    );

    return sharedSecret;
};

/**
 * High-level encryption wrapper.
 */
const encryptMessage = (sharedSecret: CryptoKey, plaintext: string): Promise<EncryptedPayload> => {
    return encryptData(sharedSecret, plaintext);
};

/**
 * High-Level decryption wrapper.
 */
const decryptMessage = (sharedSecret: CryptoKey, payload: EncryptedPayload): Promise<string> => {
    return decryptData(sharedSecret, payload.iv, payload.ciphertext);
};


// --- Composable Export ---

export const useDiffieHellman = () => {
    return {
        // Low-Level Exports
        generateKeyPair,
        generateSigningKeys,
        exportPublicKeyBase64,
        exportSigningPublicKeyBase64,
        importRemotePublicKeyBase64,
        importRemoteSigningPublicKeyBase64,
        deriveSharedSecret,
        signPublicKey,
        verifySignature,
        encryptData,
        decryptData,

        // High-Level Exports (v0.3.1 API)
        generateLocalAuthPayload,
        deriveSecretFromRemotePayload,
        encryptMessage,
        decryptMessage,
    };
};
