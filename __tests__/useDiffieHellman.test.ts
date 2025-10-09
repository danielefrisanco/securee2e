import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import { useDiffieHellman } from '../src/composables/useDiffieHellman';

// --- MOCK CRYPTO API AND GLOBAL UTILITIES ---
// This is necessary because JSDOM (the testing environment) does not natively implement
// the entire Web Crypto API or standard browser utils like btoa/atob.

// Placeholder for key material used in mocks
const MOCK_KEY_BUFFER = new Uint8Array(256).fill(0xAA).buffer;
const MOCK_SIGNATURE_BUFFER = new Uint8Array(64).fill(0xBB).buffer;
const MOCK_CIPHERTEXT_BUFFER = new Uint8Array(100).fill(0xCC).buffer;
const MOCK_IV_BUFFER = new Uint8Array(12).fill(0xDD).buffer;
const MOCK_PLAINTEXT_BUFFER = new TextEncoder().encode('Hello, world!').buffer;

// Mock the core CryptoKey object properties
const mockCryptoKey = (type: 'public' | 'private' | 'secret', algorithm: string): CryptoKey => ({
    type: type,
    extractable: type === 'public' || type === 'secret',
    algorithm: { name: algorithm, namedCurve: 'P-256' } as any,
    usages: type === 'public' ? ['verify'] : ['sign', 'deriveKey', 'encrypt', 'decrypt'],
});

const mockSubtle = {
    generateKey: vi.fn((algorithm: any, extractable: boolean, usages: string[]) => {
        const type = usages.includes('sign') ? 'private' : 'private';
        return Promise.resolve({
            publicKey: mockCryptoKey('public', algorithm.name),
            privateKey: mockCryptoKey(type as any, algorithm.name),
        });
    }),
    exportKey: vi.fn(() => Promise.resolve(MOCK_KEY_BUFFER)),
    importKey: vi.fn((format: string, keyData: ArrayBuffer, algorithm: any, extractable: boolean, usages: string[]) => {
        const type = usages.includes('verify') ? 'public' : 'secret';
        return Promise.resolve(mockCryptoKey(type as any, algorithm.name));
    }),
    deriveBits: vi.fn(() => Promise.resolve(MOCK_KEY_BUFFER)),
    encrypt: vi.fn(() => Promise.resolve(MOCK_CIPHERTEXT_BUFFER)),
    decrypt: vi.fn(() => Promise.resolve(MOCK_PLAINTEXT_BUFFER)),
    sign: vi.fn(() => Promise.resolve(MOCK_SIGNATURE_BUFFER)),
    verify: vi.fn(() => Promise.resolve(true)), // Default success for verification
};

// Mock the value we intend to set on global.crypto
const mockCrypto = {
    subtle: mockSubtle,
    getRandomValues: vi.fn((array: Uint8Array) => {
        // Mocking IV generation, important for encryptData
        array.set(new Uint8Array(MOCK_IV_BUFFER));
        return array;
    }),
} as any;

// FIX: Use Object.defineProperty to override the read-only 'crypto' getter in JSDOM
Object.defineProperty(global, 'crypto', {
    value: mockCrypto,
    writable: true,
    configurable: true,
});

// Mock Base64 functions which are often missing or faulty in JSDOM
global.btoa = vi.fn((str) => Buffer.from(str, 'binary').toString('base64'));
global.atob = vi.fn((str) => Buffer.from(str, 'base64').toString('binary'));

// Helper to convert array buffer to string for comparison in Base64URL
const arrayBufferToHexString = (buffer: ArrayBuffer): string => {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}


describe('useDiffieHellman (securee2e)', () => {
    let dh: ReturnType<typeof useDiffieHellman>;

    beforeEach(() => {
        dh = useDiffieHellman();
        vi.clearAllMocks();
    });

    // --- ECDH KEY AGREEMENT TESTS ---

    it('should generate an ECDH key pair with correct algorithms and usages', async () => {
        await dh.generateKeyPair();
        
        expect(mockSubtle.generateKey).toHaveBeenCalledWith(
            { name: 'ECDH', namedCurve: 'P-256' },
            false, // Private key MUST NOT be extractable for security
            ['deriveKey', 'deriveBits']
        );
    });

    it('should correctly export the public key to Base64URL string', async () => {
        const keyPair = await dh.generateKeyPair();
        const base64UrlKey = await dh.exportPublicKeyBase64(keyPair.publicKey);

        expect(mockSubtle.exportKey).toHaveBeenCalledWith('spki', keyPair.publicKey);
        // Check that the Base64URL conversion happened (by checking length/type)
        expect(typeof base64UrlKey).toBe('string');
        expect(base64UrlKey.length).toBeGreaterThan(0);
    });

    it('should correctly import a remote public key from Base64URL string', async () => {
        const mockBase64 = 'MOCK_BASE64_PUBLIC_KEY';
        await dh.importRemotePublicKeyBase64(mockBase64);
        
        // Assert import key was called with correct parameters for ECDH public key
        expect(mockSubtle.importKey).toHaveBeenCalledWith(
            'spki',
            expect.any(ArrayBuffer),
            { name: 'ECDH', namedCurve: 'P-256' },
            true, // Public keys are generally extractable
            [] // Public keys are not used for derivation/signing/verification directly here
        );
    });

    it('should correctly derive the shared secret using ECDH (two-step)', async () => {
        const aliceKeyPair = await dh.generateKeyPair();
        const bobPublicKey = mockCryptoKey('public', 'ECDH');
        
        await dh.deriveSharedSecret(aliceKeyPair.privateKey, bobPublicKey);

        // Step 1: Derive Bits
        expect(mockSubtle.deriveBits).toHaveBeenCalledWith(
            { name: 'ECDH', public: bobPublicKey },
            aliceKeyPair.privateKey,
            256
        );

        // Step 2: Import Key
        expect(mockSubtle.importKey).toHaveBeenCalledWith(
            'raw',
            MOCK_KEY_BUFFER, // The bits returned from deriveBits
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    });

    // --- AES ENCRYPTION/DECRYPTION TESTS ---

    it('should encrypt data using AES-GCM and return IV/ciphertext in Base64URL format', async () => {
        const sharedKey = mockCryptoKey('secret', 'AES-GCM');
        const plaintext = 'Secret Data';
        
        const payload = await dh.encryptData(sharedKey, plaintext);

        expect(crypto.getRandomValues).toHaveBeenCalled();
        expect(mockSubtle.encrypt).toHaveBeenCalled();
        expect(typeof payload.iv).toBe('string');
        expect(typeof payload.ciphertext).toBe('string');
        expect(payload.iv.length).toBeGreaterThan(0);
    });

    it('should decrypt data using the shared key and IV', async () => {
        const sharedKey = mockCryptoKey('secret', 'AES-GCM');
        const mockIVBase64 = 'MOCK-IV';
        const mockCiphertextBase64 = 'MOCK-CIPHERTEXT';
        
        const decryptedText = await dh.decryptData(sharedKey, mockIVBase64, mockCiphertextBase64);

        expect(mockSubtle.decrypt).toHaveBeenCalledWith(
            { name: 'AES-GCM', iv: expect.any(ArrayBuffer) },
            sharedKey,
            expect.any(ArrayBuffer) // Ciphertext buffer
        );
        expect(decryptedText).toBe(new TextDecoder().decode(MOCK_PLAINTEXT_BUFFER));
    });

    // ==========================================================
    // === NEW ECDSA SIGNATURE TESTS (v0.3.0 Feature) =============
    // ==========================================================

    it('should generate an ECDSA signing key pair with correct algorithms and usages', async () => {
        await dh.generateSigningKeys();
        
        expect(mockSubtle.generateKey).toHaveBeenCalledWith(
            { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' },
            false, // Private key is non-extractable
            ['sign']
        );
    });

    it('should sign the ECDH public key using the ECDSA private key and return Base64URL signature', async () => {
        const ecdsaKeyPair = await dh.generateSigningKeys();
        const ecdhPublicKey = mockCryptoKey('public', 'ECDH');

        const signature = await dh.signPublicKey(ecdsaKeyPair.privateKey, ecdhPublicKey);

        // 1. Assert ECDH public key was exported to get the data to sign
        expect(mockSubtle.exportKey).toHaveBeenCalledWith('spki', ecdhPublicKey);
        
        // 2. Assert signature creation was called
        expect(mockSubtle.sign).toHaveBeenCalledWith(
            { name: 'ECDSA', hash: 'SHA-256' },
            ecdsaKeyPair.privateKey,
            MOCK_KEY_BUFFER // The data buffer from the exportKey mock
        );
        expect(typeof signature).toBe('string');
        expect(signature.length).toBeGreaterThan(0);
    });

    it('should verify a signature against a public key using the remote ECDSA public key', async () => {
        const remoteEcdsaPublicKey = mockCryptoKey('public', 'ECDSA');
        const remoteEcdhPublicKey = mockCryptoKey('public', 'ECDH');
        const signatureBase64 = 'MOCK-SIGNATURE-BASE64';

        const result = await dh.verifySignature(
            remoteEcdsaPublicKey, 
            remoteEcdhPublicKey, 
            signatureBase64
        );

        // 1. Assert ECDH public key was exported to get the data to verify against
        expect(mockSubtle.exportKey).toHaveBeenCalledWith('spki', remoteEcdhPublicKey);

        // 2. Assert verification was called with the correct inputs
        expect(mockSubtle.verify).toHaveBeenCalledWith(
            { name: 'ECDSA', hash: 'SHA-256' },
            remoteEcdsaPublicKey,
            expect.any(ArrayBuffer), // The signature buffer
            MOCK_KEY_BUFFER // The data buffer from the exportKey mock
        );
        expect(result).toBe(true);
    });

});
