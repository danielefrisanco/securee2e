import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useDiffieHellman } from '../src/composables/useDiffieHellman';

// Mock the Web Crypto API
const mockPrivateKey = {} as CryptoKey;
const mockPublicKey = {} as CryptoKey;
const mockSharedKey = {} as CryptoKey;
const mockCiphertext = new ArrayBuffer(128); // Mock encrypted data
const mockPlaintextArrayBuffer = new TextEncoder().encode('This is a secret message.');
const mockDerivedBits = new ArrayBuffer(32); // 256 bits of raw key material

// Setup detailed mocks for the Crypto API subtle methods
const subtle = {
    generateKey: vi.fn(),
    exportKey: vi.fn(),
    importKey: vi.fn(),
    deriveBits: vi.fn(), // New mock for deriveBits
    encrypt: vi.fn(),
    decrypt: vi.fn(),
};

// Mock getRandomValues for IV generation
const mockIV = new Uint8Array(12).fill(1);
const crypto = {
    subtle,
    getRandomValues: vi.fn().mockReturnValue(mockIV),
};

// Use a custom setup for the global window.crypto object
(global as any).window = {
    crypto: crypto,
};


describe('useDiffieHellman (securee2e)', () => {
    let dh: ReturnType<typeof useDiffieHellman>;
    const plaintext = 'This is a secret message.';
    // Use the Uint8Array buffer directly for ArrayBuffer comparisons
    const ivArrayBuffer = mockIV.buffer; 
    
    // FIX 1: Updated Base64 string to match the actual encoding of the mocked export buffer
    // The buffer new Uint8Array([77, 240, 63, 63, 255, 23, 255, 15, 7, 199]).buffer encodes to 'TfA/P/8X/w8Hxw=='
    const base64PublicKey = 'TfA/P/8X/w8Hxw=='; 

    beforeEach(() => {
        // Clear all mocks before each test
        vi.clearAllMocks();

        // Initialize the composable
        dh = useDiffieHellman();

        // 1. Mock KeyPair Generation
        vi.mocked(subtle.generateKey).mockResolvedValue({
            privateKey: mockPrivateKey,
            publicKey: mockPublicKey,
        } as CryptoKeyPair);

        // 2. Mock Public Key Export (CryptoKey -> ArrayBuffer -> Base64)
        // This is the buffer that produces the base64PublicKey defined above
        vi.mocked(subtle.exportKey).mockResolvedValue(new Uint8Array([77, 240, 63, 63, 255, 23, 255, 15, 7, 199]).buffer);

        // 3. Mock Import Key (for both remote public key AND derived raw bits)
        vi.mocked(subtle.importKey).mockImplementation(async (format, keyData, algo, extractable, usages) => {
            if (format === 'spki') {
                return mockPublicKey as any; // Remote Public Key Import
            }
            if (format === 'raw') {
                return mockSharedKey as any; // Derived Shared Key Import (the new step)
            }
            return Promise.reject(new Error('MOCK: Unexpected importKey format'));
        });

        // 4. Mock Derived Bits (new mock for the first step of derivation)
        vi.mocked(subtle.deriveBits).mockResolvedValue(mockDerivedBits);

        // 5. Mock Encrypt/Decrypt
        vi.mocked(subtle.encrypt).mockResolvedValue(mockCiphertext);
        vi.mocked(subtle.decrypt).mockResolvedValue(mockPlaintextArrayBuffer.buffer);
    });

    // --- Key Pair Generation Tests ---

    it('should generate an ECDH key pair with correct algorithms and usages', async () => {
        const keyPair = await dh.generateKeyPair();

        // Assert
        expect(subtle.generateKey).toHaveBeenCalledWith(
            { name: 'ECDH', namedCurve: 'P-256' },
            false, // Private key MUST NOT be extractable for security
            ['deriveBits']
        );
        expect(keyPair.privateKey).toBe(mockPrivateKey);
        expect(keyPair.publicKey).toBe(mockPublicKey);
    });

    // --- Public Key Export/Import Tests ---

    it('should correctly export the public key to ArrayBuffer (SPKI format)', async () => {
        await dh.exportPublicKey(mockPublicKey);
        
        // Assert
        expect(subtle.exportKey).toHaveBeenCalledWith('spki', mockPublicKey);
    });

    it('should correctly import a remote public key from ArrayBuffer (SPKI format)', async () => {
        const mockKeyBuffer = new ArrayBuffer(100);
        const remoteKey = await dh.importRemotePublicKey(mockKeyBuffer);
        
        // Assert
        expect(subtle.importKey).toHaveBeenCalledWith(
            'spki',
            mockKeyBuffer,
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            []
        );
        expect(remoteKey).toBe(mockPublicKey);
    });

    it('should correctly export public key to Base64 string', async () => {
        // Assert
        const result = await dh.exportPublicKeyBase64(mockPublicKey);
        expect(result).toBe(base64PublicKey);
    });

    it('should correctly import public key from Base64 string', async () => {
        // Assert that importKey is called with the correct parameters (using the mockImplementation)
        const result = await dh.importRemotePublicKeyBase64(base64PublicKey);
        
        expect(subtle.importKey).toHaveBeenCalledTimes(1);
        expect(result).toBe(mockPublicKey);
    });

    // --- Shared Secret Derivation Test (CRITICAL FIX APPLIED HERE) ---

    it('should correctly derive the shared secret using ECDH (two-step)', async () => {
        const sharedKey = await dh.deriveSharedSecret(mockPrivateKey, mockPublicKey);
        
        // 1. Assert deriveBits was called
        expect(subtle.deriveBits).toHaveBeenCalledWith(
            { name: 'ECDH', public: mockPublicKey },
            mockPrivateKey,
            256 // Length in bits
        );

        // 2. Assert importKey was called to turn raw bits into an AES key
        expect(subtle.importKey).toHaveBeenCalledWith(
            'raw',
            mockDerivedBits,
            { name: "AES-GCM", length: 256 },
            true, // extractable
            ['encrypt', 'decrypt']
        );
        
        expect(sharedKey).toBe(mockSharedKey);
    });

    // --- Encryption/Decryption Tests ---

    it('should encrypt data using AES-GCM and return IV/ciphertext', async () => {
        const result = await dh.encryptData(mockSharedKey, plaintext);

        // Assert IV generation
        expect(crypto.getRandomValues).toHaveBeenCalledWith(expect.any(Uint8Array));
        expect(crypto.getRandomValues).toHaveBeenCalledTimes(1);
        expect(vi.mocked(crypto.getRandomValues).mock.calls[0][0].length).toBe(12); // IV generated

        // FIX 3: subtle.encrypt receives the IV as a Uint8Array, not ArrayBuffer
        expect(subtle.encrypt).toHaveBeenCalledWith(
            { name: 'AES-GCM', iv: mockIV }, 
            mockSharedKey,
            mockPlaintextArrayBuffer
        );
        
        // Assert return value structure
        expect(result.iv).toBe(ivArrayBuffer);
        expect(result.ciphertext).toBe(mockCiphertext);
    });

    it('should decrypt data using the shared key and IV', async () => {
        const decryptedText = await dh.decryptData(mockSharedKey, ivArrayBuffer, mockCiphertext);
        
        // Assert
        expect(subtle.decrypt).toHaveBeenCalledWith(
            { name: 'AES-GCM', iv: ivArrayBuffer },
            mockSharedKey,
            mockCiphertext
        );

        // Check if the result matches the mocked decrypted text
        expect(decryptedText).toBe(plaintext);
    });
});
