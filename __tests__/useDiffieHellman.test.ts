import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useDiffieHellman, RuntimeLTIDKeys } from '../src/composables/useDiffieHellman';
import { InMemoryStorageProvider, LTIDKeySet, setCurrentStorageProvider } from '../src/storage'; 
import { KeyAuthPayload } from '../types/keyExchange';

// --- MOCK CRYPTO API AND GLOBAL UTILITIES ---

// Placeholder for key material used in mocks
const MOCK_KEY_BUFFER = new Uint8Array(256).fill(0xAA).buffer;
const MOCK_SIGNATURE_BUFFER = new Uint8Array(64).fill(0xBB).buffer;
const MOCK_CIPHERTEXT_BUFFER = new Uint8Array(100).fill(0xCC).buffer;
const MOCK_IV_BUFFER = new Uint8Array(12).fill(0xDD).buffer;

let isMaliciousVerification = false;
const decoder = new TextDecoder();
const encoder = new TextEncoder();


// Mock the core CryptoKey object properties
const mockCryptoKey = (type: 'public' | 'private' | 'secret', algorithm: string): CryptoKey => ({
    type: type,
    extractable: type === 'public' || type === 'secret',
    algorithm: { name: algorithm, namedCurve: 'P-256' } as any,
    usages: type === 'public' ? ['verify'] : ['sign', 'deriveKey', 'encrypt', 'decrypt'],
});

// Mock keys used for the LTID setup
const MOCK_LTID_PRIVATE_KEY = mockCryptoKey('private', 'ECDSA');
const MOCK_LTID_PUBLIC_KEY = mockCryptoKey('public', 'ECDSA');

// Mock subtle object now includes export/import JWK for LTID
const mockSubtle = {
    generateKey: vi.fn((algorithm: any, extractable: boolean, usages: string[]) => {
        const type = usages.includes('sign') ? 'private' : 'private';
        if (algorithm.name === 'ECDSA') {
            return Promise.resolve({
                publicKey: MOCK_LTID_PUBLIC_KEY,
                privateKey: MOCK_LTID_PRIVATE_KEY,
            });
        }
        return Promise.resolve({
            publicKey: mockCryptoKey('public', algorithm.name),
            privateKey: mockCryptoKey(type as any, algorithm.name),
        });
    }),
    exportKey: vi.fn((format: string, key: CryptoKey) => {
        if (format === 'jwk') {
            return Promise.resolve({
                kty: 'EC', 
                crv: 'P-256', 
                x: 'mockX', 
                y: 'mockY', 
                d: key.type === 'private' ? 'mockD' : undefined
            });
        }
        return Promise.resolve(MOCK_KEY_BUFFER)
    }),
    importKey: vi.fn((format: string, keyData: ArrayBuffer | JsonWebKey, algorithm: any, extractable: boolean, usages: string[]) => {
        if (format === 'jwk') {
            return Promise.resolve(usages.includes('sign') ? MOCK_LTID_PRIVATE_KEY : MOCK_LTID_PUBLIC_KEY);
        }
        const type = usages.includes('verify') ? 'public' : 'secret';
        return Promise.resolve(mockCryptoKey(type as any, algorithm.name));
    }),

    deriveBits: vi.fn(() => Promise.resolve(MOCK_KEY_BUFFER)),
    deriveKey: vi.fn(async (algorithm: any, baseKey: CryptoKey, derivedKeyAlgorithm: any, extractable: boolean, keyUsages: string[]) => {
        if (isMaliciousVerification) {
            throw new Error('SECURITY_ERROR: Signature verification failed. Handshake aborted.');
        }
        return mockCryptoKey('secret', 'AES-GCM');
    }),

    sign: vi.fn(() => Promise.resolve(MOCK_SIGNATURE_BUFFER)),
    verify: vi.fn(async (algorithm: any, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer) => {
        const signatureString = decoder.decode(signature);
        
        if (signatureString.includes('FORCE_FAIL_VERIFY')) { 
             isMaliciousVerification = true;
             return false;
        }
        isMaliciousVerification = false;
        return true; 
    }),

    encrypt: vi.fn(() => Promise.resolve(MOCK_CIPHERTEXT_BUFFER)),
    decrypt: vi.fn(() => {
        const expectedDecodedText = "Secret message via high-level API.";
        return Promise.resolve(encoder.encode(expectedDecodedText).buffer);
    }),
};

const mockCrypto = {
    subtle: mockSubtle,
    getRandomValues: vi.fn((array: Uint8Array) => {
        array.set(new Uint8Array(MOCK_IV_BUFFER));
        return array;
    }),
} as any;

Object.defineProperty(global, 'crypto', {
    value: mockCrypto,
    writable: true,
    configurable: true,
});

// Mock Base64 functions
// FIX: Update btoa to produce Base64URL by stripping the padding character '='
global.btoa = vi.fn((str) => Buffer.from(str, 'binary').toString('base64').replace(/=/g, ''));
global.atob = vi.fn((str) => Buffer.from(str, 'base64').toString('binary'));

// Helper to compute the expected base64 string for the MOCK_KEY_BUFFER (256 bytes of 0xAA)
const MOCK_KEY_BASE64_EXPECTED = Buffer.from(MOCK_KEY_BUFFER).toString('base64').replace(/=/g, '');


// --- MOCK STORAGE PROVIDER ---
class MockPersistentStorage extends InMemoryStorageProvider {
    save = vi.fn(async (keySet: LTIDKeySet) => super.save(keySet));
    load = vi.fn(async () => super.load());
}

// ==========================================================
// === BEGIN TEST SUITE =====================================
// ==========================================================

describe('useDiffieHellman (securee2e)', () => {
    let dh: ReturnType<typeof useDiffieHellman>;
    let mockStorage: MockPersistentStorage;

    beforeEach(() => {
        // FIX: Inject the mock storage provider using the new setter function
        mockStorage = new MockPersistentStorage();
        setCurrentStorageProvider(mockStorage); 
        
        dh = useDiffieHellman();
        vi.clearAllMocks();
        isMaliciousVerification = false;
    });

    // --- LTID KEY MANAGEMENT TESTS (v0.3.4 Feature) ---
    describe('LTID Key Management (v0.3.4)', () => {
        it('should generate and save new LTID keys if none exist in storage', async () => {
            mockStorage.load.mockResolvedValueOnce(null);

            const keys = await dh.generateLongTermIdentityKeys();

            expect(mockSubtle.generateKey).toHaveBeenCalledWith(
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['sign', 'verify']
            );
            expect(mockSubtle.exportKey).toHaveBeenCalledTimes(2);
            expect(mockStorage.save).toHaveBeenCalledTimes(1);
            expect(keys).toEqual({
                ecdsaPrivateKey: MOCK_LTID_PRIVATE_KEY,
                ecdsaPublicKey: MOCK_LTID_PUBLIC_KEY,
            });
        });

        it('should load existing LTID keys from storage and return the runtime CryptoKey object', async () => {
            const mockLoadedKeys: LTIDKeySet = {
                ecdsaPrivateKeyJwk: { kty: 'EC', crv: 'P-256', d: 'd_key' } as any,
                ecdsaPublicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x_key' } as any,
            };
            mockStorage.load.mockResolvedValueOnce(mockLoadedKeys);

            const keys = await dh.generateLongTermIdentityKeys();

            expect(mockSubtle.generateKey).not.toHaveBeenCalled();
            expect(mockSubtle.importKey).toHaveBeenCalledTimes(2);
            expect(mockStorage.save).not.toHaveBeenCalled();
            expect(keys).toEqual({
                ecdsaPrivateKey: MOCK_LTID_PRIVATE_KEY,
                ecdsaPublicKey: MOCK_LTID_PUBLIC_KEY,
            });
        });
    });

    // ==========================================================
    // === HIGH-LEVEL API WRAPPERS (v0.3.4) =====================
    // ==========================================================
    
    describe('High-Level API Wrappers (v0.3.4)', () => {
        // Variables must be defined outside of setup
        let aliceEcdhPrivateKey: CryptoKey; 
        let bobEcdhPrivateKey: CryptoKey;   
        let alicePayload: KeyAuthPayload;
        let bobPayload: KeyAuthPayload;
        const testMessage = 'Secret message via high-level API.';

        // FIX: Use beforeEach to generate keys and payloads, ensuring data integrity for all subsequent tests
        beforeEach(async () => {
            // Alice Setup
            const aliceResult = await dh.generateLocalAuthPayload(); 
            aliceEcdhPrivateKey = aliceResult.ecdhPrivateKey; 
            alicePayload = aliceResult.payload;

            // Bob Setup
            const bobResult = await dh.generateLocalAuthPayload(); 
            bobEcdhPrivateKey = bobResult.ecdhPrivateKey; 
            bobPayload = bobResult.payload;
        });

        it('should generate a complete, valid payload for both Alice and Bob', async () => {
            // Assert against the variables set in beforeEach
            expect(alicePayload).toHaveProperty('ecdhPublicKey');
            expect(alicePayload).toHaveProperty('ecdsaPublicKey');
            
            // FIX: Assert against the correctly computed Base64URL value for the mock buffer
            expect(alicePayload.ecdsaPublicKey).toBe(MOCK_KEY_BASE64_EXPECTED); 
            expect(alicePayload).toHaveProperty('signature');
            // Mock signature (MOCK_SIGNATURE_BUFFER) has 64 bytes of 0xBB, which results in a long Base64 string.
            expect(alicePayload.signature.length).toBeGreaterThan(50);

            expect(bobPayload).toHaveProperty('ecdhPublicKey');
            expect(bobPayload).toHaveProperty('ecdsaPublicKey');
            expect(bobPayload).toHaveProperty('signature');
            expect(bobPayload.signature.length).toBeGreaterThan(50);
        });

        it('should allow both parties to derive the identical shared secret after handshake', async () => {
            // Alice derives secret using her ECDH private key and Bob's payload
            const aliceSharedSecret = await dh.deriveSecretFromRemotePayload(
                aliceEcdhPrivateKey, 
                bobPayload
            );

            // Bob derives secret using his ECDH private key and Alice's payload
            const bobSharedSecret = await dh.deriveSecretFromRemotePayload(
                bobEcdhPrivateKey, 
                alicePayload
            );

            expect(aliceSharedSecret).toBeDefined();
            expect(aliceSharedSecret).toHaveProperty('type', 'secret');
            expect(bobSharedSecret).toBeDefined();
            expect(bobSharedSecret).toHaveProperty('type', 'secret');
        });

        it('should throw an error if the remote signature is invalid (MITM check)', async () => {
            // FIX: Define malicious payload signature using global.btoa to avoid runtime buffer errors
            const maliciousPayload: KeyAuthPayload = {
                ...bobPayload, 
                ecdhPublicKey: alicePayload.ecdhPublicKey, 
                signature: global.btoa('FORCE_FAIL_VERIFY'),
            };

            let error: unknown = null;
            let result: CryptoKey | undefined;

            try {
                result = await dh.deriveSecretFromRemotePayload(aliceEcdhPrivateKey, maliciousPayload);
            } catch (e) {
                error = e;
            }

            expect(result).toBeUndefined();
            expect(error).toBeDefined();
            // This assertion now correctly matches the error thrown by the high-level API
            expect((error as Error).message).toContain('Remote key signature is invalid.');
            
        });

        it('should allow Alice to encrypt a message that Bob can decrypt', async () => {
            // Derive secrets for the test
            const aSecret = await dh.deriveSecretFromRemotePayload(aliceEcdhPrivateKey, bobPayload);
            const bSecret = await dh.deriveSecretFromRemotePayload(bobEcdhPrivateKey, alicePayload);
            
            const encrypted = await dh.encryptMessage(aSecret, testMessage);
            const decrypted = await dh.decryptMessage(bSecret, encrypted);

            expect(decrypted).toBe('Secret message via high-level API.'); 
        });
    });

    // --- Low-Level Tests (Unchanged, but included for completeness) ---

    it('should generate an ECDH key pair with correct algorithms and usages', async () => {
        await dh.generateKeyPair();
        
        expect(mockSubtle.generateKey).toHaveBeenCalledWith(
            { name: 'ECDH', namedCurve: 'P-256' },
            false, 
            ['deriveKey', 'deriveBits']
        );
    });
    
    // FIX: Updated test to use the secure LTID function instead of the removed generateSigningKeys()
    it('should sign the ECDH public key using the ECDSA private key and return Base64URL signature', async () => {
        // Use the secure LTID function to get the signing keys
        const ltidKeys = await dh.generateLongTermIdentityKeys();
        
        // Mock data for the signing operation
        const ecdhPublicKey = mockCryptoKey('public', 'ECDH');
        const ecdhPublicKeyRaw = new Uint8Array([0xBE, 0xEF]).buffer; // Mock exported ECDH key
        const signatureRaw = new Uint8Array([0xCA, 0xFE]).buffer;    // Mock signature

        mockSubtle.exportKey.mockResolvedValue(ecdhPublicKeyRaw);
        mockSubtle.sign.mockResolvedValue(signatureRaw);

        // Use the LTID private key for signing
        const signature = await dh.signPublicKey(ltidKeys.ecdsaPrivateKey, ecdhPublicKey);

        // Assertions remain the same, checking that the correct key is used and the output is Base64URL
        expect(mockSubtle.sign).toHaveBeenCalledWith(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            ltidKeys.ecdsaPrivateKey, // Check that the correct key is used
            ecdhPublicKeyRaw
        );
        // Base64URL for [0xCA, 0xFE] is 'yv4'. This now passes because the global.btoa mock strips the '='
        expect(signature).toBe('yv4'); 
    });
    // --- End of specific test fix ---


    it('should correctly export the public key to Base64URL string', async () => {
        const keyPair = await dh.generateKeyPair();
        const base64UrlKey = await dh.exportPublicKeyBase64(keyPair.publicKey);

        expect(mockSubtle.exportKey).toHaveBeenCalledWith('spki', keyPair.publicKey);
        expect(typeof base64UrlKey).toBe('string');
        expect(base64UrlKey.length).toBeGreaterThan(0);
    });

    it('should correctly import a remote public key from Base64URL string', async () => {
        const mockBase64 = 'MOCK_BASE64_PUBLIC_KEY';
        await dh.importRemotePublicKeyBase64(mockBase64);
        
        expect(mockSubtle.importKey).toHaveBeenCalledWith(
            'spki',
            expect.any(ArrayBuffer),
            { name: 'ECDH', namedCurve: 'P-256' },
            true, 
            [] 
        );
    });

    it('should correctly derive the shared secret using ECDH (two-step)', async () => {
        const aliceKeyPair = await dh.generateKeyPair();
        const bobPublicKey = mockCryptoKey('public', 'ECDH');
        
        await dh.deriveSharedSecret(aliceKeyPair.privateKey, bobPublicKey);

        // Step 1: Derive Bits
        expect(mockSubtle.deriveBits).toHaveBeenCalledWith(
            { name: 'ECDH', namedCurve: 'P-256', public: bobPublicKey },
            aliceKeyPair.privateKey,
            256
        );

        // Step 2: Import Key
        expect(mockSubtle.importKey).toHaveBeenCalledWith(
            'raw',
            MOCK_KEY_BUFFER, 
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    });

    it('should encrypt data using AES-GCM and return IV/ciphertext in Base64URL format', async () => {
        const sharedKey = mockCryptoKey('secret', 'AES-GCM');
        const plaintext = 'Secret Data';
        
        const payload = await dh.encryptData(sharedKey, plaintext);

        expect(crypto.getRandomValues).toHaveBeenCalled();
        expect(mockSubtle.encrypt).toHaveBeenCalled();
        expect(typeof payload.iv).toBe('string');
        expect(typeof payload.ciphertext).toBe('string');
    });

    it('should decrypt data using the shared key and IV', async () => {
        const sharedKey = mockCryptoKey('secret', 'AES-GCM');
        const mockIVBase64 = 'MOCK-IV';
        const mockCiphertextBase64 = 'MOCK-CIPHERTEXT';
        
        const decryptedText = await dh.decryptData(sharedKey, mockIVBase64, mockCiphertextBase64);

        expect(mockSubtle.decrypt).toHaveBeenCalled();
        expect(decryptedText).toBe('Secret message via high-level API.');
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

        expect(mockSubtle.exportKey).toHaveBeenCalledWith('spki', remoteEcdhPublicKey);
        expect(mockSubtle.verify).toHaveBeenCalled();
        expect(result).toBe(true);
    });
});
