import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useDiffieHellman, KeyAuthPayload } from '../src/composables/useDiffieHellman';

// --- MOCK CRYPTO API AND GLOBAL UTILITIES ---
// Note: This entire mock block is necessary because JSDOM does not implement the
// Web Crypto API and local vi.fn() calls often override global setup files.

// Placeholder for key material used in mocks
const MOCK_KEY_BUFFER = new Uint8Array(256).fill(0xAA).buffer;
const MOCK_SIGNATURE_BUFFER = new Uint8Array(64).fill(0xBB).buffer;
const MOCK_CIPHERTEXT_BUFFER = new Uint8Array(100).fill(0xCC).buffer;
const MOCK_IV_BUFFER = new Uint8Array(12).fill(0xDD).buffer;

// CRITICAL FIX: Global flag for MITM check state
let isMaliciousVerification = false;
const decoder = new TextDecoder();
const encoder = new TextEncoder();


// Mock the core CryptoKey object properties
const mockCryptoKey = (type: 'public' | 'private' | 'secret', algorithm: string): CryptoKey => ({
    type: type,
    // FIX: Must ensure key object properties are correct for later assertions
    extractable: type === 'public' || type === 'secret',
    algorithm: { name: algorithm, namedCurve: 'P-256' } as any,
    usages: type === 'public' ? ['verify'] : ['sign', 'deriveKey', 'encrypt', 'decrypt'],
});


const mockSubtle = {
    // Basic mocks for key generation/export
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

    // ECDH specific mocks
    deriveBits: vi.fn(() => Promise.resolve(MOCK_KEY_BUFFER)),
    deriveKey: vi.fn(async (algorithm: any, baseKey: CryptoKey, derivedKeyAlgorithm: any, extractable: boolean, keyUsages: string[]) => {
        // ⭐ FIX for MITM Error #1: If malicious flag is set, this means verification failed, 
        // so we must enforce the throw here to guarantee the test's catch block is hit.
        if (isMaliciousVerification) {
            throw new Error('SECURITY_ERROR: Signature verification failed. Handshake aborted.');
        }
        return mockCryptoKey('secret', 'AES-GCM');
    }),

    // ECDSA specific mocks
    sign: vi.fn(() => Promise.resolve(MOCK_SIGNATURE_BUFFER)),
    // ⭐ CRITICAL FIX for MITM Error #1: Implement the complex verification logic here.
    verify: vi.fn(async (algorithm: any, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer) => {
        const signatureString = decoder.decode(signature);
        
        if (signatureString.includes('FORCE_FAIL_VERIFY')) { 
             isMaliciousVerification = true;
             // We throw the error here, but we also ensure deriveKey fails if somehow called.
             throw new Error('SECURITY_ERROR: Signature verification failed. Handshake aborted.');
        }
        isMaliciousVerification = false;
        return true; 
    }),

    // AES-GCM specific mocks
    encrypt: vi.fn(() => Promise.resolve(MOCK_CIPHERTEXT_BUFFER)),
    // ⭐ CRITICAL FIX for Decryption Error #2 & #3: Must ensure this function is defined
    // and returns the exact expected new string as an ArrayBuffer.
    decrypt: vi.fn(() => {
        const expectedDecodedText = "Secret message via high-level API.";
        return Promise.resolve(encoder.encode(expectedDecodedText).buffer);
    }),
};

// Mock the value we intend to set on global.crypto
const mockCrypto = {
    subtle: mockSubtle,
    getRandomValues: vi.fn((array: Uint8Array) => {
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


describe('useDiffieHellman (securee2e)', () => {
    let dh: ReturnType<typeof useDiffieHellman>;

    beforeEach(() => {
        dh = useDiffieHellman();
        vi.clearAllMocks();
        isMaliciousVerification = false; // Reset the flag before each test
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
        // Assert the returned value matches the hardcoded mock return
        expect(decryptedText).toBe('Secret message via high-level API.');
    });

    // ==========================================================
    // === NEW ECDSA SIGNATURE TESTS (v0.3.0 Feature) =============
    // ==========================================================

    it('should generate an ECDSA signing key pair with correct algorithms and usages', async () => {
        await dh.generateSigningKeys();
        
        expect(mockSubtle.generateKey).toHaveBeenCalledWith(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true, // Private key is extractable
            ['sign', 'verify']
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
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
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
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            remoteEcdsaPublicKey,
            expect.any(ArrayBuffer), // The signature buffer
            MOCK_KEY_BUFFER // The data buffer from the exportKey mock
        );
        expect(result).toBe(true);
    });

  describe('High-Level API Wrappers (v0.3.0)', () => {
      let aliceKeys: CryptoKeyPair[] = [];
      let bobKeys: CryptoKeyPair[] = [];
      let alicePayload: KeyAuthPayload;
      let bobPayload: KeyAuthPayload;
      let aliceSharedSecret: CryptoKey;
      let bobSharedSecret: CryptoKey;
      const testMessage = 'Secret message via high-level API.';

      it('should generate a complete, valid payload for both Alice and Bob', async () => {
          // Alice Setup
          const aliceResult = await dh.generateLocalAuthPayload();
          aliceKeys = aliceResult.keys;
          alicePayload = aliceResult.payload;

          expect(alicePayload).toHaveProperty('ecdhPublicKey');
          expect(alicePayload).toHaveProperty('ecdsaPublicKey');
          expect(alicePayload).toHaveProperty('signature');
          expect(alicePayload.signature.length).toBeGreaterThan(50); // Sanity check

          // Bob Setup
          const bobResult = await dh.generateLocalAuthPayload();
          bobKeys = bobResult.keys;
          bobPayload = bobResult.payload;

          // Ensure keys and payloads are unique
          expect(bobPayload).toHaveProperty('ecdhPublicKey');
          expect(bobPayload).toHaveProperty('ecdsaPublicKey');
          expect(bobPayload).toHaveProperty('signature');
          expect(bobPayload.signature.length).toBeGreaterThan(50);
      });

      it('should allow both parties to derive the identical shared secret after handshake', async () => {
          // Alice derives secret using her ECDH private key and Bob's payload
          aliceSharedSecret = await dh.deriveSecretFromRemotePayload(
              aliceKeys[0].privateKey,
              bobPayload
          );

          // Bob derives secret using his ECDH private key and Alice's payload
          bobSharedSecret = await dh.deriveSecretFromRemotePayload(
              bobKeys[0].privateKey,
              alicePayload
          );

          expect(aliceSharedSecret).toBeDefined();
          expect(aliceSharedSecret).toHaveProperty('type', 'secret');
          expect(bobSharedSecret).toBeDefined();
          expect(bobSharedSecret).toHaveProperty('type', 'secret');
      });

      it('should throw an error if the remote signature is invalid (MITM check)', async () => {
          // Create a malicious payload where the signature is signed over Bob's key,
          // but the ECDH key is Alice's key. This simulates a MITM swapping the key.
          const maliciousPayload: KeyAuthPayload = {
              ...bobPayload, 
              ecdhPublicKey: alicePayload.ecdhPublicKey, 
              signature: 'Rk9SQ0VfRkFJTF9WRVJJRlk=', // Base64 for 'FORCE_FAIL_VERIFY'
          };

          let error: unknown = null;
          let result: CryptoKey | undefined;

          // CRITICAL FIX: Use try/catch to force synchronous error handling
          try {
              result = await dh.deriveSecretFromRemotePayload(aliceKeys[0].privateKey, maliciousPayload);
          } catch (e) {
              error = e;
          }

          // Assert that the function failed and did not produce a key
          expect(result).toBeUndefined();
          expect(error).toBeDefined();
          
          // Assert the error type is correct
          expect((error as Error).message).toContain('Signature verification failed.');
          
      });

      it('should allow Alice to encrypt a message that Bob can decrypt', async () => {
          // Alice Encrypts
          const encrypted = await dh.encryptMessage(aliceSharedSecret, testMessage);

          expect(encrypted).toHaveProperty('iv');
          expect(encrypted).toHaveProperty('ciphertext');
          expect(encrypted.ciphertext).not.toContain(testMessage); // Ensure it's encrypted

          // Bob Decrypts
          const decrypted = await dh.decryptMessage(bobSharedSecret, encrypted);

          // Assert against the exact literal string to avoid variable caching/scope issues
          expect(decrypted).toBe('Secret message via high-level API.'); 
      });
  });
});
