/**
 * Interface representing the key exchange payload sent over the network.
 * It contains the ephemeral ECDH public key and the ECDSA public key,
 * along with a signature of the ECDH key for authentication.
 */
export interface KeyAuthPayload {
    ecdhPublicKey: string; // Base64 encoded ECDH Public Key (for derivation)
    ecdsaPublicKey: string; // Base64 encoded ECDSA Public Key (for signature verification)
    signature: string; // Base64 encoded signature of ecdhPublicKey using ECDSA Private Key
}

/**
 * Interface representing an encrypted message payload ready for network transmission.
 */
export interface EncryptedPayload {
    iv: string; // Base64 encoded Initialization Vector (12 bytes)
    ciphertext: string; // Base64 encoded encrypted message
}
