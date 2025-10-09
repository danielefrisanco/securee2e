# Changelog

## [0.3.1] - 2025-10-09

### Added
* **High-Level API Wrappers (Unified Workflow):** Introduced a simplified API layer to manage the entire authenticated key exchange and messaging process, wrapping the low-level crypto functions.
    * `generateLocalAuthPayload()`: Generates all local ECDH/ECDSA keys and the authenticated public payload for sharing.
    * `deriveSecretFromRemotePayload()`: Handles importing remote keys, performing the essential MITM signature verification check, and deriving the shared secret.
    * `encryptMessage()`: High-level function to securely encrypt a plaintext message using the shared secret.
    * `decryptMessage()`: High-level function to decrypt a received encrypted payload.

## [0.3.0] - 2025-10-09

### Added
- **Authenticated Key Exchange (MITM Protection):** Implemented Elliptic Curve Digital Signature Algorithm (ECDSA) for signing and verifying the ECDH public key.
- **New Functions:**
    - `generateSigningKeys()`: Generates ECDSA key pair for authentication.
    - `signPublicKey()`: Creates an ECDSA signature over the ECDH public key.
    - `verifySignature()`: Validates the remote party's signature to prevent MITM attacks.
- **CHANGELOG.md:** Added a change log file to track release history.

### Changed
- **Updated Key Exchange Workflow:** The standard key exchange process is now a 6-step workflow that requires key signature and verification prior to shared secret derivation.
- **Documentation:** Updated `README.md` to reflect the authenticated workflow, new functions, and defined payload structures (`KeyAuthPayload`, `EncryptedPayload`).

### Security
- **Mitigation of MITM Attacks:** Public keys are now cryptographically authenticated using ECDSA (P-256), protecting against malicious intermediate parties from swapping public keys.

## 0.2.0 (2025-10-09)

### Added

- **Trusted Publisher Workflow:** Implemented GitHub Actions workflow (`.github/workflows/publish.yml`) to securely and automatically publish new releases to NPM using OIDC and GitHub's Trusted Publisher feature.

### Changed

- **Key Derivation Robustness:** Refactored `deriveSharedSecret` to use the reliable two-step process (`deriveBits` followed by `importKey`), resolving runtime issues in various browser environments.
- **Testing:** Updated unit tests to accurately mock and assert the two-step key derivation and ECDH key properties (`extractable: false`).

## 0.1.0 (Initial Release)

### Added

- **Core Functionality:** Initial implementation of the `useDiffieHellman` Vue 3 composable.
- **ECDH P-256 Key Agreement:** Functions for generating private/public key pairs (`generateKeyPair`).
- **AES-256 GCM Encryption:** Core methods for symmetric encryption and decryption (`encryptData`, `decryptData`).
- **Serialization Utilities:** Helper functions for converting keys between `CryptoKey` objects and network-friendly Base64 strings.