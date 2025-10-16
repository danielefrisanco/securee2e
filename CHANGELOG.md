# Changelog
## [0.4.2] (Persistent Storage Migration)
* **Feature:** Implemented the persistent, asynchronous `IndexedDBProvider` to store Long-Term Identity (LTID) key sets securely.

* **Update:** Set `IndexedDBProvider` as the **default storage mechanism**, ensuring LTID keys persist across browser sessions and full page refreshes.

* **Refactor:** Decoupled storage logic from the main hook by introducing the `IKeyStorageProvider` interface and creating modular files, stabilizing key retrieval logic for all storage types.

## [0.4.1] (Dependency Update)
* **Update:** Defined **Vue.js** as a `peerDependency` in the library's package configuration, aligning with best practices for Vue composables.

* **Refactor:** Centralized key generation and persistence logic within `useDiffieHellman.ts` for clearer control flow and better preparation for async operations.

## [0.4.0] - 2025-10-10
### Added
* **Key Persistence (Default):** The Long-Term Identity (LTID) keys are now persistent by default, surviving page refreshes and browser restarts.

* **LocalStorageProvider:** Introduced `LocalStorageProvider` which saves LTID keys to `window.localStorage`. This is now the default storage provider.

* **Swappable Storage Providers:** Implemented the `setCurrentStorageProvider(provider)` function and the `IKeyStorageProvider` interface, allowing users to easily swap the default storage mechanism (e.g., switching back to in-memory, or implementing custom database storage).

## [0.3.4] - 2025-10-10

### Changed
* **Simplified High-Level Identity Setup:** The `generateLocalAuthPayload()` function is now truly **zero-argument**. It was refactored to internally call `generateLongTermIdentityKeys()`, automatically handling the loading, generation, and persistence of the Long-Term Identity (LTID) keys before generating and signing the ephemeral payload. This removes the manual dependency on passing LTID keys, further simplifying the authenticated handshake for the end user.

## [0.3.2] - 2025-10-10

### 📦 Maintenance & Packaging
- **Licensing:** Added the permissive MIT License to the package to ensure easy adoption by other projects.

- **Package Optimization:** Implemented the `"files"` exclusion list in `package.json` to drastically reduce the size of the published package by excluding all development artifacts (tests, examples, configuration).

- **Module Compatibility:** Added the `"exports"` mapping to `package.json` for superior CJS/ESM dual-package support, ensuring seamless module resolution across different build systems.

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