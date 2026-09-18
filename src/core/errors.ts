/**
 * Typed errors so callers can branch on `instanceof` (or `.code`) instead of
 * matching error message strings.
 */

export type SecureE2EErrorCode =
    | 'NOT_INITIALIZED'
    | 'INVALID_PAYLOAD'
    | 'SIGNATURE_INVALID'
    | 'IDENTITY_MISMATCH'
    | 'DECRYPTION_FAILED'
    | 'STORAGE_ERROR';

export class SecureE2EError extends Error {
    readonly code: SecureE2EErrorCode;

    constructor(code: SecureE2EErrorCode, message: string, options?: { cause?: unknown }) {
        super(message, options);
        this.name = 'SecureE2EError';
        this.code = code;
    }
}

export class NotInitializedError extends SecureE2EError {
    constructor() {
        super('NOT_INITIALIZED', 'Identity keys are not initialized yet. Await init() first.');
        this.name = 'NotInitializedError';
    }
}

export class InvalidPayloadError extends SecureE2EError {
    constructor(message = 'Received payload is malformed.') {
        super('INVALID_PAYLOAD', message);
        this.name = 'InvalidPayloadError';
    }
}

/** The signature over the remote ephemeral key does not verify with the remote identity key. */
export class SignatureInvalidError extends SecureE2EError {
    constructor() {
        super('SIGNATURE_INVALID', 'Remote key signature is invalid.');
        this.name = 'SignatureInvalidError';
    }
}

/**
 * The remote payload is internally consistent, but its identity key is not the
 * one the caller pinned. This is the actual man-in-the-middle detection.
 */
export class IdentityMismatchError extends SecureE2EError {
    readonly expected: string;
    readonly actual: string;

    constructor(expected: string, actual: string) {
        super('IDENTITY_MISMATCH', 'Remote identity does not match the expected identity.');
        this.name = 'IdentityMismatchError';
        this.expected = expected;
        this.actual = actual;
    }
}

export class DecryptionError extends SecureE2EError {
    constructor(cause?: unknown) {
        super('DECRYPTION_FAILED', 'Decryption failed: wrong key, wrong AAD, or tampered ciphertext.', { cause });
        this.name = 'DecryptionError';
    }
}

export class StorageError extends SecureE2EError {
    constructor(message: string, cause?: unknown) {
        super('STORAGE_ERROR', message, { cause });
        this.name = 'StorageError';
    }
}
