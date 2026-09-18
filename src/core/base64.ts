/**
 * Base64 helpers that work on arbitrarily large buffers.
 *
 * `String.fromCharCode(...bytes)` overflows the call stack somewhere around
 * 100–200 KB, so encoding is done in fixed-size chunks. Decoding accepts both
 * standard and URL-safe alphabets and tolerates missing padding/whitespace.
 */

const CHUNK_SIZE = 0x8000;

export function bytesToBase64(input: Uint8Array | ArrayBuffer): string {
    // ArrayBuffer.isView rather than instanceof: buffers from another realm (jsdom, iframes) fail instanceof.
    const bytes = ArrayBuffer.isView(input) ? input : new Uint8Array(input);
    let binary = '';
    for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE) as unknown as number[]);
    }
    return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
    if (typeof base64 !== 'string') {
        throw new TypeError('Expected a Base64 string.');
    }
    // Normalise: strip whitespace, convert URL-safe alphabet, restore padding.
    let normalised = base64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const remainder = normalised.length % 4;
    if (remainder === 1) {
        throw new TypeError('Invalid Base64 string.');
    }
    if (remainder > 0) {
        normalised += '='.repeat(4 - remainder);
    }
    let binary: string;
    try {
        binary = atob(normalised);
    } catch {
        throw new TypeError('Invalid Base64 string.');
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/** Copies `input` into a fresh, ArrayBuffer-backed Uint8Array (what Web Crypto expects). */
export function toBytes(input: string | Uint8Array | ArrayBuffer): Uint8Array<ArrayBuffer> {
    if (typeof input === 'string') {
        return new TextEncoder().encode(input);
    }
    return new Uint8Array(input);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}
