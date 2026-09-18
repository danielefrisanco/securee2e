/** `crypto.getRandomValues` refuses more than 65 536 bytes per call; fill larger buffers in chunks. */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(length);
    for (let offset = 0; offset < length; offset += 65_536) {
        crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65_536, length)));
    }
    return out;
}
