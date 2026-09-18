import { describe, expect, it } from 'vitest';
import { base64ToBytes, bytesToBase64 } from '../src/core/base64';
import { randomBytes } from './helpers';

describe('base64', () => {
    it('round-trips arbitrary bytes', () => {
        const bytes = randomBytes(1000);
        expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
    });

    it('handles large buffers without overflowing the stack (regression for spread-based encoder)', () => {
        const bytes = randomBytes(2 * 1024 * 1024);
        const decoded = base64ToBytes(bytesToBase64(bytes));
        // toEqual on multi-MB typed arrays is very slow; compare directly.
        expect(decoded.length).toBe(bytes.length);
        expect(decoded.every((b, i) => b === bytes[i])).toBe(true);
    });

    it('accepts ArrayBuffer input', () => {
        expect(bytesToBase64(new Uint8Array([1, 2, 3]).buffer)).toBe('AQID');
    });

    it('decodes URL-safe alphabet, missing padding and whitespace', () => {
        const bytes = new Uint8Array([0xfb, 0xff, 0xbf]); // standard: "+/+/"
        expect(bytesToBase64(bytes)).toBe('+/+/');
        expect(base64ToBytes('-_-_')).toEqual(bytes);
        expect(base64ToBytes('AQI')).toEqual(new Uint8Array([1, 2]));
        expect(base64ToBytes(' AQ\nID ')).toEqual(new Uint8Array([1, 2, 3]));
    });

    it('rejects invalid input', () => {
        expect(() => base64ToBytes('A')).toThrow(TypeError);
        expect(() => base64ToBytes('!!!!')).toThrow(TypeError);
        expect(() => base64ToBytes(42 as unknown as string)).toThrow(TypeError);
    });
});
