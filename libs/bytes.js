export function fromUnicode(string, encoding = 'utf-8') {
    const encoder = new TextEncoder(encoding);
    return encoder.encode(string);
}

export function toHex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

export function fromHex(hexString) {
    let result = [];
    for (let i = 0; i < hexString.length; i += 2) {
        result.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(result);
}

import { sha256 } from '../libs/crypto.js';

export const hashText = async data => {
    return toHex(await sha256(fromUnicode(data)))
}

export function toURI(text) {
    const blob = new Blob([text], { type: 'text/plain' });
    return URL.createObjectURL(blob);
}

/**
 *
 * Concatenates two buffers
 *
 * @param {ArrayBuffer} lhs The first buffer
 * @param {ArrayBuffer} rhs The second buffer
 * @return {ArrayBuffer} The concatenated buffer
 *
 */
export function concat(lhs, rhs) {
    const array = new Uint8Array(lhs.byteLength + rhs.byteLength);
    array.set(new Uint8Array(lhs), 0);
    array.set(new Uint8Array(rhs), lhs.byteLength);
    return array.buffer;
}

/**
 *
 * Pads a buffer with zeros to the right up to a given length.
 *
 * @param {ArrayBuffer} buffer The array.
 * @param {number} n The number of bytes to return.
 * @return {ArrayBuffer} The padded bytes.
 *
 */
export function padRight(buffer, size) {
    const array = new Uint8Array(size)
    array.set(new Uint8Array(buffer), 0)
    return array.buffer
}