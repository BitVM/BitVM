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
