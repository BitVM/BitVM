import { sha256 } from './crypto.js';
import { toHex, fromUnicode } from './bytes.js';

export const hashText = async data => {
    return toHex(await sha256(fromUnicode(data)))
}

export function toURI(text) {
    const blob = new Blob([text], { type: 'text/plain' });
    return URL.createObjectURL(blob);
}

export const fetchJson = source => fetch(source).then(r => r.json())