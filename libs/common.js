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


// Count trailing zero bits
export const trailingZeros = n => {
    if(n === undefined)
        throw new Error(`n may not be undefined`)
    if(n < 0)
        throw new Error(`n may not be negative ${n}`)
    if (n === 0) 
        return 5 // Special case for 0, as it has an indefinite number of trailing zeros.

    let count = 0
    while ((n & 1) === 0) {
        count++
        n = n >>> 1
    }
    return count
}