import './std/opcodes.js'
import {fromUnicode, fromHex} from '../libs/bytes.js'


const $stop = 'debug;'

export function pushText(text) {
  return Array.from(fromUnicode(text)).reverse();
}

export function pushHexEndian(hexString) {
  return Array.from(fromHex(hexString)).reverse();
}


export function pushHex(hexString) {
  if (hexString.length % 8 !== 0) {
    throw new Error('Hex string length must be a multiple of 8 characters.');
  }

  let byteArray = [];

  for (let i = 0; i < hexString.length; i += 8) {
    // Extract 4-byte chunks (8 hex characters)
    let chunk = hexString.substring(i, i + 8);
    // Swap the endianess of the chunk
    let swappedChunk = chunk.match(/../g).reverse().join('');

    // Convert the swapped chunk into an array of integers
    for (let j = 0; j < swappedChunk.length; j += 2) {
      let byte = parseInt(swappedChunk.substring(j, j + 2), 16);
      if (isNaN(byte)) {
        throw new Error('Invalid hex string');
      }
      byteArray.push(byte);
    }
  }

  return byteArray;
}

// Verify that the top `byteCount` many stack items 
// are in the 8-bit range from 0 to 255.
export const sanitizeBytes = byteCount => [
    256,
    loop(byteCount, i => [i+1, OP_PICK, OP_OVER, 0, OP_SWAP, OP_WITHIN, OP_VERIFY]),
    OP_DROP,
];


