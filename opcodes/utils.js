import './std/opcodes.js'

export const loop = (count, template) => {
    let res = [];
    for (var i = 0; i < count; i++) {
        res.push( template(i, count) );
    }
    return res.flat(4).join('\n');
}

const $stop = 'debug;'

export function bytesFromText(text) {
   // Create a TextEncoder instance
  const encoder = new TextEncoder('utf-8');

  // Encode the text to a Uint8Array of bytes in UTF-8
  const uint8Array = encoder.encode(text);

  return Array.from(uint8Array).reverse();
}

export function bytesFromHex(hexString) {
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