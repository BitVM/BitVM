const loop = (count, template) => {
    let res = [];
    for (var i = 0; i < count; i++) {
        res.push( template(i, count) );
    }
    return res.flat(4).join('\n');
}

const $stop = 'debug;'


function bytesFromText(text) {
   // Create a TextEncoder instance
  const encoder = new TextEncoder('utf-8');

  // Encode the text to a Uint8Array of bytes in UTF-8
  const uint8Array = encoder.encode(text);

  return Array.from(uint8Array).reverse();
}