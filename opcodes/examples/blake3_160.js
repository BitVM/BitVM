[

`
//
// Input: A 64-byte message in the unlocking script
//
`,
bytesFromText('OP_CAT can be used as a tool to liberate and protect people 😸'),
`

//--------------------------------------------------------

//
// Program: A Blake3 hash lock
//

`,

// Sanitize the 64-byte message
sanitizeBytes(64),

// Compute Blake3
blake3(),

// Uncomment the following line to inspect the resulting hash
// 'debug;',

// Push the expected hash onto the stack
bytesFromHex('e72f095723bff66ad953e65b64bdf956aeeba11b628d7a44079a78e7dbff2654'),

// Verify the result of Blake3 is the expected hash
u256_equalverify,

// Every script has to end with true on the stack
'OP_TRUE',

]