[

`
//
// Input: A 40-byte message in the unlocking script
//
`,


pushText('OP_CAT can be used as a tool to liberate'),
`

//--------------------------------------------------------

//
// Program: A Blake3 hash lock
//

`,

// Sanitize the 40-byte message
sanitizeBytes(40),

// Compute Blake3
blake3_160,

// Uncomment the following line to inspect the resulting hash
// 'debug;',

// Push the expected hash onto the stack
pushHex('5d18cc351a2c105a627aaecf7d682cd7a3904c0d'),

// Verify the result of Blake3 is the expected hash
u160_equalverify,

// Every script has to end with true on the stack
'OP_TRUE',

]