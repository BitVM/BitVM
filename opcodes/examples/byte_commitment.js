const seed = '<<my_secret_seed>>';

[


`
//
//
// Example of a Byte Commitment
//
// 


//
// Unlocking Script
//
`,
u8_state_unlock(seed, 'my_varA', 0b11100100),



`
// ----------------------

//
// Program (four 2-bit commitments)
//
`,
u8_state(seed, 'my_varA'),
`

<${ 0b11100100 }>
OP_EQUALVERIFY
// Success! The value was correct

// Let's push some random data onto the stack 
// to signal we succefully got here
<42>
`

]
