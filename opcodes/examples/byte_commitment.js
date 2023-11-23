const player = new Player('730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6');

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
u8_state_unlock(player, 'my_varA', 0b11100100),



`
// ----------------------

//
// Program (four 2-bit commitments)
//
`,
u8_state(player, 'my_varA'),
`

${ 0b11100100 }
OP_EQUALVERIFY
// Success! The value was correct

// Let's push some random data onto the stack 
// to signal we succefully got here
42
`

]
