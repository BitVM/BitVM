const seed = '<<my_secret_seed>>';

[
`
//
//
// Verifying the Sum of three u32 Commitments 
//
//

//
// Unlocking Script
//
`,

u32_state_unlock( seed, 'my_varC', 0x77889955 ),
u32_state_unlock( seed, 'my_varB', 0x33557744 ),
u32_state_unlock( seed, 'my_varA', 0x44332211 ),

`

// ----------------------

//
// Program
//

`,

u32_state(seed, 'my_varA'),
u32_toaltstack,
u32_state(seed, 'my_varB'),
u32_fromaltstack,
u32_zip(0, 1),
u32_add,
u32_pick(0),
u32_toaltstack,
u32_toaltstack,
u32_state(seed, 'my_varC'),
u32_fromaltstack,
u32_zip(0, 1),
u32_equalverify,
u32_fromaltstack

]
