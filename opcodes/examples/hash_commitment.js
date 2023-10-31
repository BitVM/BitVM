const seed = '<<my_secret_seed>>'

const program = [


`
//
//
// Example of a Hash Commitment
//
//


//
// Unlocking Script
//

// Some arbitrary hash here
`,
u160_state_unlock(seed, 'my_varA', '1234567890abcdef1234567890abcdef12345678'),



`
// ----------------------

//
// Program (eighty 2-bit commitments)
//
`,
u160_state(seed, 'my_varA')



].join('\n')

document.write(`<pre>${program}</pre>`)