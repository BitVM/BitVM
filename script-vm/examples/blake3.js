const program = [
`   
// 
// The Blake3 "quarter round"
// As described in the paper in "2.2 Compression Function"
// https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
//



// Initialize our lookup table
// We have to do that only once per program
`,
u32_push_xor_table,
`

// 
// Inputs
//

`,
// Push the six inputs a, b, c, d, m0, m1 onto the stack

// m1
u32_push(0x54535251),
// m0
u32_push(0x44434241),
// d
u32_push(0x34333231),
// c
u32_push(0x24232221),
// b
u32_push(0x14131211),
// a
u32_push(0x04030201),
`

//--------------------------------------------------------


//
//
// Program
//
//

`,

// Stack:  m1 m0 d c b a  |

// z = a+b+m0 
u32_pick(1),
u32_zip(0, 1),
u32_add,
u32_zip(0, 4),
u32_add,
// Stack:  m1 d c b  |  z

// y = (d^z) >>> 16
u32_pick(0),
u32_zip(0, 4),
u32_xor(6),
u32_rrot16,
// Stack:  m1 c b  |  z y

// x = y+c
u32_pick(0),
u32_zip(0, 4),
u32_add,
// Stack:  m1 b  |  z y x

// w = (b^x) >>> 12
u32_pick(0),
u32_zip(0, 4),
u32_xor(6),
u32_rrot12,
// Stack:  m1  |  z y x w

// v = z+w+m1
u32_pick(0),
u32_zip(0, 4),
u32_add,
u32_zip(0, 4),
u32_add,
// Stack:  |  y x w v

// u = (y^v) >>> 8
u32_pick(0),
u32_zip(0, 4),
u32_xor(5),
u32_rrot8,
// Stack:  |  x w v u

// t = x+u
u32_pick(0),
u32_zip(0, 4),
u32_add,
// Stack:  |  w v u t

// s = (w^t) >>> 7
u32_pick(0),
u32_zip(0, 4),
u32_xor(5),
u32_rrot7,
// Stack:  |  v u t s



//
// Cleanup our stack to make the result more readable
//
u32_toaltstack,
u32_toaltstack,
u32_toaltstack,
u32_toaltstack,

u32_drop_xor_table,

u32_fromaltstack,
u32_fromaltstack,
u32_fromaltstack,
u32_fromaltstack

].join('')


document.write(`<pre>${program}</pre>`)
