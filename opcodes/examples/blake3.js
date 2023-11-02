//
// Memory management 
//
let ENV = {}

let S = i => `state_${i}`
let M = i => `msg_${i}`

for (let i = 0; i < 16; i++) {
    ENV[S(i)] = i
    ENV[M(i)] = i + 16
}

const ptr_extract = identifier => {
    if (!(identifier in ENV))
        throw `Undefined variable ${identifier}`

    const index = ENV[identifier]
    delete ENV[identifier]
    Object.keys(ENV).forEach(key => {
        if (index < ENV[key])
            ENV[key] -= 1
    })
    return index
}

const ptr_insert = identifier => {
    Object.keys(ENV).forEach(key => ENV[key] += 1)
    ENV[identifier] = 0
}


//
// Blake3
//

// The initial state
const IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
const INITIAL_STATE = [IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[0], IV[1], IV[2], IV[3], 0, 0, 64, 0b00001011]
const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

// 
// The Blake3 "quarter round"
// As described in the paper in "2.2 Compression Function"
// https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
//
const G = (_ap, a, b, c, d, m0, m1) => [
    // Stack:  m1 m0 d c b a  |

    // z = a+b+m0 
    u32_copy_zip(ENV[b], ptr_extract(a)),
    u32_add,
    u32_copy_zip(ENV[m0] + 1, 0),
    u32_add,
    // Stack:  m1 m0 d c b  |  z

    // y = (d^z) >>> 16
    u32_copy_zip(0, ptr_extract(d) + 1),
    u32_xor(_ap + 1),
    u32_rrot16,
    // Stack:  m1 m0 c b  |  z y


    // x = y+c
    u32_copy_zip(0, ptr_extract(c) + 2),
    u32_add,
    // Stack:  m1 m0 b  |  z y x

    // w = (b^x) >>> 12
    u32_copy_zip(0, ptr_extract(b) + 3),
    u32_xor(_ap + 1),
    u32_rrot12,
    // Stack:  m1 m0 |  z y x w


    // v = z+w+m1
    u32_copy_zip(0, 3),
    u32_add,
    u32_copy_zip(ENV[m1] + 4, 0),
    u32_add,
    // Stack: m1 m0 |  y x w v

    // u = (y^v) >>> 8
    u32_copy_zip(0, 3),
    u32_xor(_ap + 1),
    u32_rrot8,
    // Stack: m1 m0 |  x w v u

    // t = x+u
    u32_copy_zip(0, 3),
    u32_add,
    // Stack: m1 m0 |  w v u t

    // s = (w^t) >>> 7
    u32_copy_zip(0, 3),
    u32_xor(_ap + 1),
    u32_rrot7,
    // Stack: m1 m0 |  v u t s


    ptr_insert(a),
    ptr_insert(d),
    ptr_insert(c),
    ptr_insert(b),
]

// A round of blake 3
const round = _ap => [
    G(_ap, S(0), S(4), S(8),  S(12), M(0),  M(1)),
    G(_ap, S(1), S(5), S(9),  S(13), M(2),  M(3)),
    G(_ap, S(2), S(6), S(10), S(14), M(4),  M(5)),
    G(_ap, S(3), S(7), S(11), S(15), M(6),  M(7)),

    G(_ap, S(0), S(5), S(10), S(15), M(8),  M(9)),
    G(_ap, S(1), S(6), S(11), S(12), M(10), M(11)),
    G(_ap, S(2), S(7), S(8),  S(13), M(12), M(13)),
    G(_ap, S(3), S(4), S(9),  S(14), M(14), M(15)),
]

const permute = _ => {
    const oldState = {}
    for (let i = 0; i < 16; i++) {
        oldState[M(i)] = ENV[M(i)]  
    }

    Object.keys(oldState).forEach( (identifier,i) => {
        const newIdentifier = M( MSG_PERMUTATION[i] )
        ENV[newIdentifier] = oldState[identifier]
    })
}


const compress = _ap => [
    loop(6, _ => [
        round(_ap), 
        permute() 
    ]),
    round(_ap),

    loop(8, i => [
        u32_copy_zip(ENV[S(i)] + i, ptr_extract(S(8+i)) + i), 
        u32_xor(_ap + 1)
    ])
];



//
// Putting everything together...
//

[

`
// Initialize our lookup table
// We have to do that only once per program
`,
u32_push_xor_table,


`

// 
// Inputs
// 

`,
// Push the 64-byte message onto the stack

// m15
u32_push(0x00000000),
// m14
u32_push(0x00000000),
// m13
u32_push(0x00000000),
// m12
u32_push(0x00000000),

// m11
u32_push(0x00000000),
// m10
u32_push(0x00000000),
// m9
u32_push(0x00000000),
// m8
u32_push(0x00000000),

// m7
u32_push(0x00000000),
// m6
u32_push(0x00000000),
// m5
u32_push(0x00000000),
// m4
u32_push(0x00000000),

// m3
u32_push(0x00000000),
// m2
u32_push(0x00000000),
// m1
u32_push(0x00000000),
// m0
u32_push(0x00000000),
`

//--------------------------------------------------------


//
//
// Program
//
//

`,

// Push the initial state onto the stack
INITIAL_STATE.reduce((a, e) => u32_push(e) + a, ''),

// Perform a round of Blake3    
compress(32),



//
// Clean up our stack to make the result more readable
//
loop(32, _ => u32_toaltstack),
u32_drop_xor_table,
loop(32, _ => u32_fromaltstack),

loop(24, i => u32_roll( i + 8 ) ),
loop(24, i => u32_drop ),

]