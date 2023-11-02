//
// Memory management 
//
let ENV = {}

for (let i = 0; i < 16; i++) {
    ENV['s' + i] = i
    ENV['m' + i] = i + 16
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
    ENV[identifier] = 0;
    return '';
}


//
// Blake3
//

// The initial state
const IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
const INITIAL_STATE = [IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[0], IV[1], IV[2], IV[3], 0, 0, 32, 8]
const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

// 
// The Blake3 "quarter round"
// As described in the paper in "2.2 Compression Function"
// https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
//
const G = (_ap, a, b, c, d, m0, m1) => {

    return [

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

    ];
}


// A round of blake 3
const round = _ap => [
    G(_ap, 's0', 's4', 's8', 's12', 'm0', 'm1'),
    G(_ap, 's1', 's5', 's9', 's13', 'm2', 'm3'),
    G(_ap, 's2', 's6', 's10', 's14', 'm4', 'm5'),
    G(_ap, 's3', 's7', 's11', 's15', 'm6', 'm7'),

    G(_ap, 's0', 's5', 's10', 's15', 'm8', 'm9'),
    G(_ap, 's1', 's6', 's11', 's12', 'm10', 'm11'),
    G(_ap, 's2', 's7', 's8', 's13', 'm12', 'm13'),
    G(_ap, 's3', 's4', 's9', 's14', 'm14', 'm15'),
];

const permute = _ => {
    const oldState = {}
    for (let i = 0; i < 16; i++) {
        oldState['m' + i] = ENV['m' + i]  
    }

    Object.keys(oldState).forEach( (identifier,i) => {
        const newIdentifier = 'm' + MSG_PERMUTATION[i]
        ENV[newIdentifier] = oldState[identifier]
    })

    return ''
}

const compress = _ap => [
    round(_ap),
    permute(),

    round(_ap),
    permute(),

    round(_ap),
    permute(),

    round(_ap),
    permute(),

    round(_ap),
    permute(),

    round(_ap),
    permute(),

    round(_ap),

    u32_copy_zip(ENV.s0 + 0, ptr_extract('s8') + 0), u32_xor(_ap + 1),
    u32_copy_zip(ENV.s1 + 1, ptr_extract('s9') + 1), u32_xor(_ap + 1),
    u32_copy_zip(ENV.s2 + 2, ptr_extract('s10') + 2), u32_xor(_ap + 1),
    u32_copy_zip(ENV.s3 + 3, ptr_extract('s11') + 3), u32_xor(_ap + 1),
    u32_copy_zip(ENV.s4 + 4, ptr_extract('s12') + 4), u32_xor(_ap + 1),
    u32_copy_zip(ENV.s5 + 5, ptr_extract('s13') + 5), u32_xor(_ap + 1),
    u32_copy_zip(ENV.s6 + 6, ptr_extract('s14') + 6), u32_xor(_ap + 1),
    u32_copy_zip(ENV.s7 + 7, ptr_extract('s15') + 7), u32_xor(_ap + 1),

];



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

    // 'debug;',

    //
    // Clean up our stack to make the result more readable
    //
    loop(32, _ => u32_toaltstack),
    u32_drop_xor_table,
    loop(32, _ => u32_fromaltstack),

    loop(24, i => u32_roll( i + 8 )  ),
    loop(24, i => u32_drop ),
]