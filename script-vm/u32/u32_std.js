const u32_push = value => `
<${ (value & 0xff000000) >>> 24 }>
<${ (value & 0x00ff0000) >>> 16 }>
<${ (value & 0x0000ff00) >>> 8 }>
<${ (value & 0x000000ff) }>
`

const u32_equalverify = `
OP_EQUALVERIFY
OP_EQUALVERIFY
OP_EQUALVERIFY
OP_EQUALVERIFY
`

const u32_toaltstack = `
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
`

const u32_fromaltstack = `
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
`

