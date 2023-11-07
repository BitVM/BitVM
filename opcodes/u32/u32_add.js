const add_bytes_toaltstack = `
OP_ADD
OP_DUP
255
OP_GREATERTHAN
OP_IF
    256
    OP_SUB
    1
OP_ELSE
    0
OP_ENDIF
OP_SWAP
OP_TOALTSTACK
`
// 
// Addition of two u32 values represented as u8
//  
const u32_add = (a, b) => {
    if (a == b) throw "a == b"
    a = (a + 1) * 4 - 1
    b = (b + 1) * 4 - 1
    return (a < b ? `
${a}
OP_PICK
${b+1}
OP_ROLL
${a+1}
OP_PICK
${b+2}
OP_ROLL
${a+2}
OP_PICK
${b+3}
OP_ROLL
${a+3}
OP_PICK
${b+4}
OP_ROLL
` : `
${b}
OP_ROLL
${a}
OP_PICK
${b+1}
OP_ROLL
${a}
OP_PICK
${b+2}
OP_ROLL
${a}
OP_PICK
${b+3}
OP_ROLL
${a}
OP_PICK
`) + `
// A0 + B0
${add_bytes_toaltstack}

// A1 + B1 + carry_0
OP_ADD
${add_bytes_toaltstack}

// A2 + B2 + carry_1
OP_ADD
${add_bytes_toaltstack}

// A3 + B3 + carry_2
OP_ADD
OP_ADD
OP_DUP
255
OP_GREATERTHAN
OP_IF
    256
    OP_SUB
OP_ENDIF


OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK

// Now there's the result C_3 C_2 C_1 C_0 on the stack
`
}