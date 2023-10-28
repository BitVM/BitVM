// 
// Addition of two u32 values represented as u8
//  
const u32_add = `
// A0 + B0
OP_ADD
OP_DUP
<255>
OP_GREATERTHAN
OP_IF
    <256>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF
OP_SWAP
OP_TOALTSTACK

// A1 + B1 + carry_0
OP_ADD
OP_ADD
OP_DUP
<255>
OP_GREATERTHAN
OP_IF
    <256>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF
OP_SWAP
OP_TOALTSTACK

// A2 + B2 + carry_1
OP_ADD
OP_ADD
OP_DUP
<255>
OP_GREATERTHAN
OP_IF
    <256>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF
OP_SWAP
OP_TOALTSTACK

// A3 + B3 + carry_2
OP_ADD
OP_ADD
OP_DUP
<255>
OP_GREATERTHAN
OP_IF
    <256>
    OP_SUB
OP_ENDIF


OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK

// Now there's the result C_3 C_2 C_1 C_0 on the stack
`
