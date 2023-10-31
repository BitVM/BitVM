//
// Right Rotation by 7 bits
//
const u32_rrot7 = `
// First Byte
OP_DUP
<127>
OP_GREATERTHAN
OP_IF
    <128>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

// Second byte
OP_ROT

OP_DUP
<127>
OP_GREATERTHAN
OP_IF
    <128>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

OP_SWAP
OP_DUP
OP_ADD
OP_ROT
OP_ADD
OP_SWAP


// Third byte

<3>
OP_ROLL

OP_DUP
<127>
OP_GREATERTHAN
OP_IF
    <128>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

OP_SWAP
OP_DUP
OP_ADD
OP_ROT
OP_ADD
OP_SWAP

// Fourth byte


<4>
OP_ROLL

OP_DUP
<127>
OP_GREATERTHAN
OP_IF
    <128>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

OP_SWAP
OP_DUP
OP_ADD
OP_ROT
OP_ADD
OP_SWAP

// Close the circle
<4>
OP_ROLL
OP_DUP
OP_ADD
OP_ADD

OP_SWAP
OP_2SWAP
OP_SWAP
`
