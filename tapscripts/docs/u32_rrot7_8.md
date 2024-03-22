# Rotate a u32 by 7 Bits to the Right

```
// Input

<206>   // A_3
<155>   // A_2
<253>   // A_1
<140>   // A_0


//
// Right Rotation by 7 bits
//

// First Byte
OP_DUP
OP_ADD

OP_DUP
<256>
OP_GREATERTHANOREQUAL
OP_IF
    <256>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

// Second byte
OP_ROT

OP_DUP
OP_ADD

OP_DUP
<256>
OP_GREATERTHANOREQUAL
OP_IF
    <256>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

OP_SWAP
OP_ROT
OP_ADD
OP_SWAP


// Third byte

<3>
OP_ROLL

OP_DUP
OP_ADD

OP_DUP
<256>
OP_GREATERTHANOREQUAL
OP_IF
    <256>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

OP_SWAP
OP_ROT
OP_ADD
OP_SWAP

// Fourth byte


<4>
OP_ROLL

OP_DUP
OP_ADD

OP_DUP
<256>
OP_GREATERTHANOREQUAL
OP_IF
    <256>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

OP_SWAP
OP_ROT
OP_ADD
OP_SWAP

// Close the circle
<4>
OP_ROLL
OP_ADD

OP_SWAP
OP_2SWAP
OP_SWAP

// B_3 B_2 B_1 B_0 
```
