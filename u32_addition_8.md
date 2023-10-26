# Addition u32 

Addition of two u32 values represented as u8 chunks.

## Locking Script
```
// 
// Addition of two u32 values represented as u8
// 

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

```

## Unlocking Script
```
<255>   // A_3
<0>     // B_3
<255>   // A_2
<0>     // B_2
<128>   // A_1
<128>   // B_1
<0>     // A_0
<0>     // B_0
```
