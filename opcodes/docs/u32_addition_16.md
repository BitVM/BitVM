# Addition u32

Addition of two u32 values represented as u16 pairs.

## Locking Script
```
// 
// Addition of two u32 values represented as u16
// 

OP_ADD
OP_DUP
<65535>
OP_GREATERTHAN
OP_IF
    <65536>
    OP_SUB
    <1>
OP_ELSE
    <0>
OP_ENDIF

OP_2SWAP

OP_ADD
OP_ADD
OP_DUP
<65535>
OP_GREATERTHAN
OP_IF
    <65536>
    OP_SUB
OP_ENDIF


// Now there's the result's <low> <high> on the stack
```

## Unlocking Script
```
<65535>    // Variable A (high)
<65535>    // Variable B (high)
<65535>    // Variable A (low)
<65535>    // Variable B (low)
```
