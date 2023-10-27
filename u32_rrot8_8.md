# Rotate a u32 by 8 Bits to the Right
Rotate a u32 (represented as four u8) by 8 bits to the right.

```
// Inputs
<0x8700> // A_3
<0x65>   // A_2
<0x43>   // A_1
<0x21>   // A_0

// Algorithm
<3>
OP_ROLL
<3>
OP_ROLL
<3>
OP_ROLL
```
