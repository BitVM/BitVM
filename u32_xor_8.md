# Bitwise XOR u32

Bitwise XOR for two u32 words, implemented with a [lookup table for u8 words](u8_xor.md).

## Unlocking Script

```
<85>
<85>
<84>
<84>
<85>
<85>
<84>
<84>
<81>
<81>
<80>
<80>
<81>
<81>
<80>
<80>

<85>
<85>
<84>
<84>
<85>
<85>
<84>
<84>
<81>
<81>
<80>
<80>
<81>
<81>
<80>
<80>

<69>
<69>
<68>
<68>
<69>
<69>
<68>
<68>
<65>
<65>
<64>
<64>
<65>
<65>
<64>
<64>

<69>
<69>
<68>
<68>
<69>
<69>
<68>
<68>
<65>
<65>
<64>
<64>
<65>
<65>
<64>
<64>

<85>
<85>
<84>
<84>
<85>
<85>
<84>
<84>
<81>
<81>
<80>
<80>
<81>
<81>
<80>
<80>

<85>
<85>
<84>
<84>
<85>
<85>
<84>
<84>
<81>
<81>
<80>
<80>
<81>
<81>
<80>
<80>

<69>
<69>
<68>
<68>
<69>
<69>
<68>
<68>
<65>
<65>
<64>
<64>
<65>
<65>
<64>
<64>

<69>
<69>
<68>
<68>
<69>
<69>
<68>
<68>
<65>
<65>
<64>
<64>
<65>
<65>
<64>
<64>

<21>
<21>
<20>
<20>
<21>
<21>
<20>
<20>
<17>
<17>
<16>
<16>
<17>
<17>
<16>
<16>

<21>
<21>
<20>
<20>
<21>
<21>
<20>
<20>
<17>
<17>
<16>
<16>
<17>
<17>
<16>
<16>

<05>
<05>
<04>
<04>
<05>
<05>
<04>
<04>
<01>
<01>
<00>
<00>
<01>
<01>
<00>
<00>

<05>
<05>
<04>
<04>
<05>
<05>
<04>
<04>
<01>
<01>
<00>
<00>
<01>
<01>
<00>
<00>

<21>
<21>
<20>
<20>
<21>
<21>
<20>
<20>
<17>
<17>
<16>
<16>
<17>
<17>
<16>
<16>

<21>
<21>
<20>
<20>
<21>
<21>
<20>
<20>
<17>
<17>
<16>
<16>
<17>
<17>
<16>
<16>

<05>
<05>
<04>
<04>
<05>
<05>
<04>
<04>
<01>
<01>
<00>
<00>
<01>
<01>
<00>
<00>

<05>
<05>
<04>
<04>
<05>
<05>
<04>
<04>
<01>
<01>
<00>
<00>
<01>
<01>
<00>
<00>


<0x55>      // Input B3
<0xAA00>    // Input A3
<0x55>      // Input B2
<0xAA00>    // Input A2
<0xff00>    // Input B1
<0xff00>    // Input A1
<0x55>      // Input B0
<0xAA00>    // Input A0


// f_A = f(A)
OP_DUP
<8>
OP_ADD
OP_PICK
// Stack: B, A, f(A)

// A_even = f_A << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: B, A, f(A), A_even

// A_odd = A - A_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: B, f(A), A_odd

// f_B = f(B)
OP_ROT
OP_DUP
<9>
OP_ADD
OP_PICK
// Stack: f(A), A_odd, B, f(B)

// B_even = f_B << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: f(A), A_odd, B, f(B), B_even

// B_odd = B - B_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: f(A), A_odd, f(B), B_odd

// A_andxor_B_even = f_A + f_B
OP_SWAP
<3>
OP_ROLL
OP_ADD
// Stack: A_odd, B_odd, A_andxor_B_even

// A_xor_B_even = A_andxor_B_even - (f(A_andxor_B_even) << 1)
OP_DUP
<9>
OP_ADD
OP_PICK
OP_DUP
OP_ADD
OP_SUB
// Stack: A_odd, B_odd, A_xor_B_even

// A_andxor_B_odd = A_odd + B_odd
OP_SWAP
OP_ROT
OP_ADD
// Stack: A_xor_B_even, A_andxor_B_odd

// A_xor_B_odd = A_andxor_B_odd - (f(A_andxor_B_odd) << 1)
OP_DUP
<8>
OP_ADD
OP_PICK
OP_DUP
OP_ADD
OP_SUB
// Stack: A_xor_B_even, A_xor_B_odd

// A_xor_B = A_xor_B_odd + (A_xor_B_even << 1)
OP_SWAP
OP_DUP
OP_ADD
OP_ADD
// Stack: A_xor_B

OP_TOALTSTACK





// f_A = f(A)
OP_DUP
<6>
OP_ADD
OP_PICK
// Stack: B, A, f(A)

// A_even = f_A << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: B, A, f(A), A_even

// A_odd = A - A_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: B, f(A), A_odd

// f_B = f(B)
OP_ROT
OP_DUP
<7>
OP_ADD
OP_PICK
// Stack: f(A), A_odd, B, f(B)

// B_even = f_B << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: f(A), A_odd, B, f(B), B_even

// B_odd = B - B_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: f(A), A_odd, f(B), B_odd

// A_andxor_B_even = f_A + f_B
OP_SWAP
<3>
OP_ROLL
OP_ADD
// Stack: A_odd, B_odd, A_andxor_B_even

// A_xor_B_even = A_andxor_B_even - (f(A_andxor_B_even) << 1)
OP_DUP
<7>
OP_ADD
OP_PICK
OP_DUP
OP_ADD
OP_SUB
// Stack: A_odd, B_odd, A_xor_B_even

// A_andxor_B_odd = A_odd + B_odd
OP_SWAP
OP_ROT
OP_ADD
// Stack: A_xor_B_even, A_andxor_B_odd

// A_xor_B_odd = A_andxor_B_odd - (f(A_andxor_B_odd) << 1)
OP_DUP
<6>
OP_ADD
OP_PICK
OP_DUP
OP_ADD
OP_SUB
// Stack: A_xor_B_even, A_xor_B_odd

// A_xor_B = A_xor_B_odd + (A_xor_B_even << 1)
OP_SWAP
OP_DUP
OP_ADD
OP_ADD
// Stack: A_xor_B

OP_TOALTSTACK



// f_A = f(A)
OP_DUP
<4>
OP_ADD
OP_PICK
// Stack: B, A, f(A)

// A_even = f_A << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: B, A, f(A), A_even

// A_odd = A - A_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: B, f(A), A_odd

// f_B = f(B)
OP_ROT
OP_DUP
<5>
OP_ADD
OP_PICK
// Stack: f(A), A_odd, B, f(B)

// B_even = f_B << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: f(A), A_odd, B, f(B), B_even

// B_odd = B - B_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: f(A), A_odd, f(B), B_odd

// A_andxor_B_even = f_A + f_B
OP_SWAP
<3>
OP_ROLL
OP_ADD
// Stack: A_odd, B_odd, A_andxor_B_even

// A_xor_B_even = A_andxor_B_even - (f(A_andxor_B_even) << 1)
OP_DUP
<5>
OP_ADD
OP_PICK
OP_DUP
OP_ADD
OP_SUB
// Stack: A_odd, B_odd, A_xor_B_even

// A_andxor_B_odd = A_odd + B_odd
OP_SWAP
OP_ROT
OP_ADD
// Stack: A_xor_B_even, A_andxor_B_odd

// A_xor_B_odd = A_andxor_B_odd - (f(A_andxor_B_odd) << 1)
OP_DUP
<4>
OP_ADD
OP_PICK
OP_DUP
OP_ADD
OP_SUB
// Stack: A_xor_B_even, A_xor_B_odd

// A_xor_B = A_xor_B_odd + (A_xor_B_even << 1)
OP_SWAP
OP_DUP
OP_ADD
OP_ADD
// Stack: A_xor_B

OP_TOALTSTACK



// f_A = f(A)
OP_DUP
<2>
OP_ADD
OP_PICK
// Stack: B, A, f(A)

// A_even = f_A << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: B, A, f(A), A_even

// A_odd = A - A_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: B, f(A), A_odd

// f_B = f(B)
OP_ROT
OP_DUP
<3>
OP_ADD
OP_PICK
// Stack: f(A), A_odd, B, f(B)

// B_even = f_B << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: f(A), A_odd, B, f(B), B_even

// B_odd = B - B_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: f(A), A_odd, f(B), B_odd

// A_andxor_B_even = f_A + f_B
OP_SWAP
<3>
OP_ROLL
OP_ADD
// Stack: A_odd, B_odd, A_andxor_B_even

// A_xor_B_even = A_andxor_B_even - (f(A_andxor_B_even) << 1)
OP_DUP
<2>
OP_ADD
OP_PICK
OP_DUP
OP_ADD
OP_SUB
// Stack: A_odd, B_odd, A_xor_B_even

// A_andxor_B_odd = A_odd + B_odd
OP_SWAP
OP_ROT
OP_ADD
// Stack: A_xor_B_even, A_andxor_B_odd

// A_xor_B_odd = A_andxor_B_odd - (f(A_andxor_B_odd) << 1)
OP_DUP
<2>
OP_ADD
OP_PICK
OP_DUP
OP_ADD
OP_SUB
// Stack: A_xor_B_even, A_xor_B_odd

// A_xor_B = A_xor_B_odd + (A_xor_B_even << 1)
OP_SWAP
OP_DUP
OP_ADD
OP_ADD
// Stack: A_xor_B



OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK

```
