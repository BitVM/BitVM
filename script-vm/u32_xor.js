const u32_xor = stackSize => `
// f_A = f(A)
OP_DUP
<${8 + (stackSize - 2)*4}>
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
<${9 + (stackSize - 2)*4}>
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
<${9 + (stackSize - 2)*4}>
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
<${8 + (stackSize - 2)*4}>
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
<${6 + (stackSize - 2)*4}>
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
<${7 + (stackSize - 2)*4}>
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
<${7 + (stackSize - 2)*4}>
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
<${6 + (stackSize - 2)*4}>
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
<${4 + (stackSize - 2)*4}>
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
<${5 + (stackSize - 2)*4}>
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
<${5 + (stackSize - 2)*4}>
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
<${4 + (stackSize - 2)*4}>
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
<${2 + (stackSize - 2)*4}>
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
<${3 + (stackSize - 2)*4}>
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
<${3 + (stackSize - 2)*4}>
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
<${2 + (stackSize - 2)*4}>
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
`







const u32_push_xor_table = `

//
// Push XOR Table
//

<85>
OP_DUP
<84>
OP_DUP
<85>
OP_DUP
<84>
OP_DUP
<81>
OP_DUP
<80>
OP_DUP
<81>
OP_DUP
<80>
OP_DUP

<85>
OP_DUP
<84>
OP_DUP
<85>
OP_DUP
<84>
OP_DUP
<81>
OP_DUP
<80>
OP_DUP
<81>
OP_DUP
<80>
OP_DUP

<69>
OP_DUP
<68>
OP_DUP
<69>
OP_DUP
<68>
OP_DUP
<65>
OP_DUP
<64>
OP_DUP
<65>
OP_DUP
<64>
OP_DUP

<69>
OP_DUP
<68>
OP_DUP
<69>
OP_DUP
<68>
OP_DUP
<65>
OP_DUP
<64>
OP_DUP
<65>
OP_DUP
<64>
OP_DUP

<85>
OP_DUP
<84>
OP_DUP
<85>
OP_DUP
<84>
OP_DUP
<81>
OP_DUP
<80>
OP_DUP
<81>
OP_DUP
<80>
OP_DUP

<85>
OP_DUP
<84>
OP_DUP
<85>
OP_DUP
<84>
OP_DUP
<81>
OP_DUP
<80>
OP_DUP
<81>
OP_DUP
<80>
OP_DUP

<69>
OP_DUP
<68>
OP_DUP
<69>
OP_DUP
<68>
OP_DUP
<65>
OP_DUP
<64>
OP_DUP
<65>
OP_DUP
<64>
OP_DUP

<69>
OP_DUP
<68>
OP_DUP
<69>
OP_DUP
<68>
OP_DUP
<65>
OP_DUP
<64>
OP_DUP
<65>
OP_DUP
<64>
OP_DUP

<21>
OP_DUP
<20>
OP_DUP
<21>
OP_DUP
<20>
OP_DUP
<17>
OP_DUP
<16>
OP_DUP
<17>
OP_DUP
<16>
OP_DUP

<21>
OP_DUP
<20>
OP_DUP
<21>
OP_DUP
<20>
OP_DUP
<17>
OP_DUP
<16>
OP_DUP
<17>
OP_DUP
<16>
OP_DUP

<05>
OP_DUP
<04>
OP_DUP
<05>
OP_DUP
<04>
OP_DUP
<01>
OP_DUP
<00>
OP_DUP
<01>
OP_DUP
<00>
OP_DUP

<05>
OP_DUP
<04>
OP_DUP
<05>
OP_DUP
<04>
OP_DUP
<01>
OP_DUP
<00>
OP_DUP
<01>
OP_DUP
<00>
OP_DUP

<21>
OP_DUP
<20>
OP_DUP
<21>
OP_DUP
<20>
OP_DUP
<17>
OP_DUP
<16>
OP_DUP
<17>
OP_DUP
<16>
OP_DUP

<21>
OP_DUP
<20>
OP_DUP
<21>
OP_DUP
<20>
OP_DUP
<17>
OP_DUP
<16>
OP_DUP
<17>
OP_DUP
<16>
OP_DUP

<05>
OP_DUP
<04>
OP_DUP
<05>
OP_DUP
<04>
OP_DUP
<01>
OP_DUP
<00>
OP_DUP
<01>
OP_DUP
<00>
OP_DUP

<05>
OP_DUP
<04>
OP_DUP
<05>
OP_DUP
<04>
OP_DUP
<01>
OP_DUP
<00>
OP_DUP
<01>
OP_DUP
<00>
OP_DUP
`

const u32_drop_xor_table = `

//
// Drop XOR Table
//

OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP

OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP

OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP

OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP

OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP

OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP

OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP

OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
`