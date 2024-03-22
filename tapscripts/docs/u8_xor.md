# Bitwise XOR u8

Bitwise XOR for two u8 words, implemented with a lookup table for the helper function 
```
f(x) = (x & 0b10101010) >> 1
```
, which allows us in combination with OP_ADD and OP_SUB, to express bitwise XOR.

## Python Code
For simplicity, here's the algorithm in Python
```python
# Inputs
A = 0b00101010
B = 0b10100100

def f(x):
	return (x & 0b10101010) >> 1

# Algorithm 
f_A = f(A)
A_even = f_A << 1
A_odd = A - A_even

f_B = f(B)
B_even = f_B << 1
B_odd = B - B_even

A_andxor_B_even = f_A + f_B
A_xor_B_even = A_andxor_B_even - (f(A_andxor_B_even) << 1)

A_andxor_B_odd = A_odd + B_odd
A_xor_B_odd = A_andxor_B_odd - (f(A_andxor_B_odd) << 1)

A_xor_B = A_xor_B_odd + (A_xor_B_even << 1)

print(bin(A_xor_B))
```

## Locking Script
```

// Our lookup table for f(x) = (x & 0b10101010) >> 1
// We can reuse it for arbitrarily many calls of XOR 
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


<0x55>      // Input B
<0xAA00>    // Input A

// f_A = f(A)
OP_DUP
<2>
OP_ADD
OP_PICK
// Stack: B, A, f_A

// A_even = f_A << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: B, A, f_A, A_even

// A_odd = A - A_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: B, f_A, A_odd

// f_B = f(B)
OP_ROT
OP_DUP
<3>
OP_ADD
OP_PICK
// Stack: f_A, A_odd, B, f_B

// B_even = f_B << 1
OP_DUP
OP_DUP
OP_ADD
// Stack: f_A, A_odd, B, f_B, B_even

// B_odd = B - B_even
OP_ROT
OP_SWAP
OP_SUB
// Stack: f_A, A_odd, f_B, B_odd

// A_andxor_B_even = f_A + f_B
OP_SWAP
<3>
OP_ROLL
OP_ADD
// Stack: A_odd, B_odd, A_andxor_B_even

// A_xor_B_even = A_andxor_B_even - (f(A_andxor_B_even) << 1)
OP_DUP
<3>
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
```
