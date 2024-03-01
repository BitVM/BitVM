# u8 State Commitment 

This is a commitment to an `u8` value, consisting of four 2-byte commitments.

## Unlocking Script

Warning! For testing purposes, we reuse the hashes of the 2-bit commitments four times here. Don't do that in production. All hashes here should be unique.

```
// Bit 1 and 2

OP_TOALTSTACK

OP_DUP
OP_TOALTSTACK 

<0xdbe3777a6cc1bbcd481580a881964ecc5f7dd0fa>  // hash3
<0x851f9ce32df59ce2b31949fa532f99897cb93a21>  // hash2
<0x64c0aecf341a67d09475a6dd9f4650ca723f1354>  // hash1
<0x626bb6102f6c9f252c02cc562825b85468887e3b>  // hash0

OP_FROMALTSTACK
OP_ROLL

OP_FROMALTSTACK
OP_HASH160
OP_EQUALVERIFY

OP_2DROP
OP_DROP

OP_TOALTSTACK



// Bit 3 and 4

OP_TOALTSTACK

OP_DUP
OP_TOALTSTACK

<0xdbe3777a6cc1bbcd481580a881964ecc5f7dd0fa>  // hash3
<0x851f9ce32df59ce2b31949fa532f99897cb93a21>  // hash2
<0x64c0aecf341a67d09475a6dd9f4650ca723f1354>  // hash1
<0x626bb6102f6c9f252c02cc562825b85468887e3b>  // hash0

OP_FROMALTSTACK
OP_ROLL

OP_FROMALTSTACK
OP_HASH160
OP_EQUALVERIFY

OP_2DROP
OP_DROP

OP_FROMALTSTACK
OP_DUP
OP_ADD
OP_DUP
OP_ADD
OP_ADD
OP_TOALTSTACK


// Bit 5 and 6

OP_TOALTSTACK

OP_DUP
OP_TOALTSTACK

<0xdbe3777a6cc1bbcd481580a881964ecc5f7dd0fa>  // hash3
<0x851f9ce32df59ce2b31949fa532f99897cb93a21>  // hash2
<0x64c0aecf341a67d09475a6dd9f4650ca723f1354>  // hash1
<0x626bb6102f6c9f252c02cc562825b85468887e3b>  // hash0

OP_FROMALTSTACK
OP_ROLL

OP_FROMALTSTACK
OP_HASH160
OP_EQUALVERIFY

OP_2DROP
OP_DROP

OP_FROMALTSTACK
OP_DUP
OP_ADD
OP_DUP
OP_ADD
OP_ADD
OP_TOALTSTACK



// Bit 7 and 8

OP_TOALTSTACK

OP_DUP
OP_TOALTSTACK

<0xdbe3777a6cc1bbcd481580a881964ecc5f7dd0fa>  // hash3
<0x851f9ce32df59ce2b31949fa532f99897cb93a21>  // hash2
<0x64c0aecf341a67d09475a6dd9f4650ca723f1354>  // hash1
<0x626bb6102f6c9f252c02cc562825b85468887e3b>  // hash0

OP_FROMALTSTACK
OP_ROLL

OP_FROMALTSTACK
OP_HASH160
OP_EQUALVERIFY

OP_2DROP
OP_DROP

OP_FROMALTSTACK
OP_DUP
OP_ADD
OP_DUP
OP_ADD
OP_ADD

// Now there's the u8 value on the stack
```

## Unlocking Script

Unlocking the four 2-bit commitments. This example, `(0,1,2,3)`, puts the value `228` on the stack, (which is `11 10 01 00` in binary).

```
<0>
<0x6f04886ac0d32aa336c6f8804cbad557a473f1e9>

<1>
<0x2434749071bf3013552a8d3ee9943336dc79c987>

<2>
<0x92ac570a125208e098ab8037a4d3d9769ba52177>

<3>
<0x47c31e611a3bd2f3a7a42207613046703fa27493>

```
