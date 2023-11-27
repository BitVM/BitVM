# Reveal a 2-bit Commitment

Reveal the value of a 2-bit commitment. This is useful to commit to a particular value to be able to perform some computation with the value in a set of potential subsequent transactions.

```



//
// Example input, preimage3 
//
<0x47c31e611a3bd2f3a7a42207613046703fa27493>

//
// Program
//

OP_HASH160

OP_DUP
<0xdbe3777a6cc1bbcd481580a881964ecc5f7dd0fa>  // hash3
OP_EQUAL

OP_OVER
<0x851f9ce32df59ce2b31949fa532f99897cb93a21>  // hash2
OP_EQUAL
OP_BOOLOR

OP_OVER
<0x64c0aecf341a67d09475a6dd9f4650ca723f1354>  // hash1
OP_EQUAL
OP_BOOLOR

OP_SWAP
<0x626bb6102f6c9f252c02cc562825b85468887e3b>  // hash0
OP_EQUAL
OP_BOOLOR
OP_VERIFY
```