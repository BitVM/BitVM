# 2-Bit Commitment
The following is an optimization of the bit commitments described in the BitVM whitepaper. This commitment is more compact as it commits to 2 bits with a single preimage. It still requires 4 hashes in the locking script, however in total it saves 10 bytes per bit commitment.

This trick works for 2 bits because it's a special case in the sense that `2^2 == 2*2`. For 3 or more bits this pattern becomes less efficient than 1-bit commitments.

## Commitment

### Unlocking Script

These are the 4 possible unlocking scripts:

Case `value = 0`:
```
<0>
<0x6f04886ac0d32aa336c6f8804cbad557a473f1e9>
```

Case `value = 1`:
```
<1>
<0x2434749071bf3013552a8d3ee9943336dc79c987>
```

Case `value = 2`:
```
<2>
<0x92ac570a125208e098ab8037a4d3d9769ba52177>
```
Case `value = 3`:
```
<3>
<0x47c31e611a3bd2f3a7a42207613046703fa27493>
```

### Locking Script
```
OP_TOALTSTACK

<3>
OP_MIN  // Sanitize the input. Ensure value < 4

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
```

## Slashing Script

The verifier can slash the prover if they know any 2 preimages of the 4 hashes. 
```
TODO: implementation
```
