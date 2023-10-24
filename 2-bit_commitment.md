# 2-Bit Commitment
The following is an optimization of bit commitments as described in the BitVM whitepaper. This commitment allows you to commit to 2 bits with a single preimage. It still requires 4 hashes in the locking script, but in total it safes 10 bytes per bit commitment.

This trick works for 2 bits because it's a special case in the sense that `2^2 == 2*2`.

## Commitment

### Unlocking Script
```
// <0>
// <0x6f04886ac0d32aa336c6f8804cbad557a473f1e9>

// <1>
// <0x2434749071bf3013552a8d3ee9943336dc79c987>

<2>
<0xdbe3777a6cc1bbcd481580a881964ecc5f7dd0fa>


// <3>
// <0x47c31e611a3bd2f3a7a42207613046703fa27493>
```

### Locking Script
```
OP_TOALTSTACK

OP_DUP
OP_TOALTSTACK

<0xdbe3777a6cc1bbcd481580a881964ecc5f7dd0fa>
<0x090645121b7f5c69aa57a4f86401bcc73f93da70>
<0x64c0aecf341a67d09475a6dd9f4650ca723f1354>
<0x626bb6102f6c9f252c02cc562825b85468887e3b>

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
