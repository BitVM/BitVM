# Equivocation Script 
For every bit commitment, there is a leaf script like the following in the *equivocation taptree*, which allows the verifier to punish the prover in case they equivocate.

## Locking Script 
```
// 
// Equivocation Script
// Vicky can take if she knows both the preimages to hash0 and hash1
// 

OP_RIPEMD160
<0xe0537e5ed908820aaacdd03b3966f3047a405a92>    // hash0
OP_EQUALVERIFY

OP_RIPEMD160
<0x700dcae2d8b396bbc8ed588122f5d7819f20cf05>    // hash1
OP_EQUALVERIFY

<'pubkey_vicky'>
<OP_CHECKSIG>
```


## Unlocking Script 

```
// 
// Inputs
//

// Vicky's signature
<0xddb473f559380e7385dbfcc4d7fa7fcbebb8c66eddb473f559380e7385dbfcc4d7fa7fcbebb8c66eddb473f559380e7385dbfcc4d7fa7fcbebb8c66e>

// preimage1
<0x39c7023cd99be570d4bc3917647c574b5efbaffd>
// preimage0
<0x47c31e611a3bd2f3a7a42207613046703fa27499>
```
