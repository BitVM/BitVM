# Commit to a Bit Value using a Schnorr Signature

This is a bit commitment (e.g. for BitVM) which allows you to commit to the value of a 1-bit variable across two different UTXOs via Schnorr signatures. If Paul equivocates on the bit's value then he leaks his private key.

Surprisingly, the commitment script doesn't need to commit to anything specific. All semantics arise from the nonces in the partial signatures. That allows you to reprogram gates after compile time.

## Commitment Script

The commitment script uses `OP_CODESEPARATOR` such that public key `P` can sign off on one of two execution branches in the script. Depending on which branch is signed, the script leaves `0` or `1` on the stack.

```
OP_IF   
    OP_CODESEPARATOR       // This is branch_1
    <1> 
OP_ELSE
    OP_CODESEPARATOR       // This is branch_0
    <0> 
OP_ENDIF
OP_SWAP

<joined_pubkey_P>
OP_CHECKSIGVERIFY
```

which can get unlocked with 

```
<signature_for_branch_0>
<0>
```
or 
```
<signature_for_branch_1>
<1>
```


## Presigning
The MuSig scheme allows the verifier to force the prover to use for their partial signature one of two nonces `nonceX` and `nonceY`.
The verifier creates four partial signatures. For both script branches `0` and `1` for both scripts `scriptA` and `scriptB`.


```
scriptA "0" nonceX
scriptA "1" nonceY
```

The `scriptB` is signed with inverted nonces: 
```
scriptB "0" nonceY
scriptB "1" nonceX
```

This ensures the prover cannot sign different values for scriptA and scriptB without reusing a nonce. This leaks his key.

## Details

### 2-of-2 Signatures
The equations for a 2-of-2 MuSig for Vicky `P1 = x1 G` and Paul `P2 = x2 G` with their joint key `P = P1 + P2`

Public nonces
```
R1 = r1 G
R2 = r2 G

R = R1 + R2
```

(for the sake of simplicity we don't delinearize the nonces here. However, that's probably necessary in practice. )

Partial signatures
```

s1 = r1 + H(R | P | m) * x1 
s2 = r2 + H(R | P | m) * x2

s = s1 + s2
```

### Vicky's Pre-Signed Partial Signatures
Vicky pre-signs four partial signatures because there are two transactions each having two branches, "branch_0" and "branch_1". For herself, she uses *four* different nonces, `r_a0, r_a1, r_b0, r_b1`, however, for Paul she uses only *two* different nonces, `R_x, R_y`.

```
scriptA:
s_a0 = r_a0 + H( R_a0 + R_x | P | "branch_0 of scriptA" ) * x1
s_a1 = r_a1 + H( R_a1 + R_y | P | "branch_1 of scriptA" ) * x1

scriptB:
s_b0 = r_b0 + H( R_b0 + R_y | P | "branch_0 of scriptB" ) * x1
s_b1 = r_b1 + H( R_b1 + R_x | P | "branch_1 of scriptB" ) * x1
```

If Paul completes signatures for `scriptA` and `scriptB` with conflicting bit commitment values, then he reuses a nonce, which leaks his key, and Vicky can use it to slash him.

For example, Paul could choose with his partial signature for scriptA the value `1`: 
```
s_a1' = r_y + H( R_a1 + R_y | P | "branch_1 of scriptA" ) * x2
```
and for scriptB he chooses the conflicting value `0`:

```
s_b0' = r_y + H( R_a1 + R_y | P | "branch_0 of scriptB" ) * x2
```

which forces him to reuse his secret nonce `r_y`. This leaks his key `x2`.
