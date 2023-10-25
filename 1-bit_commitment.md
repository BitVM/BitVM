# 1-Bit Commitment 
The following is an optimized form of a bit commitment as described in the BitVM whitepaper. It uses fewer opcodes and doesn't require the unlocking script to provide the bit's value. 

You can test this script by pasting it into [Script Wiz](https://ide.scriptwiz.app).

## Locking Script 
```
OP_HASH160
OP_DUP
<0xf592e757267b7f307324f1e78b34472f8b6f46f3>
OP_EQUAL
OP_DUP

OP_ROT
<0x100b9f19ebd537fdc371fa1367d7ccc802dc2524>
OP_EQUAL

OP_BOOLOR
OP_VERIFY
```

## Unlocking Script 

Case `value = 0`
```
<0xfa7fa5b1dea37d71a0b841967f6a3b119dbea140>
```
Case `value = 1`
```
<0x47c31e611a3bd2f3a7a42207613046703fa27496>
```
