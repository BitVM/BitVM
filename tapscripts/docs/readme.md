# Tapscripts

A collection of low-level Bitcoin Scripts for BitVM. There are mainly two types of scripts: bit commitments (Lamport signatures) and u32 instructions. The instructions are designed to implement hash functions such as Blake2s and [Blake3](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf). They include

- u32 addition
- u32 XOR
- u32 rotations (rotate to the right by 7, 8, 12, and 16 bits)


The scripts are developed using our [Script Interpreter](https://bitvm.github.io/BitVM/run/interpreter.html) and also [Script Wiz](https://ide.scriptwiz.app).
