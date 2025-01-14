# BitVM Bridge: A Trust-minimized Bitcoin Bridge

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> [!WARNING]
> DO NOT USE IN PRODUCTION!

The official implementation of [BitVM2](https://bitvm.org/bitvm2),
running a [SNARK verifier](https://bitvm.org/snark).

The code follows the implementation of [Arkworks](https://github.com/arkworks-rs)

## Overview

The repository contains the implementation of a groth16 SNARK verifier that is executable via the optimistic BitVM paradigm on Bitcoin without any soft forks.


It is designed to be modular, allowing developers to reuse bitcoin scripts for u32 data types, hashes and curve operations.

## Components

BitVM is composed of several components.
Below is a list of the components and their purpose.

- [**`u32` Operations**](src/u32/):
  Basic arithmetic operations of `u32` for hash functions,
  including `add`, `sub`, `or`, `xor`, `rotation`, `shift`.

- [**`u4` Operations**](src/u4):
  `u4` version arithmetic operations,
  providing a more efficient way to construct hashes.

- [**Hash Functions**](src/hash/):
  Two types of hash functions:

  - `SHA256`: comparing block headers and measuring Bitcoin difficulty.
  - `BLAKE3`: compressing intermediate states in the chunker.

- [**Big Integer**](src/bigint/):
  Variable-length big integer operations,
  including of `add`, `sub`, `mul`, `div`, `inverse` and other operations.

- [**BN254**](src/bn254/):
  Point expression of BN254 elliptic curves and operations based on BN254,
  including addition, multiplication, pairing.
  The pairing part is related to the "Algorithm 9" in the paper "On Proving Pairings"

- [**Groth16**](src/groth16/):
  Groth16 uses BN254 to verify proof, the script is currently around 1 GB.
  Some hints are precomputed in this part, which is related to the paper "On Proving Pairings".

- [**Chunker**](src/chunker/):
  Splits Groth16 into chunks.
  These chunks make sure two principles:

  1. Any chunks shouldn't be success with a right proof.
  2. There are always some successful chunks with a wrong proof.

- [**Signatures**](src/signatures/):
  Bit commitment using
  [Winternitz signature](https://en.wikipedia.org/wiki/Lamport_signature#Short_keys_and_signature).

- [**Bridge**](src/bridge/):
  Definitions for the context (roles), connectors, Bitcoin transaction construction,
  Bitcoin client wrapper, etc.

## BitVM1

If you are looking for the deprectated BitVM1 implementation, please check out
[BitVM1](https://github.com/BitVM/BitVM/tree/1dce989d1963b90c35391b77b451c6823302d503).
