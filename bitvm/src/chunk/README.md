Steps to test:
1. Generate Partial Scripts
RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_compile --exact --nocapture
2. Generate Assertions
RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_generate_assertions --exact --nocapture 
3. Validate generated Assertions
RUST_MIN_STACK=104857600 RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_validate_assertions --exact --nocapture
4. Manually Corrupt each Assertion one at a time and Disprove invalid assertion
RUST_MIN_STACK=104857600 RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_disprove_invalid_assertions --exact --nocapture  


Contents:
api - interface between verifier and external module (like bridge)
assert - functions to generate intermediate values in each chunks used during assertion or disprove
assigner - interface to assign Assertions
blake3compiled - wrapper to blake3_u4 hasher
compile - functions to generate tapscripts
elements - data structure to represent inputs and outputs of each chunk
primitives - utility functions [will likely refactor]
segment - data structure to represent each chunk [script, inputs and outputs, identifiers]
taps_msm - tapscripts for MSM
taps_mul - tapscripts for Fp12 multiplications
taps_point_ops - tapscripts for point operations
taps_premiller - miscellaneous tapscripts external to Miller Loop
wots - wrapper to winternitz methods