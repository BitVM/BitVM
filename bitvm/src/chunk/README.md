Steps to test:
1. Generate Partial Scripts
RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_compile --exact --nocapture
2. Generate Assertions
RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_generate_assertions --exact --nocapture 
3. Validate generated Assertions
RUST_MIN_STACK=104857600 RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_validate_assertions --exact --nocapture
4. Manually Corrupt each Assertion one at a time and Disprove invalid assertion
RUST_MIN_STACK=104857600 RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_disprove_invalid_assertions --exact --nocapture  