#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;

use bitvm::hash::sha256::{reference_sha256, test_sha256_with};
use bitvm::hash::sha256_u4::test_sha256_u4_with;
use bitvm::hash::sha256_u4_stack::test_sha256_u4_stack_with;

#[derive(Debug)]
struct LimitedBytes(Vec<u8>);

impl<'a> Arbitrary<'a> for LimitedBytes {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let size = u.int_in_range(0..=512)?;
        let mut bytes = vec![0u8; size];
        u.fill_buffer(&mut bytes)?;
        Ok(LimitedBytes(bytes.to_vec()))
    }
}

fuzz_target!(|data: LimitedBytes| {
    let hex_input = hex::encode(&data.0);
    let output = reference_sha256(&data.0);
    let hex_output = hex::encode(output);

    test_sha256_with(&hex_input, &hex_output);
    test_sha256_u4_with(&hex_input, &hex_output);
    test_sha256_u4_stack_with(&hex_input, &hex_output, true, true);
    test_sha256_u4_stack_with(&hex_input, &hex_output, true, false);
    test_sha256_u4_stack_with(&hex_input, &hex_output, false, true);
    test_sha256_u4_stack_with(&hex_input, &hex_output, false, false);
});
