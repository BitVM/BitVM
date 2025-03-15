#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;

use bitvm::hash::{sha256, sha256_u4, sha256_u4_stack};

#[derive(Debug)]
struct LimitedBytesSha256(Vec<u8>);

impl<'a> Arbitrary<'a> for LimitedBytesSha256 {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let size = u.int_in_range(0..=sha256::INPUT_N_BYTES_LIMIT)?;
        let mut bytes = vec![0u8; size];
        u.fill_buffer(&mut bytes)?;
        Ok(Self(bytes.to_vec()))
    }
}

#[derive(Debug)]
struct LimitedBytesSha256U4(Vec<u8>);

impl<'a> Arbitrary<'a> for LimitedBytesSha256U4 {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let size = u.int_in_range(0..=sha256_u4::INPUT_N_BYTES_LIMIT)?;
        let mut bytes = vec![0u8; size];
        u.fill_buffer(&mut bytes)?;
        Ok(Self(bytes.to_vec()))
    }
}

#[derive(Debug)]
struct LimitedBytesSha256U4Stack(Vec<u8>);

impl<'a> Arbitrary<'a> for LimitedBytesSha256U4Stack {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let size = u.int_in_range(0..=sha256_u4_stack::INPUT_N_BYTES_LIMIT)?;
        let mut bytes = vec![0u8; size];
        u.fill_buffer(&mut bytes)?;
        Ok(Self(bytes.to_vec()))
    }
}

fuzz_target!(|data: LimitedBytesSha256| {
    let hex_input = hex::encode(&data.0);
    let output = sha256::reference_sha256(&data.0);
    let hex_output = hex::encode(output);

    sha256::test_sha256_with(&hex_input, &hex_output);
});

fuzz_target!(|data: LimitedBytesSha256U4| {
    let hex_input = hex::encode(&data.0);
    let output = sha256::reference_sha256(&data.0);
    let hex_output = hex::encode(output);

    sha256_u4::test_sha256_u4_with(&hex_input, &hex_output);
});

fuzz_target!(|data: LimitedBytesSha256U4Stack| {
    let hex_input = hex::encode(&data.0);
    let output = sha256::reference_sha256(&data.0);
    let hex_output = hex::encode(output);

    sha256_u4_stack::test_sha256_u4_stack_with(&hex_input, &hex_output, true, true);
    sha256_u4_stack::test_sha256_u4_stack_with(&hex_input, &hex_output, true, false);
    sha256_u4_stack::test_sha256_u4_stack_with(&hex_input, &hex_output, false, true);
    sha256_u4_stack::test_sha256_u4_stack_with(&hex_input, &hex_output, false, false);
});
