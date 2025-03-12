#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;

use bitvm::hash::blake3::verify_blake_output;

/// This struct will hold up to 1024 bytes of fuzz data.
#[derive(Debug)]
struct LimitedBytes(Vec<u8>);

impl<'a> Arbitrary<'a> for LimitedBytes {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // we want to confine length of byte array to 1024
        let size = u.int_in_range(0..=1024)?;
        let mut bytes = vec![0u8; size];
        u.fill_buffer(&mut bytes)?;
        Ok(LimitedBytes(bytes.to_vec()))
    }
}

fuzz_target!(|data: LimitedBytes| {
    let expected_hash = blake3::hash(&message).as_bytes().clone();
    verify_blake_output(&data.0, expected_hash);
});
