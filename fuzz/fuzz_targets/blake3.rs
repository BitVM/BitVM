#![no_main]

use libfuzzer_sys::fuzz_target;
use bitvm::hash::blake3_u4_compact::test_blake3_compact_givenbyteslice;

fuzz_target!(|data: &[u8]| {
    test_blake3_compact_givenbyteslice(data);
});
