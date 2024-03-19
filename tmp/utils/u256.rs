#![allow(non_camel_case_types)]

pub type u256 = [u32; 8];

pub fn from_bytes(bytes: [u8; 32]) -> u256 {
    let mut u256 = [0, 0, 0, 0, 0, 0, 0, 0];
    for n in 0..8 {
        let mut u32 = [0u8; 4];
        u32.copy_from_slice(&bytes[n*4..n*4+4]);
        u256[n] = u32::from_le_bytes(u32);
    }
    u256
}