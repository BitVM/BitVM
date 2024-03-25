#![allow(dead_code)]
use bitcoin::ScriptBuf as Script;
use super::{pushable, unroll};
use bitcoin_script::bitcoin_script as script;

/// Pushes a value as u256 element onto the stack
pub fn u256_push(value: [u8; 32]) -> Script {
    // Convert big endian byte array to shorts
    let mut fixed_value = [[0u8; 2]; 16];
    fixed_value[0].copy_from_slice(&value[0..2]);
    fixed_value[1].copy_from_slice(&value[2..4]);
    fixed_value[2].copy_from_slice(&value[4..6]);
    fixed_value[3].copy_from_slice(&value[6..8]);
    fixed_value[4].copy_from_slice(&value[8..10]);
    fixed_value[5].copy_from_slice(&value[10..12]);
    fixed_value[6].copy_from_slice(&value[12..14]);
    fixed_value[7].copy_from_slice(&value[14..16]);
    fixed_value[8].copy_from_slice(&value[16..18]);
    fixed_value[9].copy_from_slice(&value[18..20]);
    fixed_value[10].copy_from_slice(&value[20..22]);
    fixed_value[11].copy_from_slice(&value[22..24]);
    fixed_value[12].copy_from_slice(&value[24..26]);
    fixed_value[13].copy_from_slice(&value[26..28]);
    fixed_value[14].copy_from_slice(&value[28..30]);
    fixed_value[15].copy_from_slice(&value[30..32]);
    let value_as_u16_array: [u16; 16] = [
        u16::from_be_bytes(fixed_value[0]),
        u16::from_be_bytes(fixed_value[1]),
        u16::from_be_bytes(fixed_value[2]),
        u16::from_be_bytes(fixed_value[3]),
        u16::from_be_bytes(fixed_value[4]),
        u16::from_be_bytes(fixed_value[5]),
        u16::from_be_bytes(fixed_value[6]),
        u16::from_be_bytes(fixed_value[7]),
        u16::from_be_bytes(fixed_value[8]),
        u16::from_be_bytes(fixed_value[9]),
        u16::from_be_bytes(fixed_value[10]),
        u16::from_be_bytes(fixed_value[11]),
        u16::from_be_bytes(fixed_value[12]),
        u16::from_be_bytes(fixed_value[13]),
        u16::from_be_bytes(fixed_value[14]),
        u16::from_be_bytes(fixed_value[15]),
    ];
    script! {
        {unroll(16, |i| script! { {value_as_u16_array[15 - i as usize] as u32} })}
    }
}
// NOTE: May chunk input value as [u32; 5]