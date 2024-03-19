#![allow(non_camel_case_types)]

pub type u160 = [u32; 5];

pub fn from_hex(hex_string: &str) -> u160 {
    let mut u160 = [0, 0, 0, 0, 0];
    let mut index = 0;
    for char in hex_string.chars().rev() {
        u160[40 - hex_string.len() + index >> 3] |= u32::from_str_radix(&format!("{char}"), 16).unwrap() << (index % 8 << 2);
        index += 1;
    }
    u160
}

pub fn from_le_bytes(bytes: [u8; 20]) -> u160 {
    let mut u160: u160 = [0, 0, 0, 0, 0];
    let mut index = 0;
    for bytes in bytes.chunks_exact(4) {
        let mut uint32 = [0u8; 4];
        uint32.copy_from_slice(bytes);
        u160[index] = u32::from_le_bytes(uint32);
        index += 1;
    }
    u160
}

pub fn from_be_bytes(bytes: [u8; 20]) -> u160 {
    let mut u160: u160 = [0, 0, 0, 0, 0];
    let mut index = 4;
    for bytes in bytes.chunks_exact(4) {
        let mut uint32 = [0u8; 4];
        uint32.copy_from_slice(bytes);
        u160[index] = u32::from_be_bytes(uint32);
        index -= 1;
    }
    u160
}

pub fn to_bytes(uint160: u160) -> [u8; 20] {
    let mut bytes = [0u8; 20];
    bytes[0..4].copy_from_slice(&uint160[0].to_le_bytes());
    bytes[4..8].copy_from_slice(&uint160[1].to_le_bytes());
    bytes[8..12].copy_from_slice(&uint160[2].to_le_bytes());
    bytes[12..16].copy_from_slice(&uint160[3].to_le_bytes());
    bytes[16..20].copy_from_slice(&uint160[4].to_le_bytes());
    bytes
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//
#[cfg(test)]
mod tests {

    use super::{from_hex, to_bytes};

    #[test]
    fn test_from_hex() {
        // Test valid input
        assert_eq!(
            from_hex("0123456789abcdef0123456789abcdef01234567"),
            [0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef, 0x01234567]
        );

        // Test valid input #2
        assert_eq!(
            from_hex("f123456789abcdef0123456789abcdef01234567"),
            [0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef, 0xf1234567]
        );

        // Test invalid input (wrong length)
        let invalid_hex_string = "0123456789abcdef0123456789abcdef0123450000";
        assert!(std::panic::catch_unwind(|| from_hex(invalid_hex_string)).is_err());
    }
    #[test]
    fn test_to_bytes() {
        assert_eq!(to_bytes([1,2,3,4,5]), [1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0]);
    }
}