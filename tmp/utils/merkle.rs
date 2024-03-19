use crate::utils::u160::u160;

const BLAKE3_ZERO_HASHES: [[u32; 5]; 32] = [
    [0x0, 0x0, 0x0, 0x0, 0x0],
    [0x66D22B35, 0x6E3CE5DA, 0x4024296A, 0x29A0CF11, 0xB80A3D81],
    [0x95BAC50E, 0x5B0271AF, 0xC5EA6D14, 0x9AFF963E, 0x743303DC],
    [0xE114A57B, 0x12B51FA6, 0xADFD6D49, 0x1FAD2F0E, 0x2700DA0C],
    [0xDC683D52, 0x303CB7D0, 0xB1AF3D4F, 0xEE34AAFC, 0x6BD575FF],
    [0xB3A08C48, 0x613211DA, 0x7FC46454, 0x7FB36622, 0xA7716A97],
    [0xB1D643A6, 0xB0553EF, 0xA5499B67, 0x346F2BFB, 0x239641CD],
    [0x872D2FF7, 0xA8A9EB0B, 0xA1F52235, 0x326468A3, 0x2FF2C1A2],
    [0x2EC67809, 0xBF320FEA, 0xA3E1A6CE, 0xA9FFE760, 0xD921AF75],
    [0x32A91E2C, 0x3310D181, 0x140CD26A, 0x1A44C5C0, 0x7762448B],
    [0x1003C232, 0xA7D94877, 0xB6B04D6C, 0x323C8C8F, 0x36BEC42E],
    [0x10B6AD6, 0xBF4E2FD9, 0x95778A66, 0x9B10A49A, 0x8F15AE7],
    [0x1FECD432, 0x965FE676, 0xD23BAC60, 0x5E49D4A5, 0x34220AB3],
    [0xD4184578, 0x5DF22867, 0xC6CD2AAA, 0x694D7894, 0xA70FF955],
    [0x6B92988C, 0xF8052329, 0x718EDEF5, 0xA8853C0B, 0xFA45F742],
    [0xDB1F6292, 0xAF66D0F8, 0x74EE48CB, 0xE58F6F77, 0x68C77185],
    [0x9F3F08AA, 0xD0AA9772, 0xC8313C2B, 0x31B50B98, 0xF61C0E3C],
    [0x67882A44, 0xCB3E0035, 0x85AE2CA1, 0x8C89386, 0x19A1EBB9],
    [0xCF58F912, 0x90A02A69, 0xED1C9BAB, 0xF91860B0, 0xC6C8283A],
    [0x33C0825D, 0x83EDA0EF, 0xFBC861CD, 0xE89346A6, 0x362EF11F],
    [0xD2ADCF8B, 0xF3C964CB, 0x90DCAA96, 0x91051F2A, 0xF3D4FCC7],
    [0x9645E3AC, 0xFBAC9C0, 0x253C4957, 0xBF4B9AE2, 0x9BA4F7EE],
    [0xD26FE278, 0x7756E121, 0xA124EAF2, 0xC887799F, 0xD6C371C6],
    [0x11A2DAEF, 0x7DE12E77, 0x2F000101, 0xD63E6745, 0xFA9A4245],
    [0x308ED59F, 0x810424AF, 0xCCC63CE7, 0x21D5EABB, 0xE08A8D9],
    [0x82CD2B2D, 0x4662717B, 0x41A0E2D6, 0xB5DE36B8, 0xB4FC02AD],
    [0xC23B248C, 0x834C5784, 0x3BF013F2, 0x8826A315, 0xA5620269],
    [0xCDAF85B8, 0x3A3B0FD7, 0x512947FE, 0x4CC9D24F, 0xE8506E9A],
    [0x4D3CA672, 0x4361ABB9, 0xAEC53B56, 0x825A2D65, 0xD2051C05],
    [0xD4E97822, 0x670B1072, 0x4E5F9D35, 0xEC6526EC, 0xDAE079BC],
    [0xE8FB311A, 0xD470BADE, 0xF5E2317E, 0xDF7F3C8B, 0x88BF53DA],
    [0x7D44DD48, 0xEE66748C, 0x2EDDC4D7, 0xC9EA66CB, 0x3C418DF6],
];

fn hash(left: u160, right: u160) -> u160 {
    let mut input = [0u8; 40];
    for n in 0..5 {
        input[n*4..n*4+4].copy_from_slice(&left[n].to_le_bytes());
        input[n*4+20..n*4+24].copy_from_slice(&right[n].to_le_bytes());
    }
    let hash = blake3::hash(&input);
    let mut hash160: u160 = [0, 0, 0, 0, 0];
    for n in 0..5 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&hash.as_bytes()[n*4..n*4+4]);
        hash160[n] = u32::from_le_bytes(bytes);
    }
    hash160
}

pub fn build_tree(leaves: &[u32]) -> u160 {
    // We need at least one leaf
    if leaves.len() == 0 { panic!("leaves is empty") }

    // Pad each leaf with zeros
    let mut leaves160 = Vec::new();
    for leaf in leaves {
        leaves160.push([*leaf, 0, 0, 0, 0]);
    }

    // Hash from leaves to root
    let mut layer = 0;
    while leaves160.len() > 1 {
        // Use precomputed zero hash
        if (leaves160.len() & 1) == 1 {
            leaves160.push(BLAKE3_ZERO_HASHES[layer]);
        }
        // Compute next layer
        let mut tmp = Vec::new();
        let mut i = 0;
        while i < leaves160.len() {
            tmp.push(hash(leaves160[i], leaves160[i+1]));
            i += 2;
        }
        leaves160 = tmp;
        layer += 1;
    }
    leaves160.shrink_to(1);
    // Extend to LOG_TRACE_LEN layers
    while layer < 32 {
        // Use precomputed zero hash
        leaves160[0] = hash(leaves160[0], BLAKE3_ZERO_HASHES[layer]);
        layer += 1;
    }
    // Return root
    leaves160[0]
}

pub fn build_path(leaves: &[u32], index: u32) -> Vec<u160> {
    // We need at least one leaf
    if leaves.len() == 0 { panic!("leaves is empty") }

    // Pad each leaf with zeros
    let mut leaves160 = Vec::new();
    for leaf in leaves {
        leaves160.push([*leaf, 0, 0, 0, 0]);
    }

    let mut path = Vec::new();
    let mut index = index;
    let mut layer = 0;
    // Hash from leaves to root
    while leaves160.len() > 1 {
        // Use precomputed zero hash
        if (leaves160.len() & 1) == 1 {
            leaves160.push(BLAKE3_ZERO_HASHES[layer]);
        }
        path.push(leaves160[1 ^ index as usize]);
        // Compute next layer
        let mut tmp = Vec::new();
        let mut i = 0;
        while i < leaves160.len() {
            tmp.push(hash(leaves160[i], leaves160[i+1]));
            i += 2;
        }
        leaves160 = tmp;
        index = index >> 1;
        layer += 1;
    }
    // Extend to LOG_TRACE_LEN layers
    while layer < 32 {
        // Use precomputed zero hash
        path.push(BLAKE3_ZERO_HASHES[layer]);
        layer += 1;
    }
    // Return path
    path
}

pub fn verify_path(path: &[u160], leaf: u32, index: u32) -> u160 {
    // Pad the leaf with zeros
    let leaf160: u160 = [leaf, 0, 0, 0, 0];
    let mut index = index;
    // Hash the path from leaf to root
    path.into_iter().fold(leaf160, |node, sibling| {
        let hash = if (index & 1) == 0 { hash(node, *sibling) } else { hash(*sibling, node) };
        index = index >> 1;
        hash
    })
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//
#[cfg(test)]
mod tests {
    use crate::utils::merkle::{hash, BLAKE3_ZERO_HASHES};

    #[test]
    fn validate_precomputed_zero_hashes() {
        assert_eq!(BLAKE3_ZERO_HASHES[0], [0, 0, 0, 0, 0]);
        for n in 1..BLAKE3_ZERO_HASHES.len() {
            assert_eq!(hash(BLAKE3_ZERO_HASHES[n-1], BLAKE3_ZERO_HASHES[n-1]), BLAKE3_ZERO_HASHES[n]);
        }
    }
}