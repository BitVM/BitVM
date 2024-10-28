use super::constants::SHA256_DIGEST_LENGTH_IN_BYTES;

#[derive(Debug, PartialEq)]
pub struct Superblock {
    pub height: u32,
    pub time: u32,
    pub weight: u32,
}

pub fn serialize_superblock(sb: &Superblock) -> [u8; 12] {
    let mut buffer = [0u8; 12];

    buffer[0..4].copy_from_slice(&sb.height.to_le_bytes());
    buffer[4..8].copy_from_slice(&sb.time.to_le_bytes());
    buffer[8..12].copy_from_slice(&sb.weight.to_le_bytes());

    buffer
}

pub fn deserialize_superblock(buffer: &[u8; 12]) -> Superblock {
    let height = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    let time = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
    let weight = u32::from_le_bytes(buffer[8..12].try_into().unwrap());

    Superblock {
        height,
        time,
        weight,
    }
}

pub type SuperblockHash = [u8; SHA256_DIGEST_LENGTH_IN_BYTES];

pub const SUPERBLOCK_MESSAGE_LENGTH_IN_BYTES: usize =
    size_of::<Superblock>() + size_of::<SuperblockHash>();
pub(crate) type SuperblockMessage = [u8; SUPERBLOCK_MESSAGE_LENGTH_IN_BYTES];
pub(crate) const SUPERBLOCK_MESSAGE_LENGTH_IN_DIGITS: usize =
    SUPERBLOCK_MESSAGE_LENGTH_IN_BYTES * 2;

pub fn get_superblock_message(sb: &Superblock, sb_hash: &SuperblockHash) -> SuperblockMessage {
    let mut buffer = [0u8; size_of::<SuperblockMessage>()];
    buffer[..size_of::<Superblock>()].copy_from_slice(&serialize_superblock(sb));
    buffer[size_of::<Superblock>()..].copy_from_slice(&sb_hash[..]);

    buffer
}

pub fn find_superblock() -> (Superblock, SuperblockHash) { todo!() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_superblock() {
        let sb = Superblock {
            height: 123,
            time: 45678,
            weight: 9012345,
        };

        let serialized_sb = serialize_superblock(&sb);
        let deserialized_sb = deserialize_superblock(&serialized_sb);

        assert_eq!(sb, deserialized_sb);
    }
}
