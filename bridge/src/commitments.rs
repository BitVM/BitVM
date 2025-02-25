use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoEnumIterator};

use bitvm::{chunker::assigner::BridgeAssigner, signatures::signing_winternitz::WinternitzSecret};

use super::{
    constants::{
        DESTINATION_NETWORK_TXID_LENGTH, SOURCE_NETWORK_TXID_LENGTH, START_TIME_MESSAGE_LENGTH,
    },
    superblock::{SUPERBLOCK_HASH_MESSAGE_LENGTH, SUPERBLOCK_MESSAGE_LENGTH},
};

#[derive(
    Serialize, Deserialize, Eq, PartialEq, Hash, Clone, PartialOrd, Ord, Display, Debug, EnumIter,
)]
#[serde(into = "String", try_from = "String")]
pub enum CommitmentMessageId {
    PegOutTxIdSourceNetwork,
    PegOutTxIdDestinationNetwork,
    StartTime,
    Superblock,
    SuperblockHash,
    // name of intermediate value and length of message
    Groth16IntermediateValues((String, usize)),
}

const VAL_SEPARATOR: char = '|';

impl From<CommitmentMessageId> for String {
    fn from(id: CommitmentMessageId) -> String {
        match id {
            CommitmentMessageId::Groth16IntermediateValues((variable_name, size)) => {
                format!(
                    "Groth16IntermediateValues{}{}{}{}",
                    VAL_SEPARATOR, variable_name, VAL_SEPARATOR, size
                )
            }
            _ => id.to_string(),
        }
    }
}

impl TryFrom<String> for CommitmentMessageId {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        for variant in CommitmentMessageId::iter() {
            if s == variant.to_string() {
                return Ok(variant);
            } else if s.starts_with(&format!("Groth16IntermediateValues{}", VAL_SEPARATOR)) {
                let parts: Vec<_> = s.split(VAL_SEPARATOR).collect();
                if parts.len() != 3 {
                    return Err(format!("Invalid Groth16IntermediateValues format: {}", s));
                }
                let variable_name = parts[1].to_string();
                let size = parts[2]
                    .parse::<usize>()
                    .map_err(|e| format!("Invalid size in Groth16IntermediateValues: {}", e))?;

                return Ok(CommitmentMessageId::Groth16IntermediateValues((
                    variable_name,
                    size,
                )));
            }
        }

        Err(format!("Unknown CommitmentMessageId: {}", s))
    }
}

impl CommitmentMessageId {
    // btree map is a copy of chunker related commitments
    pub fn generate_commitment_secrets() -> HashMap<CommitmentMessageId, WinternitzSecret> {
        println!("Generating commitment secrets ...");
        let mut commitment_map = HashMap::from([
            (
                CommitmentMessageId::PegOutTxIdSourceNetwork,
                WinternitzSecret::new(SOURCE_NETWORK_TXID_LENGTH),
            ),
            (
                CommitmentMessageId::PegOutTxIdDestinationNetwork,
                WinternitzSecret::new(DESTINATION_NETWORK_TXID_LENGTH),
            ),
            (
                CommitmentMessageId::StartTime,
                WinternitzSecret::new(START_TIME_MESSAGE_LENGTH),
            ),
            (
                CommitmentMessageId::Superblock,
                WinternitzSecret::new(SUPERBLOCK_MESSAGE_LENGTH),
            ),
            (
                CommitmentMessageId::SuperblockHash,
                WinternitzSecret::new(SUPERBLOCK_HASH_MESSAGE_LENGTH),
            ),
        ]);

        // maybe variable cache is more efficient
        let all_variables = BridgeAssigner::default().all_intermediate_variables();

        // split variable to different connectors
        for (v, size) in all_variables {
            commitment_map.insert(
                CommitmentMessageId::Groth16IntermediateValues((v, size)),
                WinternitzSecret::new(size),
            );
        }

        commitment_map
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::serialization::{deserialize, serialize};

    use super::CommitmentMessageId;

    #[test]
    fn test_commitment_message_id_serialization() {
        let messages = HashMap::from([
            (CommitmentMessageId::PegOutTxIdSourceNetwork, "test"),
            (CommitmentMessageId::PegOutTxIdDestinationNetwork, "test"),
            (CommitmentMessageId::StartTime, "test"),
            (CommitmentMessageId::Superblock, "test"),
            (CommitmentMessageId::SuperblockHash, "test"),
            (
                CommitmentMessageId::Groth16IntermediateValues(("F_10_mul_c_1p0c".to_string(), 31)),
                "test",
            ),
            (
                CommitmentMessageId::Groth16IntermediateValues((
                    "F_18_mul_ca0_a1 * b0_b1".to_string(),
                    29,
                )),
                "test",
            ),
        ]);

        let json = serialize(&messages);
        let deserialized_messages = deserialize::<HashMap<CommitmentMessageId, &str>>(&json);
        assert_eq!(messages, deserialized_messages);
    }
}
