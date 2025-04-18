use std::collections::HashMap;

use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use bitcoin_script::script;
use bitvm::{
    hash::sha256::{sha256, sha256_32bytes},
    signatures::{
        signing_winternitz::{winternitz_message_checksig, WinternitzPublicKey, LOG_D},
        utils::digits_to_number,
    },
};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use crate::{
    commitments::CommitmentMessageId,
    constants::START_TIME_MESSAGE_LENGTH,
    superblock::{extract_superblock_ts_from_header, SUPERBLOCK_MESSAGE_LENGTH},
    utils::{sb_hash_from_bytes, sb_hash_from_nibbles, H256},
};

use super::{
    super::{
        constants::NUM_BLOCKS_PER_3_DAYS, scripts::*, transactions::base::Input,
        utils::num_blocks_per_network,
    },
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorB {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub commitment_public_keys: HashMap<CommitmentMessageId, WinternitzPublicKey>,
    pub num_blocks_timelock_1: u32,
}

impl ConnectorB {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
    ) -> Self {
        ConnectorB {
            network,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            commitment_public_keys: commitment_public_keys.clone(),
            num_blocks_timelock_1: num_blocks_per_network(network, NUM_BLOCKS_PER_3_DAYS),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.n_of_n_taproot_public_key)
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.n_of_n_taproot_public_key,
            self.num_blocks_timelock_1,
        )
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.num_blocks_timelock_1)
    }

    fn generate_taproot_leaf_2_script(&self) -> ScriptBuf {
        const TWO_WEEKS_IN_SECONDS: u32 = 60 * 60 * 24 * 14;
        let superblock_hash_public_key =
            &self.commitment_public_keys[&CommitmentMessageId::SuperblockHash];
        let start_time_public_key = &self.commitment_public_keys[&CommitmentMessageId::StartTime];

        // Expected witness:
        // n-of-n Schnorr signature
        // SB' (byte stream)
        // Committed start time (Winternitz sig)
        // Committed SB hash (Winternitz sig)

        script! {
            // Verify superblock hash commitment sig
            { winternitz_message_checksig(superblock_hash_public_key) }
            // Convert committed SB hash to number and push it to altstack
            { sb_hash_from_nibbles() }
            { H256::toaltstack() }          // Stack: SB' sig(start_time) | Altstack: SB.hash

            // Verify start time commitment sig
            { winternitz_message_checksig(start_time_public_key) }
            // Convert committed start time to number and push it to altstack
            { digits_to_number::<{ START_TIME_MESSAGE_LENGTH * 2 }, { LOG_D as usize }>() }
            OP_TOALTSTACK                   // Stack: SB' | Altstack: SB.hash start_time

            extract_superblock_ts_from_header
                                            // Stack: SB' SB'.time | Altstack: SB.hash start_time

            // SB'.time > start_time
            OP_FROMALTSTACK                 // Stack: SB' SB'.time start_time | Altstack: SB.hash
            OP_2DUP                         // Stack: SB' SB'.time start_time SB'.time start_time | Altstack: SB.hash
            OP_GREATERTHAN OP_VERIFY        // Stack: SB' SB'.time start_time | Altstack: SB.hash

            // SB'.time < start_time + 2 weeks
            { TWO_WEEKS_IN_SECONDS } OP_ADD // Stack: SB' SB'.time (start_time + 2 weeks) | Altstack: SB.hash
            OP_LESSTHAN OP_VERIFY           // Stack: SB' | Altstack: SB.hash

            // Calculate SB' hash
            { sha256(SUPERBLOCK_MESSAGE_LENGTH) }
            { sha256_32bytes() }
            { sb_hash_from_bytes() }        // Stack: SB'.hash | Altstack: SB.hash

            // SB'.weight > SB.weight
            // We're comparing hashes as numbers (smaller number = bigger weight),
            // so we need to evaluate (SB'.hash < SB.hash).
            { H256::fromaltstack() }        // Stack: SB'.hash SB.hash
            { H256::lessthan(1, 0) } OP_VERIFY

            { self.n_of_n_taproot_public_key }
            OP_CHECKSIG
        }
        .compile()
    }

    fn generate_taproot_leaf_2_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}

impl TaprootConnector for ConnectorB {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            2 => self.generate_taproot_leaf_2_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            2 => self.generate_taproot_leaf_2_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(2, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(2, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .add_leaf(1, self.generate_taproot_leaf_2_script())
            .expect("Unable to add leaf 2")
            .finalize(SECP256K1, self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        block::{Header, Version},
        BlockHash, CompactTarget,
        Network::Regtest,
        TxMerkleNode,
    };
    use bitcoin_script::script;
    use bitvm::{
        execute_script,
        hash::sha256::{sha256, sha256_32bytes},
        signatures::{
            signing_winternitz::{
                generate_winternitz_witness, winternitz_message_checksig, WinternitzPublicKey,
                WinternitzSecret, WinternitzSigningInputs, LOG_D,
            },
            utils::digits_to_number,
        },
    };

    use crate::{
        constants::START_TIME_MESSAGE_LENGTH,
        superblock::{
            extract_superblock_ts_from_header, get_start_time_block_number,
            get_superblock_hash_message, SUPERBLOCK_HASH_MESSAGE_LENGTH, SUPERBLOCK_MESSAGE_LENGTH,
        },
        utils::{sb_hash_from_bytes, sb_hash_from_nibbles, H256},
    };

    // Copied from tests/bridge/helper.rs
    fn get_superblock_header() -> Header {
        Header {
            version: Version::from_consensus(0x200d2000),
            prev_blockhash: BlockHash::from_str(
                "000000000000000000027c9f5b07f21e39ba31aa4d900d519478bdac32f4a15d",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_str(
                "0064b0d54f20412756ba7ce07b0594f3548b06f2dad5cfeaac2aca508634ed19",
            )
            .unwrap(),
            time: 1729251961,
            bits: CompactTarget::from_hex("0x17030ecd").unwrap(),
            nonce: 0x400e345c,
        }
    }

    #[test]
    fn test_connector_b_leaf_2_script() {
        const TWO_WEEKS_IN_SECONDS: u32 = 60 * 60 * 24 * 14;

        // Setup test headers appropriately for the verification in the script to pass
        let start_time = get_start_time_block_number(Regtest);
        
        // Create a baseline header
        let base_header = get_superblock_header();
        
        // Create committed superblock with lower weight (higher hash value)
        // Higher bits value = lower difficulty/weight
        let mut committed_sb = base_header.clone();
        committed_sb.bits = CompactTarget::from_hex("0x1d030ecd").unwrap(); // Much lower difficulty
        
        // Create disprove superblock with higher weight (lower hash value)
        // Lower bits value = higher difficulty/weight
        let mut disprove_sb = base_header;
        disprove_sb.bits = CompactTarget::from_hex("0x17030ecd").unwrap(); // Much higher difficulty
        
        // Make them distinct blocks with very different hashes
        committed_sb.nonce = 0x12345678;
        disprove_sb.nonce = 0x87654321;
        committed_sb.merkle_root = TxMerkleNode::from_str(
            "1064b0d54f20412756ba7ce07b0594f3548b06f2dad5cfeaac2aca508634ed19"
        ).unwrap();
        disprove_sb.merkle_root = TxMerkleNode::from_str(
            "2064b0d54f20412756ba7ce07b0594f3548b06f2dad5cfeaac2aca508634ed19"
        ).unwrap();
        
        // Set times to satisfy time constraints:
        // 1. disprove_sb.time > start_time
        // 2. disprove_sb.time < start_time + 2 weeks
        committed_sb.time = start_time - 100; // Some time before start_time (doesn't matter for test)
        disprove_sb.time = start_time + 1000; // Some time after start_time but less than 2 weeks
        
        // Debug print to verify the targets and hashes
        println!("Committed SB bits: {:?}", committed_sb.bits);
        println!("Disprove SB bits: {:?}", disprove_sb.bits);
        
        // Calculate and print actual block hashes for debugging
        let committed_hash = committed_sb.block_hash();
        let disprove_hash = disprove_sb.block_hash();
        println!("Committed SB hash: {}", committed_hash);
        println!("Disprove SB hash: {}", disprove_hash);
        
        // Directly compare the hashes without serialization
        // Lower hash value means higher weight in Bitcoin
        assert!(disprove_hash < committed_hash, "Disprove superblock is not heavier than committed superblock! Test precondition failed.");
        println!("Is disprove SB heavier: true (verified by direct hash comparison)");
        
        let mut disprove_sb_message = crate::superblock::get_superblock_message(&disprove_sb);
        disprove_sb_message.reverse();

        let committed_sb_hash_secret = WinternitzSecret::new(SUPERBLOCK_HASH_MESSAGE_LENGTH);
        let committed_sb_hash_public_key = WinternitzPublicKey::from(&committed_sb_hash_secret);
        let committed_sb_hash_signing_inputs = WinternitzSigningInputs {
            message: &get_superblock_hash_message(&committed_sb),
            signing_key: &committed_sb_hash_secret,
        };

        let start_time_message = start_time.to_le_bytes();
        assert!(start_time_message.len() == START_TIME_MESSAGE_LENGTH);
        let start_time_secret = WinternitzSecret::new(START_TIME_MESSAGE_LENGTH);
        let start_time_public_key = WinternitzPublicKey::from(&start_time_secret);
        let start_time_signing_inputs = WinternitzSigningInputs {
            message: &start_time_message,
            signing_key: &start_time_secret,
        };

        let s = script! {
            // Witness data

            for byte in disprove_sb_message { {byte} }
            { generate_winternitz_witness(&start_time_signing_inputs).to_vec() }
            { generate_winternitz_witness(&committed_sb_hash_signing_inputs).to_vec() }
                                            // Terms used in stack notation below:
                                            //   SB = commited SB (challenged SB)
                                            //   SB' = disprove SB (challenger SB)
                                            //
                                            // Stack: SB' sig(start_time) sig(SB.hash)

            // Start unlock script

            // Verify superblock hash commitment sig
            { winternitz_message_checksig(&committed_sb_hash_public_key) }
            // Convert committed SB hash to number and push it to altstack
            { sb_hash_from_nibbles() }
            { H256::toaltstack() }          // Stack: SB' sig(start_time) | Altstack: SB.hash

            // Verify start time commitment sig
            { winternitz_message_checksig(&start_time_public_key) }
            // Convert committed start time to number and push it to altstack
            { digits_to_number::<{ START_TIME_MESSAGE_LENGTH * 2 }, { LOG_D as usize }>() }
            OP_TOALTSTACK                   // Stack: SB' | Altstack: SB.hash start_time

            extract_superblock_ts_from_header
                                            // Stack: SB' SB'.time | Altstack: SB.hash start_time

            // SB'.time > start_time
            OP_FROMALTSTACK                 // Stack: SB' SB'.time start_time | Altstack: SB.hash
            OP_2DUP                         // Stack: SB' SB'.time start_time SB'.time start_time | Altstack: SB.hash
            OP_GREATERTHAN OP_VERIFY        // Stack: SB' SB'.time start_time | Altstack: SB.hash

            // SB'.time < start_time + 2 weeks
            { TWO_WEEKS_IN_SECONDS } OP_ADD // Stack: SB' SB'.time (start_time + 2 weeks) | Altstack: SB.hash
            OP_LESSTHAN OP_VERIFY           // Stack: SB' | Altstack: SB.hash

            // Calculate SB' hash
            { sha256(SUPERBLOCK_MESSAGE_LENGTH) }
            { sha256_32bytes() }
            { sb_hash_from_bytes() }        // Stack: SB'.hash | Altstack: SB.hash

            // SB'.weight > SB.weight
            // We're comparing hashes as numbers (smaller number = bigger weight),
            // so we need to evaluate (SB'.hash < SB.hash).
            { H256::fromaltstack() }        // Stack: SB'.hash SB.hash
            { H256::lessthan(1, 0) } OP_VERIFY

            OP_TRUE
        };

        let result = execute_script(s);
        
        if !result.success {
            println!("Script execution failed. Final stack: {:?}", result.final_stack);
            if let Some(error) = result.error {
                println!("Script error: {:?}", error);
            }
        }

        assert!(result.success);
    }
}
