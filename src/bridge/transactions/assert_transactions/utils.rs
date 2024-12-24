use serde::{Deserialize, Serialize};
use std::{
    borrow::BorrowMut,
    collections::{BTreeMap, HashMap},
};

use crate::{
    bridge::{
        connectors::{
            connector_e::ConnectorE, connector_f_1::ConnectorF1, connector_f_2::ConnectorF2,
        },
        graphs::peg_out::CommitmentMessageId,
        transactions::signing_winternitz::{WinternitzPublicKey, WinternitzSecret},
    },
    chunker::common::BLAKE3_HASH_LENGTH,
};

/// The number of connector e is related to the number of intermediate values.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommit1ConnectorsE {
    pub connectors_e: Vec<ConnectorE>,
}

impl AssertCommit1ConnectorsE {
    pub fn connectors_num(&self) -> usize {
        self.connectors_e.len()
    }

    pub fn get_connector_e(&self, idx: usize) -> &ConnectorE {
        &self.connectors_e[idx]
    }

    pub fn commitment_public_keys(
        &self,
    ) -> Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>> {
        self.connectors_e
            .iter()
            .map(|connector| connector.commitment_public_keys.clone())
            .collect()
    }
}

/// The number of connector e is related to the number of intermediate values.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommit2ConnectorsE {
    pub connectors_e: Vec<ConnectorE>,
}

impl AssertCommit2ConnectorsE {
    pub fn connectors_num(&self) -> usize {
        self.connectors_e.len()
    }

    pub fn get_connector_e(&self, idx: usize) -> &ConnectorE {
        &self.connectors_e[idx]
    }

    pub fn commitment_public_keys(
        &self,
    ) -> Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>> {
        self.connectors_e
            .iter()
            .map(|connector| connector.commitment_public_keys.clone())
            .collect()
    }
}

pub fn groth16_commitment_secrets_to_public_keys(
    commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
) -> (
    Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>,
    Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>,
) {
    // see the unit test: assigner.rs/test_commitment_size
    let commitments_of_connector = 10;
    let connectors_e_of_transaction = 70;
    let mut connector_e1_commitment_public_keys = vec![BTreeMap::new()];
    let mut connector_e2_commitment_public_keys = vec![BTreeMap::new()];

    for (message_id, secret) in commitment_secrets.iter() {
        match message_id {
            CommitmentMessageId::Groth16IntermediateValues((name, size)) => {
                let pushing_keys =
                    if connector_e1_commitment_public_keys.len() < connectors_e_of_transaction {
                        &mut connector_e1_commitment_public_keys
                    } else {
                        &mut connector_e2_commitment_public_keys
                    };

                // for hashes
                if *size == BLAKE3_HASH_LENGTH {
                    if pushing_keys.last().unwrap().len() < commitments_of_connector {
                        pushing_keys
                            .last_mut()
                            .unwrap()
                            .insert(message_id.clone(), WinternitzPublicKey::from(secret));
                    } else {
                        pushing_keys.push(BTreeMap::from([(
                            message_id.clone(),
                            WinternitzPublicKey::from(secret),
                        )]));
                    }
                // for proof
                } else {
                    pushing_keys.push(BTreeMap::from([(
                        message_id.clone(),
                        WinternitzPublicKey::from(secret),
                    )]));
                    pushing_keys.push(BTreeMap::new());
                }
            }
            _ => {}
        }
    }

    assert!(connector_e1_commitment_public_keys.len() < connectors_e_of_transaction);
    assert!(connector_e2_commitment_public_keys.len() < connectors_e_of_transaction);
    (
        connector_e1_commitment_public_keys,
        connector_e2_commitment_public_keys,
    )
}
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitConnectorsF {
    pub connector_f_1: ConnectorF1,
    pub connector_f_2: ConnectorF2,
}
