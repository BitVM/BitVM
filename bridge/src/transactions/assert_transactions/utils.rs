use serde::{Deserialize, Serialize};
use std::{
    borrow::BorrowMut,
    collections::{BTreeMap, HashMap},
};

use crate::{
    connectors::{
        connector_e::ConnectorE, connector_f_1::ConnectorF1, connector_f_2::ConnectorF2,
    },
    graphs::peg_out::CommitmentMessageId,
};

use bitvm::{
    chunker::{
        assigner::{BCAssigner as _, BridgeAssigner},
        chunk_groth16_verifier::groth16_verify_to_segments,
        common::{RawWitness, BLAKE3_HASH_LENGTH},
        disprove_execution::RawProof,
    },
    signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret},
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

pub fn sign_assert_tx_with_groth16_proof(
    commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
    proof: &RawProof,
) -> (Vec<RawWitness>, Vec<RawWitness>) {
    let (commit1_publickeys, commit2_publickeys) =
        groth16_commitment_secrets_to_public_keys(commitment_secrets);

    // hash map to btree map
    let commitment_secrets: BTreeMap<String, WinternitzSecret> = commitment_secrets
        .clone()
        .into_iter()
        .map(|(k, v)| {
            (
                match k {
                    CommitmentMessageId::Groth16IntermediateValues((name, _)) => name,
                    _ => String::new(),
                },
                v,
            )
        })
        .collect();

    let mut bridge_assigner = BridgeAssigner::new_operator(commitment_secrets);

    let segments =
        groth16_verify_to_segments(&mut bridge_assigner, &proof.public, &proof.proof, &proof.vk);

    let mut elements = BTreeMap::new();
    for segment in segments {
        for parameter in segment.parameter_list {
            elements.insert(parameter.id().to_owned(), parameter);
        }
        for result in segment.result_list {
            elements.insert(result.id().to_owned(), result);
        }
    }

    let mut commit1_witness = vec![];
    let mut commit2_witness = vec![];

    for pks in commit1_publickeys {
        let mut witness = vec![];
        for (message, pk) in pks {
            match message {
                CommitmentMessageId::Groth16IntermediateValues((name, _)) => {
                    witness.append(&mut bridge_assigner.get_witness(elements.get(&name).unwrap()));
                }
                _ => {}
            }
        }
        commit1_witness.push(witness);
    }

    for pks in commit2_publickeys {
        let mut witness = vec![];
        for (message, pk) in pks {
            match message {
                CommitmentMessageId::Groth16IntermediateValues((name, _)) => {
                    witness.append(&mut bridge_assigner.get_witness(elements.get(&name).unwrap()));
                }
                _ => {}
            }
        }
        commit2_witness.push(witness);
    }

    (commit1_witness, commit2_witness)
}

pub fn groth16_commitment_secrets_to_public_keys(
    commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
) -> (
    Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>,
    Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>,
) {
    // hash map to btree map
    let commitment_secrets: BTreeMap<CommitmentMessageId, WinternitzSecret> =
        commitment_secrets.clone().into_iter().collect();

    // see the unit test: assigner.rs/test_commitment_size
    let commitments_of_connector = 1;
    let connectors_e_of_transaction = 700;
    let mut connector_e1_commitment_public_keys = vec![];
    let mut connector_e2_commitment_public_keys = vec![];

    for (message_id, secret) in commitment_secrets.iter() {
        match message_id {
            CommitmentMessageId::Groth16IntermediateValues((name, size)) => {
                let pushing_keys =
                    if connector_e1_commitment_public_keys.len() < connectors_e_of_transaction {
                        &mut connector_e1_commitment_public_keys
                    } else {
                        &mut connector_e2_commitment_public_keys
                    };

                pushing_keys.push(BTreeMap::from([(
                    message_id.clone(),
                    WinternitzPublicKey::from(secret),
                )]));
            }
            _ => {}
        }
    }

    assert!(connector_e1_commitment_public_keys.len() <= connectors_e_of_transaction);
    assert!(connector_e2_commitment_public_keys.len() <= connectors_e_of_transaction);
    (
        connector_e1_commitment_public_keys,
        connector_e2_commitment_public_keys,
    )
}

pub fn merge_to_connector_c_commits_public_key(
    connector_e1_commitment_public_keys: &Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>,
    connector_e2_commitment_public_keys: &Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>,
) -> BTreeMap<CommitmentMessageId, WinternitzPublicKey> {
    let mut connector_c_commitment_public_keys = BTreeMap::new();
    for tree in connector_e1_commitment_public_keys.iter() {
        for (message, pk) in tree {
            connector_c_commitment_public_keys.insert(message.clone(), pk.clone());
        }
    }
    for tree in connector_e2_commitment_public_keys.iter() {
        for (message, pk) in tree {
            connector_c_commitment_public_keys.insert(message.clone(), pk.clone());
        }
    }
    connector_c_commitment_public_keys
}
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitConnectorsF {
    pub connector_f_1: ConnectorF1,
    pub connector_f_2: ConnectorF2,
}
