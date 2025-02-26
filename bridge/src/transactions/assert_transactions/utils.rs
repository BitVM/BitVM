use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::{
    commitments::CommitmentMessageId,
    connectors::{connector_e::ConnectorE, connector_f_1::ConnectorF1, connector_f_2::ConnectorF2},
};

use bitvm::{
    chunk::api::{generate_signatures, generate_signatures_for_any_proof, type_conversion_utils::{utils_raw_witnesses_from_signatures, RawProof, RawWitness}}, 
    signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret}
};

/// The number of connector e is related to the number of intermediate values.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommit1ConnectorsE {
    pub connectors_e: Vec<ConnectorE>,
}

impl AssertCommit1ConnectorsE {
    pub fn connectors_num(&self) -> usize { self.connectors_e.len() }

    pub fn get_connector_e(&self, idx: usize) -> &ConnectorE { &self.connectors_e[idx] }

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
    pub fn connectors_num(&self) -> usize { self.connectors_e.len() }

    pub fn get_connector_e(&self, idx: usize) -> &ConnectorE { &self.connectors_e[idx] }

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
    let mut sorted_secrets: Vec<(u32, String)> = vec![];
    commitment_secrets
        .clone()
        .into_iter()
        .for_each(|(k, v)| {
            if let CommitmentMessageId::Groth16IntermediateValues((name, _)) = k {
                let index = u32::from_str_radix(&name, 10).unwrap();
                sorted_secrets.push((index, hex::encode(v.secret_key)));
            }
        });
    
    sorted_secrets.sort_by(|a, b| a.0.cmp(&b.0));
    let secrets = sorted_secrets.iter().map(|f| f.1.clone()).collect();

    let sigs = generate_signatures_for_any_proof(proof.proof.clone(), proof.public.clone(), &proof.vk, secrets);

    let raw = utils_raw_witnesses_from_signatures(&sigs);

    let raw1 = raw[0..300].to_vec();
    let raw2 = raw[300..].to_vec();

    (raw1, raw2)
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
    let connectors_e_of_transaction = 300;
    let mut connector_e1_commitment_public_keys = vec![];
    let mut connector_e2_commitment_public_keys = vec![];

    let mut secrets_vec = vec![];
    for (message_id, secret) in commitment_secrets.iter() {
        if let CommitmentMessageId::Groth16IntermediateValues((name, _)) = message_id {
            let index = u32::from_str_radix(name, 10).unwrap();
            secrets_vec.push((index, (message_id, secret)));
        }
    }

    secrets_vec.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, (message_id, secret)) in secrets_vec {
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



    assert!(connector_e1_commitment_public_keys.len() <= connectors_e_of_transaction);
    assert!(connector_e2_commitment_public_keys.len() <= connectors_e_of_transaction);
    (
        connector_e1_commitment_public_keys,
        connector_e2_commitment_public_keys,
    )
}

pub fn merge_to_connector_c_commits_public_key(
    connector_e1_commitment_public_keys: &[BTreeMap<CommitmentMessageId, WinternitzPublicKey>],
    connector_e2_commitment_public_keys: &[BTreeMap<CommitmentMessageId, WinternitzPublicKey>],
) -> BTreeMap<CommitmentMessageId, WinternitzPublicKey> {
    let mut connector_c_commitment_public_keys = BTreeMap::new();
    for tree in connector_e1_commitment_public_keys {
        for (message, pk) in tree {
            connector_c_commitment_public_keys.insert(message.clone(), pk.clone());
        }
    }
    for tree in connector_e2_commitment_public_keys {
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
