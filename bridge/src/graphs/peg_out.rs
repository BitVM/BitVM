use bitcoin::{
    hashes::Hash,
    hex::{Case::Upper, DisplayHex},
    key::Keypair,
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Transaction, Txid, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, TxStatus};
use musig2::SecNonce;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Display, Formatter, Result as FmtResult},
};

use crate::{
    commitments::CommitmentMessageId,
    common::ZkProofVerifyingKey,
    connectors::{
        connector_c::get_commit_from_assert_commit_tx, connector_d::ConnectorD,
        connector_e::ConnectorE, connector_f_1::ConnectorF1, connector_f_2::ConnectorF2,
    },
    error::{Error, GraphError, L2Error, NamedTx},
    superblock::{
        find_superblock, get_start_time_block_number, get_superblock_hash_message,
        get_superblock_message,
    },
    transactions::{
        assert_transactions::{
            assert_commit_1::AssertCommit1Transaction,
            assert_commit_2::AssertCommit2Transaction,
            assert_final::AssertFinalTransaction,
            assert_initial::AssertInitialTransaction,
            utils::{
                groth16_commitment_secrets_to_public_keys, merge_to_connector_c_commits_public_key,
                sign_assert_tx_with_groth16_proof, AssertCommit1ConnectorsE,
                AssertCommit2ConnectorsE, AssertCommitConnectorsF,
            },
        },
        peg_in_confirm::PEG_IN_CONFIRM_TX_NAME,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use bitvm::{chunk::api::type_conversion_utils::RawProof, signatures::signing_winternitz::{
    WinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs,
}};

use super::{
    super::{
        client::chain::chain::PegOutEvent,
        connectors::{
            connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
            connector_3::Connector3, connector_4::Connector4, connector_5::Connector5,
            connector_6::Connector6, connector_a::ConnectorA, connector_b::ConnectorB,
            connector_c::ConnectorC,
        },
        contexts::{operator::OperatorContext, verifier::VerifierContext},
        transactions::{
            base::{
                validate_transaction, verify_public_nonces_for_tx, BaseTransaction, Input,
                InputWithScript,
            },
            challenge::ChallengeTransaction,
            disprove::DisproveTransaction,
            disprove_chain::DisproveChainTransaction,
            kick_off_1::KickOff1Transaction,
            kick_off_2::KickOff2Transaction,
            kick_off_timeout::KickOffTimeoutTransaction,
            peg_out::PegOutTransaction,
            peg_out_confirm::PegOutConfirmTransaction,
            pre_signed::PreSignedTransaction,
            start_time::StartTimeTransaction,
            start_time_timeout::StartTimeTimeoutTransaction,
            take_1::Take1Transaction,
            take_2::Take2Transaction,
        },
    },
    base::{verify_if_not_mined, BaseGraph, GraphId, CROWDFUNDING_AMOUNT, GRAPH_VERSION},
    peg_in::PegInGraph,
};

pub type PegOutId = GraphId;

#[derive(derive_more::Display)]
pub enum PegOutWithdrawerStatus {
    #[display("Peg-out available. Request peg-out?")]
    PegOutNotStarted, // peg-out transaction not created yet
    #[display("No action available. Wait...")]
    PegOutWait,       // peg-out not confirmed yet, wait
    #[display("Peg-out complete. Done.")]
    PegOutComplete,   // peg-out complete
}

#[derive(derive_more::Display)]
pub enum PegOutVerifierStatus {
    #[display("Nonces required. Push nonces for peg-out transactions?")]
    PegOutPendingNonces,      // should push nonces
    #[display("Awaiting nonces for peg-out transactions. Wait...")]
    PegOutAwaitingNonces,     // should wait for nonces from other verifiers
    #[display("Signatures required. Push signatures for peg-out transactions?")]
    PegOutPendingSignatures,  // should push signatures
    #[display("Awaiting signatures for peg-out transactions. Wait...")]
    PegOutAwaitingSignatures, // should wait for signatures from other verifiers
    #[display("Peg-out complete, reimbursement succeded. Done.")]
    PegOutComplete,           // peg-out complete
    #[display("No action available. Wait...")]
    PegOutWait,               // no action required, wait
    #[display("Kick-off 1 transaction confirmed, dispute available. Broadcast challenge transaction?")]
    PegOutChallengeAvailable, // can call challenge
    #[display("Start time timed out. Broadcast timeout transaction?")]
    PegOutStartTimeTimeoutAvailable,
    #[display("Kick-off 1 timed out. Broadcast timeout transaction?")]
    PegOutKickOffTimeoutAvailable,
    #[display("Kick-off 2 transaction confirmed. Broadcast disprove chain transaction?")]
    PegOutDisproveChainAvailable,
    #[display("Assert transaction confirmed. Broadcast disprove transaction?")]
    PegOutDisproveAvailable,
    #[display("Peg-out complete, reimbursement failed. Done.")]
    PegOutFailed, // timeouts or disproves executed
}

#[derive(derive_more::Display)]
pub enum PegOutOperatorStatus {
    // TODO: add assert initial and assert final
    #[display("No action available. Wait...")]
    PegOutWait,
    #[display("Peg-out complete, reimbursement succeded. Done.")]
    PegOutComplete,    // peg-out complete
    #[display("Peg-out complete, reimbursement failed. Done.")]
    PegOutFailed,      // timeouts or disproves executed
    #[display("Peg-out requested. Create and broadcast peg-out transaction?")]
    PegOutStartPegOut, // should execute peg-out tx
    #[display("Peg-out confirmed. Broadcast peg-out-confirm transaction?")]
    PegOutPegOutConfirmAvailable,
    #[display("Peg-out-confirm confirmed. Broadcast kick-off 1 transaction?")]
    PegOutKickOff1Available,
    #[display("Kick-off confirmed. Broadcast start time transaction?")]
    PegOutStartTimeAvailable,
    #[display("Start time confirmed. Broadcast kick-off 2 transaction?")]
    PegOutKickOff2Available,
    #[display("Dispute raised. Broadcast initial assert transaction?")]
    PegOutAssertInitialAvailable,
    #[display("Dispute raised. Broadcast commit 1 assert transaction?")]
    PegOutAssertCommit1Available,
    #[display("Dispute raised. Broadcast commit 2 assert transaction?")]
    PegOutAssertCommit2Available,
    #[display("Dispute raised. Broadcast final assert transaction?")]
    PegOutAssertFinalAvailable,
    #[display("Dispute timed out, reimbursement available. Broadcast take 1 transaction?")]
    PegOutTake1Available,
    #[display("Dispute timed out, reimbursement available. Broadcast take 2 transaction?")]
    PegOutTake2Available,
}

struct PegOutConnectors {
    connector_0: Connector0,
    connector_1: Connector1,
    connector_2: Connector2,
    connector_3: Connector3,
    connector_4: Connector4,
    connector_5: Connector5,
    connector_6: Connector6,
    connector_a: ConnectorA,
    connector_b: ConnectorB,
    connector_c: ConnectorC,
    connector_d: ConnectorD,
    assert_commit_connectors_e_1: AssertCommit1ConnectorsE,
    assert_commit_connectors_e_2: AssertCommit2ConnectorsE,
    assert_commit_connectors_f: AssertCommitConnectorsF,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegOutGraph {
    version: String,
    network: Network,
    id: String,

    // state: State,
    // n_of_n_pre_signing_state: PreSigningState,
    n_of_n_presigned: bool,
    n_of_n_public_key: PublicKey,
    n_of_n_taproot_public_key: XOnlyPublicKey,

    pub peg_in_graph_id: String,
    peg_in_confirm_txid: Txid,

    // Note that only the connectors that are used with message commitments are
    // required to be here. They carry the Winternitz public keys, which need
    // to be pushed to remote data store. The remaining connectors can be
    // constructed dynamically.
    connector_0: Connector0,
    connector_1: Connector1,
    connector_2: Connector2,
    connector_3: Connector3,
    connector_4: Connector4,
    connector_5: Connector5,
    connector_6: Connector6,
    connector_a: ConnectorA,
    connector_b: ConnectorB,
    connector_c: ConnectorC,
    connector_d: ConnectorD,
    connector_e_1: AssertCommit1ConnectorsE,
    connector_e_2: AssertCommit2ConnectorsE,
    connector_f_1: ConnectorF1,
    connector_f_2: ConnectorF2,

    peg_out_confirm_transaction: PegOutConfirmTransaction,
    assert_initial_transaction: AssertInitialTransaction,
    assert_commit_1_transaction: AssertCommit1Transaction,
    assert_commit_2_transaction: AssertCommit2Transaction,
    assert_final_transaction: AssertFinalTransaction,
    challenge_transaction: ChallengeTransaction,
    disprove_chain_transaction: DisproveChainTransaction,
    disprove_transaction: DisproveTransaction,
    kick_off_1_transaction: KickOff1Transaction,
    kick_off_2_transaction: KickOff2Transaction,
    kick_off_timeout_transaction: KickOffTimeoutTransaction,
    start_time_transaction: StartTimeTransaction,
    start_time_timeout_transaction: StartTimeTimeoutTransaction,
    take_1_transaction: Take1Transaction,
    take_2_transaction: Take2Transaction,

    operator_public_key: PublicKey,
    operator_taproot_public_key: XOnlyPublicKey,

    pub peg_out_chain_event: Option<PegOutEvent>,
    pub peg_out_transaction: Option<PegOutTransaction>,
}

impl BaseGraph for PegOutGraph {
    fn network(&self) -> Network { self.network }

    fn id(&self) -> &String { &self.id }

    fn verifier_sign(
        &mut self,
        verifier_context: &VerifierContext,
        secret_nonces: &HashMap<Txid, HashMap<usize, SecNonce>>,
    ) {
        self.assert_initial_transaction.pre_sign(
            verifier_context,
            &self.connector_b,
            &secret_nonces[&self.assert_initial_transaction.tx().compute_txid()],
        );
        self.assert_final_transaction.pre_sign(
            verifier_context,
            &self.connector_d,
            &secret_nonces[&self.assert_final_transaction.tx().compute_txid()],
        );
        self.disprove_chain_transaction.pre_sign(
            verifier_context,
            &self.connector_b,
            &secret_nonces[&self.disprove_chain_transaction.tx().compute_txid()],
        );
        self.disprove_transaction.pre_sign(
            verifier_context,
            &self.connector_5,
            &secret_nonces[&self.disprove_transaction.tx().compute_txid()],
        );
        self.kick_off_timeout_transaction.pre_sign(
            verifier_context,
            &self.connector_1,
            &secret_nonces[&self.kick_off_timeout_transaction.tx().compute_txid()],
        );
        self.start_time_timeout_transaction.pre_sign(
            verifier_context,
            &self.connector_1,
            &self.connector_2,
            &secret_nonces[&self.start_time_timeout_transaction.tx().compute_txid()],
        );
        self.take_1_transaction.pre_sign(
            verifier_context,
            &self.connector_0,
            &self.connector_b,
            &secret_nonces[&self.take_1_transaction.tx().compute_txid()],
        );
        self.take_2_transaction.pre_sign(
            verifier_context,
            &self.connector_0,
            &self.connector_5,
            &secret_nonces[&self.take_2_transaction.tx().compute_txid()],
        );

        self.n_of_n_presigned = true; // TODO: set to true after collecting all n of n signatures
    }

    fn push_verifier_nonces(
        &mut self,
        verifier_context: &VerifierContext,
    ) -> HashMap<Txid, HashMap<usize, SecNonce>> {
        self.all_presigned_txs_mut()
            .map(|tx_wrapper| {
                (
                    tx_wrapper.tx().compute_txid(),
                    tx_wrapper.push_nonces(verifier_context),
                )
            })
            .collect()
    }
}

impl PegOutGraph {
    pub fn new(
        context: &OperatorContext,
        peg_in_graph: &PegInGraph,
        peg_out_confirm_input: Input,
        commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
    ) -> Self {
        let peg_in_confirm_transaction = peg_in_graph.peg_in_confirm_transaction_ref();
        let peg_in_confirm_txid = peg_in_confirm_transaction.tx().compute_txid();

        let connector_1_commitment_public_keys = HashMap::from([
            (
                CommitmentMessageId::Superblock,
                WinternitzPublicKey::from(&commitment_secrets[&CommitmentMessageId::Superblock]),
            ),
            (
                CommitmentMessageId::SuperblockHash,
                WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::SuperblockHash],
                ),
            ),
        ]);
        let connector_2_commitment_public_keys = HashMap::from([(
            CommitmentMessageId::StartTime,
            WinternitzPublicKey::from(&commitment_secrets[&CommitmentMessageId::StartTime]),
        )]);
        let connector_6_commitment_public_keys = HashMap::from([
            (
                CommitmentMessageId::PegOutTxIdSourceNetwork,
                WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::PegOutTxIdSourceNetwork],
                ),
            ),
            (
                CommitmentMessageId::PegOutTxIdDestinationNetwork,
                WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::PegOutTxIdDestinationNetwork],
                ),
            ),
        ]);
        let connector_b_commitment_public_keys = HashMap::from([
            (
                CommitmentMessageId::StartTime,
                WinternitzPublicKey::from(&commitment_secrets[&CommitmentMessageId::StartTime]),
            ),
            (
                CommitmentMessageId::SuperblockHash,
                WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::SuperblockHash],
                ),
            ),
        ]);

        let (connector_e1_commitment_public_keys, connector_e2_commitment_public_keys) =
            groth16_commitment_secrets_to_public_keys(commitment_secrets);

        let connectors = Self::create_new_connectors(
            context.network,
            &context.n_of_n_taproot_public_key,
            &context.operator_taproot_public_key,
            &context.operator_public_key,
            &connector_1_commitment_public_keys,
            &connector_2_commitment_public_keys,
            &connector_6_commitment_public_keys,
            &connector_b_commitment_public_keys,
            &connector_e1_commitment_public_keys,
            &connector_e2_commitment_public_keys,
        );

        let peg_out_confirm_transaction =
            PegOutConfirmTransaction::new(context, &connectors.connector_6, peg_out_confirm_input);
        let peg_out_confirm_txid = peg_out_confirm_transaction.tx().compute_txid();

        let kick_off_1_vout_0 = 0;
        let kick_off_1_transaction = KickOff1Transaction::new(
            context,
            &connectors.connector_1,
            &connectors.connector_2,
            &connectors.connector_6,
            Input {
                outpoint: OutPoint {
                    txid: peg_out_confirm_txid,
                    vout: kick_off_1_vout_0.to_u32().unwrap(),
                },
                amount: peg_out_confirm_transaction.tx().output[kick_off_1_vout_0].value,
            },
        );
        let kick_off_1_txid = kick_off_1_transaction.tx().compute_txid();

        let start_time_vout_0 = 2;
        let start_time_transaction = StartTimeTransaction::new(
            context,
            &connectors.connector_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_vout_0].value,
            },
        );

        let start_time_timeout_vout_0 = 2;
        let start_time_timeout_vout_1 = 1;
        let start_time_timeout_transaction = StartTimeTimeoutTransaction::new(
            context,
            &connectors.connector_1,
            &connectors.connector_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_timeout_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_timeout_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_timeout_vout_1.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_timeout_vout_1].value,
            },
        );

        let kick_off_2_vout_0 = 1;
        let kick_off_2_transaction = KickOff2Transaction::new(
            context,
            &connectors.connector_1,
            &connectors.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: kick_off_2_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[kick_off_2_vout_0].value,
            },
        );
        let kick_off_2_txid = kick_off_2_transaction.tx().compute_txid();

        let kick_off_timeout_vout_0 = 1;
        let kick_off_timeout_transaction = KickOffTimeoutTransaction::new(
            context,
            &connectors.connector_1,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: kick_off_timeout_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[kick_off_timeout_vout_0].value,
            },
        );

        let input_amount_crowdfunding = Amount::from_btc(CROWDFUNDING_AMOUNT).unwrap();
        let challenge_vout_0 = 0;
        let challenge_transaction = ChallengeTransaction::new(
            context,
            &connectors.connector_a,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: challenge_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[challenge_vout_0].value,
            },
            input_amount_crowdfunding,
        );

        let take_1_vout_0 = 0;
        let take_1_vout_1 = 0;
        let take_1_vout_2 = 0;
        let take_1_vout_3 = 1;
        let take_1_transaction = Take1Transaction::new(
            context,
            &connectors.connector_0,
            &connectors.connector_3,
            &connectors.connector_a,
            &connectors.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take_1_vout_0.to_u32().unwrap(),
                },
                amount: peg_in_confirm_transaction.tx().output[take_1_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: take_1_vout_1.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[take_1_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: take_1_vout_2.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[take_1_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: take_1_vout_3.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[take_1_vout_3].value,
            },
        );

        // assert initial
        let assert_initial_vout_0 = 1;
        let assert_initial_transaction = AssertInitialTransaction::new(
            &connectors.connector_b,
            &connectors.connector_d,
            &connectors.assert_commit_connectors_e_1,
            &connectors.assert_commit_connectors_e_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: assert_initial_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[assert_initial_vout_0].value,
            },
        );
        let assert_initial_txid = assert_initial_transaction.tx().compute_txid();

        // assert commit txs
        let mut vout_base = 1;
        let assert_commit_1_transaction = AssertCommit1Transaction::new(
            &connectors.assert_commit_connectors_e_1,
            &connectors.assert_commit_connectors_f.connector_f_1,
            (0..connectors.assert_commit_connectors_e_1.connectors_num())
                .map(|idx| Input {
                    outpoint: OutPoint {
                        txid: assert_initial_transaction.tx().compute_txid(),
                        vout: (idx + vout_base).to_u32().unwrap(),
                    },
                    amount: assert_initial_transaction.tx().output[idx + vout_base].value,
                })
                .collect(),
        );

        vout_base += connectors.assert_commit_connectors_e_1.connectors_num();

        let assert_commit_2_transaction = AssertCommit2Transaction::new(
            &connectors.assert_commit_connectors_e_2,
            &connectors.assert_commit_connectors_f.connector_f_2,
            (0..connectors.assert_commit_connectors_e_2.connectors_num())
                .map(|idx| Input {
                    outpoint: OutPoint {
                        txid: assert_initial_transaction.tx().compute_txid(),
                        vout: (idx + vout_base).to_u32().unwrap(),
                    },
                    amount: assert_initial_transaction.tx().output[idx + vout_base].value,
                })
                .collect(),
        );

        // assert final
        let assert_final_vout_0 = 0;
        let assert_final_vout_1 = 0;
        let assert_final_vout_2 = 0;
        let assert_final_transaction = AssertFinalTransaction::new(
            context,
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_c,
            &connectors.connector_d,
            &connectors.assert_commit_connectors_f,
            Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: assert_final_vout_0.to_u32().unwrap(),
                },
                amount: assert_initial_transaction.tx().output[assert_final_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_commit_1_transaction.tx().compute_txid(),
                    vout: assert_final_vout_1.to_u32().unwrap(),
                },
                amount: assert_commit_1_transaction.tx().output[assert_final_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_commit_2_transaction.tx().compute_txid(),
                    vout: assert_final_vout_2.to_u32().unwrap(),
                },
                amount: assert_commit_2_transaction.tx().output[assert_final_vout_2].value,
            },
        );
        let assert_final_txid = assert_final_transaction.tx().compute_txid();

        let take_2_vout_0 = 0;
        let take_2_vout_1 = 0;
        let take_2_vout_2 = 1;
        let take_2_vout_3 = 2;
        let take_2_transaction = Take2Transaction::new(
            context,
            &connectors.connector_0,
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take_2_vout_0.to_u32().unwrap(),
                },
                amount: peg_in_confirm_transaction.tx().output[take_2_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_1.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_2.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_3.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_3].value,
            },
        );

        let disprove_vout_0 = 1;
        let disprove_vout_1 = 2;
        let disprove_transaction = DisproveTransaction::new(
            context,
            &connectors.connector_5,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: disprove_vout_0.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[disprove_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: disprove_vout_1.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[disprove_vout_1].value,
            },
        );

        let disprove_chain_vout_0 = 1;
        let disprove_chain_transaction = DisproveChainTransaction::new(
            context,
            &connectors.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: disprove_chain_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[disprove_chain_vout_0].value,
            },
        );

        PegOutGraph {
            version: GRAPH_VERSION.to_string(),
            network: context.network,
            id: generate_id(peg_in_graph, &context.operator_public_key),
            n_of_n_presigned: false,
            n_of_n_public_key: context.n_of_n_public_key,
            n_of_n_taproot_public_key: context.n_of_n_taproot_public_key,
            peg_in_graph_id: peg_in_graph.id().clone(),
            peg_in_confirm_txid,
            connector_0: connectors.connector_0,
            connector_1: connectors.connector_1,
            connector_2: connectors.connector_2,
            connector_3: connectors.connector_3,
            connector_4: connectors.connector_4,
            connector_5: connectors.connector_5,
            connector_6: connectors.connector_6,
            connector_a: connectors.connector_a,
            connector_b: connectors.connector_b,
            connector_c: connectors.connector_c,
            connector_d: connectors.connector_d,
            connector_e_1: connectors.assert_commit_connectors_e_1,
            connector_e_2: connectors.assert_commit_connectors_e_2,
            connector_f_1: connectors.assert_commit_connectors_f.connector_f_1,
            connector_f_2: connectors.assert_commit_connectors_f.connector_f_2,
            peg_out_confirm_transaction,
            assert_initial_transaction,
            assert_commit_1_transaction,
            assert_commit_2_transaction,
            assert_final_transaction,
            challenge_transaction,
            disprove_chain_transaction,
            disprove_transaction,
            kick_off_1_transaction,
            kick_off_2_transaction,
            kick_off_timeout_transaction,
            start_time_transaction,
            start_time_timeout_transaction,
            take_1_transaction,
            take_2_transaction,
            operator_public_key: context.operator_public_key,
            operator_taproot_public_key: context.operator_taproot_public_key,
            peg_out_chain_event: None,
            peg_out_transaction: None,
        }
    }

    pub fn new_for_validation(&self) -> Self {
        let peg_in_confirm_txid = self.take_1_transaction.tx().input[0].previous_output.txid; // Self-referencing

        let connectors = Self::create_new_connectors(
            self.network,
            &self.n_of_n_taproot_public_key,
            &self.operator_taproot_public_key,
            &self.operator_public_key,
            &self.connector_1.commitment_public_keys,
            &self.connector_2.commitment_public_keys,
            &self.connector_6.commitment_public_keys,
            &self.connector_b.commitment_public_keys,
            &self.connector_e_1.commitment_public_keys(),
            &self.connector_e_2.commitment_public_keys(),
        );

        let peg_out_confirm_vout_0 = 0;
        let peg_out_confirm_transaction = PegOutConfirmTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_6,
            Input {
                outpoint: self.peg_out_confirm_transaction.tx().input[peg_out_confirm_vout_0]
                    .previous_output, // Self-referencing
                amount: self.peg_out_confirm_transaction.prev_outs()[peg_out_confirm_vout_0].value, // Self-referencing
            },
        );

        let kick_off_1_vout_0 = 0;
        let kick_off_1_transaction = KickOff1Transaction::new_for_validation(
            self.network,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            &connectors.connector_1,
            &connectors.connector_2,
            &connectors.connector_6,
            Input {
                outpoint: self.kick_off_1_transaction.tx().input[kick_off_1_vout_0].previous_output, // Self-referencing
                amount: self.kick_off_1_transaction.prev_outs()[kick_off_1_vout_0].value, // Self-referencing
            },
        );
        let kick_off_1_txid = kick_off_1_transaction.tx().compute_txid();

        let start_time_vout_0 = 2;
        let start_time_transaction = StartTimeTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_vout_0].value,
            },
        );

        let start_time_timeout_vout_0 = 2;
        let start_time_timeout_vout_1 = 1;
        let start_time_timeout_transaction = StartTimeTimeoutTransaction::new_for_validation(
            self.network,
            &connectors.connector_1,
            &connectors.connector_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_timeout_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_timeout_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_timeout_vout_1.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_timeout_vout_1].value,
            },
        );

        let kick_off_2_vout_0 = 1;
        let kick_off_2_transaction = KickOff2Transaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_1,
            &connectors.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: kick_off_2_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[kick_off_2_vout_0].value,
            },
        );
        let kick_off_2_txid = kick_off_2_transaction.tx().compute_txid();

        let kick_off_timeout_vout_0 = 1;
        let kick_off_timeout_transaction = KickOffTimeoutTransaction::new_for_validation(
            self.network,
            &connectors.connector_1,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: kick_off_timeout_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[kick_off_timeout_vout_0].value,
            },
        );

        let input_amount_crowdfunding = Amount::from_btc(CROWDFUNDING_AMOUNT).unwrap();
        let challenge_vout_0 = 0;
        let challenge_transaction = ChallengeTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &self.connector_a,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: challenge_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[challenge_vout_0].value,
            },
            input_amount_crowdfunding,
        );

        let take_1_vout_0 = 0;
        let take_1_vout_1 = 0;
        let take_1_vout_2 = 0;
        let take_1_vout_3 = 1;
        let take_1_transaction = Take1Transaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_0,
            &connectors.connector_3,
            &connectors.connector_a,
            &connectors.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take_1_vout_0.to_u32().unwrap(),
                },
                amount: self.take_1_transaction.prev_outs()[take_1_vout_0].value, // Self-referencing
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: take_1_vout_1.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[take_1_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: take_1_vout_2.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[take_1_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: take_1_vout_3.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[take_1_vout_3].value,
            },
        );

        // assert initial
        let assert_initial_vout_0 = 1;
        let assert_initial_transaction = AssertInitialTransaction::new_for_validation(
            &connectors.connector_b,
            &connectors.connector_d,
            &connectors.assert_commit_connectors_e_1,
            &connectors.assert_commit_connectors_e_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: assert_initial_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[assert_initial_vout_0].value,
            },
        );
        let assert_initial_txid = assert_initial_transaction.tx().compute_txid();

        // assert commit txs
        let mut vout_base = 1;
        let assert_commit_1_transaction = AssertCommit1Transaction::new_for_validation(
            &connectors.assert_commit_connectors_e_1,
            &connectors.assert_commit_connectors_f.connector_f_1,
            (0..connectors.assert_commit_connectors_e_1.connectors_num())
                .map(|idx| Input {
                    outpoint: OutPoint {
                        txid: assert_initial_transaction.tx().compute_txid(),
                        vout: (idx + vout_base).to_u32().unwrap(),
                    },
                    amount: assert_initial_transaction.tx().output[idx + vout_base].value,
                })
                .collect(),
        );

        vout_base += connectors.assert_commit_connectors_e_1.connectors_num();

        let assert_commit_2_transaction = AssertCommit2Transaction::new_for_validation(
            &connectors.assert_commit_connectors_e_2,
            &connectors.assert_commit_connectors_f.connector_f_2,
            (0..connectors.assert_commit_connectors_e_2.connectors_num())
                .map(|idx| Input {
                    outpoint: OutPoint {
                        txid: assert_initial_transaction.tx().compute_txid(),
                        vout: (idx + vout_base).to_u32().unwrap(),
                    },
                    amount: assert_initial_transaction.tx().output[idx + vout_base].value,
                })
                .collect(),
        );

        // assert final
        let assert_final_vout_0 = 0;
        let assert_final_vout_1 = 0;
        let assert_final_vout_2 = 0;
        let assert_final_transaction = AssertFinalTransaction::new_for_validation(
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_c,
            &connectors.connector_d,
            &connectors.assert_commit_connectors_f,
            Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: assert_final_vout_0.to_u32().unwrap(),
                },
                amount: assert_initial_transaction.tx().output[assert_final_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_commit_1_transaction.tx().compute_txid(),
                    vout: assert_final_vout_1.to_u32().unwrap(),
                },
                amount: assert_commit_1_transaction.tx().output[assert_final_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_commit_2_transaction.tx().compute_txid(),
                    vout: assert_final_vout_2.to_u32().unwrap(),
                },
                amount: assert_commit_2_transaction.tx().output[assert_final_vout_2].value,
            },
        );
        let assert_final_txid = assert_final_transaction.tx().compute_txid();

        let take_2_vout_0 = 0;
        let take_2_vout_1 = 0;
        let take_2_vout_2 = 1;
        let take_2_vout_3 = 2;
        let take_2_transaction = Take2Transaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_0,
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take_2_vout_0.to_u32().unwrap(),
                },
                amount: self.take_2_transaction.prev_outs()[take_2_vout_0].value, // Self-referencing
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_1.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_2.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_3.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_3].value,
            },
        );

        let disprove_vout_0 = 1;
        let disprove_vout_1 = 2;
        let disprove_transaction = DisproveTransaction::new_for_validation(
            self.network,
            &self.connector_5,
            &self.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: disprove_vout_0.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[disprove_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: disprove_vout_1.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[disprove_vout_1].value,
            },
        );

        let disprove_chain_vout_0 = 1;
        let disprove_chain_transaction = DisproveChainTransaction::new_for_validation(
            self.network,
            &self.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: disprove_chain_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[disprove_chain_vout_0].value,
            },
        );

        PegOutGraph {
            version: GRAPH_VERSION.to_string(),
            network: self.network,
            id: self.id.clone(),
            n_of_n_presigned: false,
            n_of_n_public_key: self.n_of_n_public_key,
            n_of_n_taproot_public_key: self.n_of_n_taproot_public_key,
            peg_in_graph_id: self.peg_in_graph_id.clone(),
            peg_in_confirm_txid,
            connector_0: connectors.connector_0,
            connector_1: connectors.connector_1,
            connector_2: connectors.connector_2,
            connector_3: connectors.connector_3,
            connector_4: connectors.connector_4,
            connector_5: connectors.connector_5,
            connector_6: connectors.connector_6,
            connector_a: connectors.connector_a,
            connector_b: connectors.connector_b,
            connector_c: connectors.connector_c,
            connector_d: connectors.connector_d,
            connector_e_1: connectors.assert_commit_connectors_e_1,
            connector_e_2: connectors.assert_commit_connectors_e_2,
            connector_f_1: connectors.assert_commit_connectors_f.connector_f_1,
            connector_f_2: connectors.assert_commit_connectors_f.connector_f_2,
            peg_out_confirm_transaction,
            assert_initial_transaction,
            assert_commit_1_transaction,
            assert_commit_2_transaction,
            assert_final_transaction,
            challenge_transaction,
            disprove_chain_transaction,
            disprove_transaction,
            kick_off_1_transaction,
            kick_off_2_transaction,
            kick_off_timeout_transaction,
            start_time_transaction,
            start_time_timeout_transaction,
            take_1_transaction,
            take_2_transaction,
            operator_public_key: self.operator_public_key,
            operator_taproot_public_key: self.operator_taproot_public_key,
            peg_out_chain_event: None,
            peg_out_transaction: None,
        }
    }

    pub async fn verifier_status(
        &self,
        client: &AsyncClient,
        verifier_context: &VerifierContext,
    ) -> PegOutVerifierStatus {
        if self.n_of_n_presigned {
            let (
                _,
                _,
                _,
                assert_final_status,
                challenge_status,
                disprove_chain_status,
                disprove_status,
                _,
                kick_off_1_status,
                kick_off_2_status,
                kick_off_timeout_status,
                _,
                start_time_timeout_status,
                start_time_status,
                take_1_status,
                take_2_status,
            ) = Self::get_peg_out_statuses(self, client).await;
            let blockchain_height = client.get_height().await;

            if kick_off_2_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                if take_1_status.as_ref().is_ok_and(|status| status.confirmed)
                    || take_2_status.as_ref().is_ok_and(|status| status.confirmed)
                {
                    PegOutVerifierStatus::PegOutComplete
                } else if disprove_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                    || disprove_chain_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutFailed; // TODO: can be also `PegOutVerifierStatus::PegOutComplete`
                } else if assert_final_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutDisproveAvailable;
                } else {
                    return PegOutVerifierStatus::PegOutDisproveChainAvailable;
                }
            } else if kick_off_1_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                if start_time_timeout_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                    || kick_off_timeout_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutFailed; // TODO: can be also `PegOutVerifierStatus::PegOutComplete`
                } else if start_time_status
                    .as_ref()
                    .is_ok_and(|status| !status.confirmed)
                {
                    if kick_off_1_status
                        .as_ref()
                        .unwrap()
                        .block_height
                        .is_some_and(|block_height| {
                            blockchain_height.is_ok_and(|blockchain_height| {
                                block_height + self.connector_1.num_blocks_timelock_leaf_2
                                    <= blockchain_height
                            })
                        })
                    {
                        return PegOutVerifierStatus::PegOutStartTimeTimeoutAvailable;
                    } else {
                        return PegOutVerifierStatus::PegOutWait;
                    }
                } else if kick_off_1_status
                    .as_ref()
                    .unwrap()
                    .block_height
                    .is_some_and(|block_height| {
                        blockchain_height.is_ok_and(|blockchain_height| {
                            block_height + self.connector_1.num_blocks_timelock_leaf_1
                                <= blockchain_height
                        })
                    })
                {
                    return PegOutVerifierStatus::PegOutKickOffTimeoutAvailable;
                } else if challenge_status
                    .as_ref()
                    .is_ok_and(|status| !status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutChallengeAvailable;
                } else {
                    return PegOutVerifierStatus::PegOutWait;
                }
            } else {
                return PegOutVerifierStatus::PegOutWait;
            }
        } else {
            if !self.has_all_nonces_of(verifier_context) {
                return PegOutVerifierStatus::PegOutPendingNonces;
            } else if !self.has_all_nonces(&verifier_context.n_of_n_public_keys) {
                return PegOutVerifierStatus::PegOutAwaitingNonces;
            } else if !self.has_all_signatures_of(verifier_context) {
                return PegOutVerifierStatus::PegOutPendingSignatures;
            } else if !self.has_all_signatures(&verifier_context.n_of_n_public_keys) {
                return PegOutVerifierStatus::PegOutAwaitingSignatures;
            } else {
                return PegOutVerifierStatus::PegOutWait;
            }
        }
    }

    pub async fn operator_status(&self, client: &AsyncClient) -> PegOutOperatorStatus {
        if self.n_of_n_presigned && self.is_peg_out_initiated() {
            let (
                assert_initial_status,
                assert_commit_1_status,
                assert_commit_2_status,
                assert_final_status,
                challenge_status,
                disprove_chain_status,
                disprove_status,
                peg_out_confirm_status,
                kick_off_1_status,
                kick_off_2_status,
                kick_off_timeout_status,
                peg_out_status,
                start_time_timeout_status,
                start_time_status,
                take_1_status,
                take_2_status,
            ) = Self::get_peg_out_statuses(self, client).await;
            let blockchain_height = client.get_height().await;

            if peg_out_status.is_some_and(|status| status.unwrap().confirmed) {
                if kick_off_2_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    if take_1_status.as_ref().is_ok_and(|status| status.confirmed)
                        || take_2_status.as_ref().is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutComplete;
                    } else if disprove_chain_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                        || disprove_status
                            .as_ref()
                            .is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutFailed; // TODO: can be also `PegOutOperatorStatus::PegOutComplete`
                    } else if challenge_status.is_ok_and(|status| status.confirmed) {
                        if assert_final_status
                            .as_ref()
                            .is_ok_and(|status| status.confirmed)
                        {
                            if assert_final_status
                                .as_ref()
                                .unwrap()
                                .block_height
                                .is_some_and(|block_height| {
                                    blockchain_height.is_ok_and(|blockchain_height| {
                                        block_height + self.connector_4.num_blocks_timelock
                                            <= blockchain_height
                                    })
                                })
                            {
                                return PegOutOperatorStatus::PegOutTake2Available;
                            } else {
                                return PegOutOperatorStatus::PegOutWait;
                            }
                        } else if kick_off_2_status
                            .as_ref()
                            .unwrap()
                            .block_height
                            .is_some_and(|block_height| {
                                blockchain_height.is_ok_and(|blockchain_height| {
                                    block_height + self.connector_b.num_blocks_timelock_1
                                        <= blockchain_height
                                })
                            })
                        {
                            if assert_initial_status
                                .as_ref()
                                .is_ok_and(|status| status.confirmed)
                            {
                                if assert_commit_1_status
                                    .as_ref()
                                    .is_ok_and(|status| status.confirmed)
                                    && assert_commit_2_status
                                        .as_ref()
                                        .is_ok_and(|status| status.confirmed)
                                {
                                    return PegOutOperatorStatus::PegOutAssertFinalAvailable;
                                } else if assert_commit_1_status
                                    .as_ref()
                                    .is_ok_and(|status| status.confirmed)
                                {
                                    return PegOutOperatorStatus::PegOutAssertCommit2Available;
                                } else {
                                    return PegOutOperatorStatus::PegOutAssertCommit1Available;
                                }
                            } else {
                                return PegOutOperatorStatus::PegOutAssertInitialAvailable;
                            }
                        } else {
                            return PegOutOperatorStatus::PegOutWait;
                        }
                    } else if kick_off_2_status
                        .as_ref()
                        .unwrap()
                        .block_height
                        .is_some_and(|block_height| {
                            blockchain_height.is_ok_and(|blockchain_height| {
                                block_height + self.connector_3.num_blocks_timelock
                                    <= blockchain_height
                            })
                        })
                    {
                        return PegOutOperatorStatus::PegOutTake1Available;
                    } else {
                        return PegOutOperatorStatus::PegOutWait;
                    }
                } else if kick_off_1_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    if start_time_timeout_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                        || kick_off_timeout_status
                            .as_ref()
                            .is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutFailed; // TODO: can be also `PegOutOperatorStatus::PegOutComplete`
                    } else if start_time_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                    {
                        if kick_off_1_status
                            .as_ref()
                            .unwrap()
                            .block_height
                            .is_some_and(|block_height| {
                                blockchain_height.is_ok_and(|blockchain_height| {
                                    block_height + self.connector_1.num_blocks_timelock_leaf_0
                                        <= blockchain_height
                                })
                            })
                        {
                            return PegOutOperatorStatus::PegOutKickOff2Available;
                        } else {
                            return PegOutOperatorStatus::PegOutWait;
                        }
                    } else {
                        return PegOutOperatorStatus::PegOutStartTimeAvailable;
                    }
                } else if peg_out_confirm_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    return PegOutOperatorStatus::PegOutKickOff1Available;
                } else {
                    return PegOutOperatorStatus::PegOutPegOutConfirmAvailable;
                }
            } else {
                return PegOutOperatorStatus::PegOutStartPegOut;
            }
        }

        PegOutOperatorStatus::PegOutWait
    }

    pub fn interpret_withdrawer_status(
        &self,
        peg_out_status: Option<&Result<TxStatus, esplora_client::Error>>,
    ) -> PegOutWithdrawerStatus {
        if let Some(peg_out_status) = peg_out_status {
            if peg_out_status.as_ref().is_ok_and(|status| status.confirmed) {
                PegOutWithdrawerStatus::PegOutComplete
            } else {
                PegOutWithdrawerStatus::PegOutWait
            }
        } else {
            PegOutWithdrawerStatus::PegOutNotStarted
        }
    }

    pub async fn withdrawer_status(&self, client: &AsyncClient) -> PegOutWithdrawerStatus {
        let peg_out_status = match self.peg_out_transaction {
            Some(_) => {
                let peg_out_txid = self
                    .peg_out_transaction
                    .as_ref()
                    .unwrap()
                    .tx()
                    .compute_txid();
                let peg_out_status = client.get_tx_status(&peg_out_txid).await;
                Some(peg_out_status)
            }
            None => None,
        };
        self.interpret_withdrawer_status(peg_out_status.as_ref())
    }

    pub async fn peg_out(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        input: Input,
    ) -> Result<Transaction, Error> {
        if !self.is_peg_out_initiated() {
            return Err(Error::L2(L2Error::PegOutNotInitiated));
        }

        if self.peg_out_transaction.is_some() {
            let txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid();
            verify_if_not_mined(client, txid).await?;
        } else {
            let event = self.peg_out_chain_event.as_ref().unwrap();
            let tx = PegOutTransaction::new(context, event, input);
            self.peg_out_transaction = Some(tx);
        }

        Ok(self.peg_out_transaction.as_mut().unwrap().finalize())
    }

    pub async fn peg_out_confirm(&mut self, client: &AsyncClient) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.peg_out_confirm_transaction.tx().compute_txid()).await?;

        if self.peg_out_transaction.as_ref().is_some() {
            let peg_out_txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid();
            let peg_out_status = client.get_tx_status(&peg_out_txid).await;

            match peg_out_status {
                Ok(status) => match status.confirmed {
                    true => Ok(self.peg_out_confirm_transaction.finalize()),
                    false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                        NamedTx::for_tx(
                            self.peg_out_transaction.as_ref().unwrap(),
                            status.confirmed,
                        ),
                    ]))),
                },
                Err(e) => Err(Error::Esplora(e)),
            }
        } else {
            Err(Error::Graph(GraphError::PrecedingTxNotCreated("peg-out")))
        }
    }

    pub async fn kick_off_1(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        source_network_txid_commitment_secret: &WinternitzSecret,
        destination_network_txid_commitment_secret: &WinternitzSecret,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.kick_off_1_transaction.tx().compute_txid()).await?;

        let peg_out_confirm_txid = self.peg_out_confirm_transaction.tx().compute_txid();
        let peg_out_confirm_status = client.get_tx_status(&peg_out_confirm_txid).await;

        match peg_out_confirm_status {
            Ok(status) => match status.confirmed {
                true => {
                    let pegout_txid = self
                        .peg_out_transaction
                        .as_ref()
                        .unwrap()
                        .tx()
                        .compute_txid()
                        .as_byte_array()
                        .to_owned();
                    let source_network_txid_inputs = WinternitzSigningInputs {
                        message: &pegout_txid,
                        signing_key: source_network_txid_commitment_secret,
                    };
                    let destination_network_txid_inputs = WinternitzSigningInputs {
                        message: self
                            .peg_out_chain_event
                            .as_ref()
                            .unwrap()
                            .tx_hash
                            .as_slice(),
                        signing_key: destination_network_txid_commitment_secret,
                    };
                    self.kick_off_1_transaction.sign(
                        context,
                        &self.connector_6,
                        &source_network_txid_inputs,
                        &destination_network_txid_inputs,
                    );
                    Ok(self.kick_off_1_transaction.finalize())
                }
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.peg_out_confirm_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn challenge(
        &mut self,
        client: &AsyncClient,
        crowdfundng_inputs: &Vec<InputWithScript<'_>>,
        keypair: &Keypair,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await?;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        match kick_off_1_status {
            Ok(status) => match status.confirmed {
                true => {
                    self.challenge_transaction.add_inputs_and_output(
                        crowdfundng_inputs,
                        keypair,
                        output_script_pubkey,
                    );
                    Ok(self.challenge_transaction.finalize())
                }
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.kick_off_1_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn start_time(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        start_time_commitment_secret: &WinternitzSecret,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.start_time_transaction.tx().compute_txid()).await?;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        match kick_off_1_status {
            Ok(status) => match status.confirmed {
                true => {
                    self.start_time_transaction.sign(
                        context,
                        &self.connector_2,
                        get_start_time_block_number(context.network),
                        start_time_commitment_secret,
                    );
                    Ok(self.start_time_transaction.finalize())
                }
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.kick_off_1_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn start_time_timeout(
        &mut self,
        client: &AsyncClient,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(
            client,
            self.start_time_timeout_transaction.tx().compute_txid(),
        )
        .await?;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = client.get_height().await;

        match kick_off_1_status {
            Ok(status) => match status.confirmed {
                true => match status.block_height {
                    Some(block_height)
                        if blockchain_height.is_ok_and(|height| {
                            block_height + self.connector_1.num_blocks_timelock_leaf_2 <= height
                        }) =>
                    {
                        self.start_time_timeout_transaction
                            .add_output(output_script_pubkey);
                        Ok(self.start_time_timeout_transaction.finalize())
                    }
                    _ => Err(Error::Graph(GraphError::PrecedingTxTimelockNotMet(
                        NamedTx::for_tx(&self.kick_off_1_transaction, status.confirmed),
                    ))),
                },
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.kick_off_1_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn kick_off_2(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        superblock_commitment_secret: &WinternitzSecret,
        superblock_hash_commitment_secret: &WinternitzSecret,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.kick_off_2_transaction.tx().compute_txid()).await?;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = client.get_height().await;

        match kick_off_1_status {
            Ok(status) => match status.confirmed {
                true => match status.block_height {
                    Some(block_height)
                        if blockchain_height.is_ok_and(|height| {
                            block_height + self.connector_1.num_blocks_timelock_leaf_0 <= height
                        }) =>
                    {
                        let superblock_header = find_superblock();
                        self.kick_off_2_transaction.sign(
                            context,
                            &self.connector_1,
                            &WinternitzSigningInputs {
                                message: &get_superblock_message(&superblock_header),
                                signing_key: superblock_commitment_secret,
                            },
                            &WinternitzSigningInputs {
                                message: &get_superblock_hash_message(&superblock_header),
                                signing_key: superblock_hash_commitment_secret,
                            },
                        );
                        Ok(self.kick_off_2_transaction.finalize())
                    }
                    _ => Err(Error::Graph(GraphError::PrecedingTxTimelockNotMet(
                        NamedTx::for_tx(&self.kick_off_1_transaction, status.confirmed),
                    ))),
                },
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.kick_off_1_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn kick_off_timeout(
        &mut self,
        client: &AsyncClient,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(
            client,
            self.kick_off_timeout_transaction.tx().compute_txid(),
        )
        .await?;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = client.get_height().await;

        match kick_off_1_status {
            Ok(status) => match status.confirmed {
                true => match status.block_height {
                    Some(block_height)
                        if blockchain_height.is_ok_and(|height| {
                            block_height + self.connector_1.num_blocks_timelock_leaf_1 <= height
                        }) =>
                    {
                        self.kick_off_timeout_transaction
                            .add_output(output_script_pubkey);
                        Ok(self.kick_off_timeout_transaction.finalize())
                    }
                    _ => Err(Error::Graph(GraphError::PrecedingTxTimelockNotMet(
                        NamedTx::for_tx(&self.kick_off_1_transaction, status.confirmed),
                    ))),
                },
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.kick_off_1_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn assert_initial(&mut self, client: &AsyncClient) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.assert_initial_transaction.tx().compute_txid()).await?;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        let blockchain_height = client.get_height().await;

        match kick_off_2_status {
            Ok(status) => match status.confirmed {
                true => match status.block_height {
                    Some(block_height)
                        if blockchain_height.is_ok_and(|height| {
                            block_height + self.connector_b.num_blocks_timelock_1 <= height
                        }) =>
                    {
                        Ok(self.assert_initial_transaction.finalize())
                    }
                    _ => Err(Error::Graph(GraphError::PrecedingTxTimelockNotMet(
                        NamedTx::for_tx(&self.kick_off_2_transaction, status.confirmed),
                    ))),
                },
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.kick_off_2_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn assert_commit_1(
        &mut self,
        client: &AsyncClient,
        commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
        proof: &RawProof,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.assert_commit_1_transaction.tx().compute_txid()).await?;

        let assert_initial_txid = self.assert_initial_transaction.tx().compute_txid();
        let assert_initial_status = client.get_tx_status(&assert_initial_txid).await;

        match assert_initial_status {
            Ok(status) => match status.confirmed {
                true => {
                    let (witness_for_commit1, _) =
                        sign_assert_tx_with_groth16_proof(commitment_secrets, proof);
                    self.assert_commit_1_transaction
                        .sign(&self.connector_e_1, witness_for_commit1.clone());
                    Ok(self.assert_commit_1_transaction.finalize())
                }
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.assert_initial_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn assert_commit_2(
        &mut self,
        client: &AsyncClient,
        commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
        proof: &RawProof,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.assert_commit_2_transaction.tx().compute_txid()).await?;

        let assert_initial_txid = self.assert_initial_transaction.tx().compute_txid();
        let assert_initial_status = client.get_tx_status(&assert_initial_txid).await;

        match assert_initial_status {
            Ok(status) => match status.confirmed {
                true => {
                    let (_, witness_for_commit2) =
                        sign_assert_tx_with_groth16_proof(commitment_secrets, proof);
                    self.assert_commit_2_transaction
                        .sign(&self.connector_e_2, witness_for_commit2.clone());
                    Ok(self.assert_commit_2_transaction.finalize())
                }
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.assert_initial_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn assert_final(&mut self, client: &AsyncClient) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.assert_final_transaction.tx().compute_txid()).await?;

        let assert_initial_txid = self.assert_initial_transaction.tx().compute_txid();
        let assert_initial_status = client.get_tx_status(&assert_initial_txid).await;

        match assert_initial_status {
            Ok(status) => match status.confirmed {
                true => Ok(self.assert_final_transaction.finalize()),
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.assert_initial_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn disprove(
        &mut self,
        client: &AsyncClient,
        output_script_pubkey: ScriptBuf,
        verifying_key: &ZkProofVerifyingKey,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await?;

        let assert_final_txid = self.assert_final_transaction.tx().compute_txid();
        let assert_final_status = client.get_tx_status(&assert_final_txid).await;

        match assert_final_status {
            Ok(status) => match status.confirmed {
                true => {
                    // get commit from assert_commit txs
                    let assert_commit_1_witness =
                        get_commit_from_assert_commit_tx(self.assert_commit_1_transaction.tx());
                    let assert_commit_2_witness =
                        get_commit_from_assert_commit_tx(self.assert_commit_2_transaction.tx());

                    let (input_script_index, disprove_witness) =
                        self.connector_c.generate_disprove_witness(
                            assert_commit_1_witness,
                            assert_commit_2_witness,
                            verifying_key,
                        )?;
                    self.disprove_transaction.add_input_output(
                        &self.connector_c,
                        input_script_index as u32,
                        disprove_witness,
                        output_script_pubkey,
                    );
                    Ok(self.disprove_transaction.finalize())
                }
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.assert_final_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn disprove_chain(
        &mut self,
        client: &AsyncClient,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.disprove_chain_transaction.tx().compute_txid()).await?;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        match kick_off_2_status {
            Ok(status) => match status.confirmed {
                true => {
                    self.disprove_chain_transaction
                        .add_output(output_script_pubkey);

                    // TODO: This must be a heavier superblock than the one the Operator committed in the KickOff2 tx.
                    let disprove_sb = find_superblock();

                    self.disprove_chain_transaction.sign(
                        &disprove_sb,
                        self.start_time_transaction
                            .start_time_witness
                            .as_ref()
                            .ok_or(Error::Graph(GraphError::WitnessNotGenerated(
                                CommitmentMessageId::StartTime,
                            )))?,
                        self.kick_off_2_transaction
                            .superblock_hash_witness
                            .as_ref()
                            .ok_or(Error::Graph(GraphError::WitnessNotGenerated(
                                CommitmentMessageId::SuperblockHash,
                            )))?,
                    );

                    Ok(self.disprove_chain_transaction.finalize())
                }
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.kick_off_2_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn take_1(&mut self, client: &AsyncClient) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.take_1_transaction.tx().compute_txid()).await?;
        verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await?;
        verify_if_not_mined(client, self.assert_initial_transaction.tx().compute_txid()).await?;
        verify_if_not_mined(client, self.disprove_chain_transaction.tx().compute_txid()).await?;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        let blockchain_height = client.get_height().await;

        match (peg_in_confirm_status, kick_off_1_status, kick_off_2_status) {
            (Ok(pic_stat), Ok(ko1_stat), Ok(ko2_stat)) => {
                match (pic_stat.confirmed, ko1_stat.confirmed, ko2_stat.confirmed) {
                    (true, true, true) => match ko2_stat.block_height {
                        Some(block_height)
                            if blockchain_height.is_ok_and(|height| {
                                block_height + self.connector_3.num_blocks_timelock <= height
                            }) =>
                        {
                            Ok(self.take_1_transaction.finalize())
                        }
                        _ => Err(Error::Graph(GraphError::PrecedingTxTimelockNotMet(
                            NamedTx::for_tx(&self.kick_off_2_transaction, ko2_stat.confirmed),
                        ))),
                    },
                    _ => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                        NamedTx {
                            txid: self.peg_in_confirm_txid,
                            name: PEG_IN_CONFIRM_TX_NAME,
                            confirmed: pic_stat.confirmed,
                        },
                        NamedTx::for_tx(&self.kick_off_1_transaction, ko1_stat.confirmed),
                        NamedTx::for_tx(&self.kick_off_2_transaction, ko2_stat.confirmed),
                    ]))),
                }
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(Error::Esplora(e)),
        }
    }

    pub async fn take_2(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
    ) -> Result<Transaction, Error> {
        verify_if_not_mined(client, self.take_2_transaction.tx().compute_txid()).await?;
        verify_if_not_mined(client, self.take_1_transaction.tx().compute_txid()).await?;
        verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await?;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;

        let assert_final_txid = self.assert_final_transaction.tx().compute_txid();
        let assert_final_status = client.get_tx_status(&assert_final_txid).await;

        let blockchain_height = client.get_height().await;

        match (peg_in_confirm_status, assert_final_status) {
            (Ok(pic_stat), Ok(assert_stat)) => match (pic_stat.confirmed, assert_stat.confirmed) {
                (true, true) => match assert_stat.block_height {
                    Some(block_height)
                        if blockchain_height.is_ok_and(|height| {
                            block_height + self.connector_4.num_blocks_timelock <= height
                        }) =>
                    {
                        self.take_2_transaction.sign(context, &self.connector_c);
                        Ok(self.take_2_transaction.finalize())
                    }
                    _ => Err(Error::Graph(GraphError::PrecedingTxTimelockNotMet(
                        NamedTx::for_tx(&self.assert_final_transaction, assert_stat.confirmed),
                    ))),
                },
                _ => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx {
                        txid: self.peg_in_confirm_txid,
                        name: PEG_IN_CONFIRM_TX_NAME,
                        confirmed: pic_stat.confirmed,
                    },
                    NamedTx::for_tx(&self.assert_final_transaction, assert_stat.confirmed),
                ]))),
            },
            (Err(e), _) | (_, Err(e)) => Err(Error::Esplora(e)),
        }
    }

    pub fn is_peg_out_initiated(&self) -> bool { self.peg_out_chain_event.is_some() }

    pub fn min_crowdfunding_amount(&self) -> u64 {
        self.challenge_transaction.min_crowdfunding_amount()
    }

    pub async fn match_and_set_peg_out_event(
        &mut self,
        all_events: &mut Vec<PegOutEvent>,
    ) -> Result<Option<PegOutEvent>, String> {
        let mut events: Vec<PegOutEvent> = Vec::new();
        let mut ids: Vec<usize> = Vec::new();
        for (i, event) in all_events.iter().enumerate() {
            if self.peg_in_confirm_txid.eq(&event.source_outpoint.txid)
                && self.operator_public_key.eq(&event.operator_public_key)
            {
                events.push(event.clone());
                ids.push(i);
            }
        }
        ids.iter().for_each(|x| {
            all_events.swap_remove(*x);
        });

        match events.len() {
            0 => Ok(None),
            1 => {
                self.peg_out_chain_event = Some(events[0].clone());
                Ok(Some(events[0].clone()))
            }
            _ => Err(String::from("Event from L2 chain is not unique")),
        }
    }

    async fn get_peg_out_statuses(
        &self,
        client: &AsyncClient,
    ) -> (
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Option<Result<TxStatus, esplora_client::Error>>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
    ) {
        let assert_initial_status = client
            .get_tx_status(&self.assert_initial_transaction.tx().compute_txid())
            .await;

        let assert_commit_1_status = client
            .get_tx_status(&self.assert_commit_1_transaction.tx().compute_txid())
            .await;

        let assert_commit_2_status = client
            .get_tx_status(&self.assert_commit_2_transaction.tx().compute_txid())
            .await;

        let assert_final_status = client
            .get_tx_status(&self.assert_final_transaction.tx().compute_txid())
            .await;

        let challenge_status = client
            .get_tx_status(&self.challenge_transaction.tx().compute_txid())
            .await;

        let disprove_chain_status = client
            .get_tx_status(&self.disprove_chain_transaction.tx().compute_txid())
            .await;

        let disprove_status = client
            .get_tx_status(&self.disprove_transaction.tx().compute_txid())
            .await;

        let peg_out_confirm_status = client
            .get_tx_status(&self.peg_out_confirm_transaction.tx().compute_txid())
            .await;

        let kick_off_1_status = client
            .get_tx_status(&self.kick_off_1_transaction.tx().compute_txid())
            .await;

        let kick_off_2_status = client
            .get_tx_status(&self.kick_off_2_transaction.tx().compute_txid())
            .await;

        let kick_off_timeout_status = client
            .get_tx_status(&self.kick_off_timeout_transaction.tx().compute_txid())
            .await;

        let mut peg_out_status: Option<Result<TxStatus, esplora_client::Error>> = None;
        if self.peg_out_transaction.is_some() {
            peg_out_status = Some(
                client
                    .get_tx_status(
                        &self
                            .peg_out_transaction
                            .as_ref()
                            .unwrap()
                            .tx()
                            .compute_txid(),
                    )
                    .await,
            );
        }

        let start_time_timeout_status = client
            .get_tx_status(&self.start_time_timeout_transaction.tx().compute_txid())
            .await;

        let start_time_status = client
            .get_tx_status(&self.start_time_transaction.tx().compute_txid())
            .await;

        let take_1_status = client
            .get_tx_status(&self.take_1_transaction.tx().compute_txid())
            .await;

        let take_2_status = client
            .get_tx_status(&self.take_2_transaction.tx().compute_txid())
            .await;

        (
            assert_initial_status,
            assert_commit_1_status,
            assert_commit_2_status,
            assert_final_status,
            challenge_status,
            disprove_chain_status,
            disprove_status,
            peg_out_confirm_status,
            kick_off_1_status,
            kick_off_2_status,
            kick_off_timeout_status,
            peg_out_status,
            start_time_timeout_status,
            start_time_status,
            take_1_status,
            take_2_status,
        )
    }

    pub fn validate(&self) -> bool {
        let mut ret_val = true;
        let peg_out_graph = self.new_for_validation();
        if !validate_transaction(
            self.assert_initial_transaction.tx(),
            peg_out_graph.assert_initial_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.assert_commit_1_transaction.tx(),
            peg_out_graph.assert_commit_1_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.assert_commit_2_transaction.tx(),
            peg_out_graph.assert_commit_2_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.assert_final_transaction.tx(),
            peg_out_graph.assert_final_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.challenge_transaction.tx(),
            peg_out_graph.challenge_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.disprove_chain_transaction.tx(),
            peg_out_graph.disprove_chain_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.disprove_transaction.tx(),
            peg_out_graph.disprove_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.peg_out_confirm_transaction.tx(),
            peg_out_graph.peg_out_confirm_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.kick_off_1_transaction.tx(),
            peg_out_graph.kick_off_1_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.kick_off_2_transaction.tx(),
            peg_out_graph.kick_off_2_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.kick_off_timeout_transaction.tx(),
            peg_out_graph.kick_off_timeout_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.start_time_transaction.tx(),
            peg_out_graph.start_time_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.start_time_timeout_transaction.tx(),
            peg_out_graph.start_time_timeout_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.take_1_transaction.tx(),
            peg_out_graph.take_1_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.take_2_transaction.tx(),
            peg_out_graph.take_2_transaction.tx(),
        ) {
            ret_val = false;
        }

        if !verify_public_nonces_for_tx(&self.assert_initial_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.assert_final_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.disprove_chain_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.disprove_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.kick_off_timeout_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.start_time_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.start_time_timeout_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.take_1_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.take_2_transaction) {
            ret_val = false;
        }

        ret_val
    }

    pub fn merge(&mut self, source_peg_out_graph: &PegOutGraph) {
        self.assert_initial_transaction
            .merge(&source_peg_out_graph.assert_initial_transaction);

        self.assert_commit_1_transaction
            .merge(&source_peg_out_graph.assert_commit_1_transaction);

        self.assert_commit_2_transaction
            .merge(&source_peg_out_graph.assert_commit_2_transaction);

        self.assert_final_transaction
            .merge(&source_peg_out_graph.assert_final_transaction);

        self.challenge_transaction
            .merge(&source_peg_out_graph.challenge_transaction);

        self.disprove_chain_transaction
            .merge(&source_peg_out_graph.disprove_chain_transaction);

        self.disprove_transaction
            .merge(&source_peg_out_graph.disprove_transaction);

        self.kick_off_timeout_transaction
            .merge(&source_peg_out_graph.kick_off_timeout_transaction);

        self.start_time_transaction
            .merge(&source_peg_out_graph.start_time_transaction);

        self.start_time_timeout_transaction
            .merge(&source_peg_out_graph.start_time_timeout_transaction);

        self.take_1_transaction
            .merge(&source_peg_out_graph.take_1_transaction);

        self.take_2_transaction
            .merge(&source_peg_out_graph.take_2_transaction);
    }

    #[allow(clippy::too_many_arguments)]
    fn create_new_connectors(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        operator_public_key: &PublicKey,
        connector_1_commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
        connector_2_commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
        connector_6_commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
        connector_b_commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
        connector_e1_commitment_public_keys: &[BTreeMap<
            CommitmentMessageId,
            WinternitzPublicKey,
        >],
        connector_e2_commitment_public_keys: &[BTreeMap<
            CommitmentMessageId,
            WinternitzPublicKey,
        >],
    ) -> PegOutConnectors {
        let connector_0 = Connector0::new(network, n_of_n_taproot_public_key);
        let connector_1 = Connector1::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
            connector_1_commitment_public_keys,
        );
        let connector_2 = Connector2::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
            connector_2_commitment_public_keys,
        );
        let connector_3 = Connector3::new(network, operator_public_key);
        let connector_4 = Connector4::new(network, operator_public_key);
        let connector_5 = Connector5::new(network, n_of_n_taproot_public_key);
        let connector_6 = Connector6::new(
            network,
            operator_taproot_public_key,
            connector_6_commitment_public_keys,
        );
        let connector_a = ConnectorA::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(
            network,
            n_of_n_taproot_public_key,
            connector_b_commitment_public_keys,
        );

        // connector c pks = connector e1 pks + connector e2 pks
        let commitment_public_keys = &merge_to_connector_c_commits_public_key(
            connector_e1_commitment_public_keys,
            connector_e2_commitment_public_keys,
        );
        let connector_c = ConnectorC::new(
            network,
            operator_taproot_public_key,
            commitment_public_keys,
            ConnectorC::cache_id(commitment_public_keys)
                .inspect_err(|e| {
                    eprintln!("Failed to generate cache id: {}", e);
                })
                .ok(),
        );
        let connector_d = ConnectorD::new(network, n_of_n_taproot_public_key);

        let assert_commit_connectors_e_1 = AssertCommit1ConnectorsE {
            connectors_e: connector_e1_commitment_public_keys
                .iter()
                .map(|x| ConnectorE::new(network, operator_public_key, x))
                .collect(),
        };
        let assert_commit_connectors_e_2 = AssertCommit2ConnectorsE {
            connectors_e: connector_e2_commitment_public_keys
                .iter()
                .map(|x| ConnectorE::new(network, operator_public_key, x))
                .collect(),
        };

        let connector_f_1 = ConnectorF1::new(network, operator_public_key);
        let connector_f_2 = ConnectorF2::new(network, operator_public_key);

        PegOutConnectors {
            connector_0,
            connector_1,
            connector_2,
            connector_3,
            connector_4,
            connector_5,
            connector_6,
            connector_a,
            connector_b,
            connector_c,
            connector_d,
            assert_commit_connectors_e_1,
            assert_commit_connectors_e_2,
            assert_commit_connectors_f: AssertCommitConnectorsF {
                connector_f_1,
                connector_f_2,
            },
        }
    }

    fn all_presigned_txs(&self) -> impl Iterator<Item = &dyn PreSignedMusig2Transaction> {
        let all_txs: Vec<&dyn PreSignedMusig2Transaction> = vec![
            &self.assert_initial_transaction,
            &self.assert_final_transaction,
            &self.disprove_chain_transaction,
            &self.disprove_transaction,
            &self.kick_off_timeout_transaction,
            &self.start_time_timeout_transaction,
            &self.take_1_transaction,
            &self.take_2_transaction,
        ];
        all_txs.into_iter()
    }

    fn all_presigned_txs_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut dyn PreSignedMusig2Transaction> {
        let all_txs: Vec<&mut dyn PreSignedMusig2Transaction> = vec![
            &mut self.assert_initial_transaction,
            &mut self.assert_final_transaction,
            &mut self.disprove_chain_transaction,
            &mut self.disprove_transaction,
            &mut self.kick_off_timeout_transaction,
            &mut self.start_time_timeout_transaction,
            &mut self.take_1_transaction,
            &mut self.take_2_transaction,
        ];
        all_txs.into_iter()
    }

    pub fn has_all_nonces_of(&self, context: &VerifierContext) -> bool {
        self.all_presigned_txs()
            .all(|x| x.has_nonces_for(context.verifier_public_key))
    }
    pub fn has_all_nonces(&self, verifier_pubkeys: &[PublicKey]) -> bool {
        self.all_presigned_txs()
            .all(|x| x.has_all_nonces(verifier_pubkeys))
    }
    pub fn has_all_signatures_of(&self, context: &VerifierContext) -> bool {
        self.all_presigned_txs()
            .all(|x| x.has_signatures_for(context.verifier_public_key))
    }
    pub fn has_all_signatures(&self, verifier_pubkeys: &[PublicKey]) -> bool {
        self.all_presigned_txs()
            .all(|x| x.has_all_signatures(verifier_pubkeys))
    }
}

pub fn generate_id(peg_in_graph: &PegInGraph, operator_public_key: &PublicKey) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_graph.id().to_string() + &operator_public_key.to_string());

    hasher.finalize().to_hex_string(Upper)
}
