use bitcoin::{
    hashes::Hash,
    hex::{Case::Upper, DisplayHex},
    key::Keypair,
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Txid, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, Error, TxStatus};
use musig2::SecNonce;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result as FmtResult},
};

use crate::bridge::{
    superblock::{
        find_superblock, get_start_time_block_number, get_superblock_hash_message_digits,
        get_superblock_message_digits,
    },
    transactions::signing_winternitz::{WinternitzPublicKeyVariant, WinternitzSingingInputs},
};

use super::{
    super::{
        client::chain::chain::PegOutEvent,
        connectors::{
            connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
            connector_3::Connector3, connector_4::Connector4, connector_5::Connector5,
            connector_6::Connector6, connector_a::ConnectorA, connector_b::ConnectorB,
            connector_c::ConnectorC,
        },
        contexts::{base::BaseContext, operator::OperatorContext, verifier::VerifierContext},
        transactions::{
            assert::AssertTransaction,
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
            signing_winternitz::WinternitzPublicKey,
            signing_winternitz::WinternitzSecret,
            start_time::StartTimeTransaction,
            start_time_timeout::StartTimeTimeoutTransaction,
            take_1::Take1Transaction,
            take_2::Take2Transaction,
        },
    },
    base::{get_block_height, verify_if_not_mined, verify_tx_result, BaseGraph, GRAPH_VERSION},
    peg_in::PegInGraph,
};

pub enum PegOutWithdrawerStatus {
    PegOutNotStarted, // peg-out transaction not created yet
    PegOutWait,       // peg-out not confirmed yet, wait
    PegOutComplete,   // peg-out complete
}

impl Display for PegOutWithdrawerStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegOutWithdrawerStatus::PegOutNotStarted => {
                write!(f, "Peg-out available. Request peg-out?")
            }
            PegOutWithdrawerStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutWithdrawerStatus::PegOutComplete => write!(f, "Peg-out complete. Done."),
        }
    }
}

pub enum PegOutVerifierStatus {
    PegOutPresign,            // should presign peg-out graph
    PegOutComplete,           // peg-out complete
    PegOutWait,               // no action required, wait
    PegOutChallengeAvailable, // can call challenge
    PegOutStartTimeTimeoutAvailable,
    PegOutKickOffTimeoutAvailable,
    PegOutDisproveChainAvailable,
    PegOutDisproveAvailable,
    PegOutFailed, // timeouts or disproves executed
}

impl Display for PegOutVerifierStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegOutVerifierStatus::PegOutPresign => {
                write!(f, "Signatures required. Presign peg-out transactions?")
            }
            PegOutVerifierStatus::PegOutComplete => {
                write!(f, "Peg-out complete, reimbursement succeded. Done.")
            }
            PegOutVerifierStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutVerifierStatus::PegOutChallengeAvailable => {
                write!(
                    f,
                    "Kick-off 1 transaction confirmed, dispute available. Broadcast challenge transaction?"
                )
            }
            PegOutVerifierStatus::PegOutStartTimeTimeoutAvailable => {
                write!(f, "Start time timed out. Broadcast timeout transaction?")
            }
            PegOutVerifierStatus::PegOutKickOffTimeoutAvailable => {
                write!(f, "Kick-off 1 timed out. Broadcast timeout transaction?")
            }
            PegOutVerifierStatus::PegOutDisproveChainAvailable => {
                write!(
                    f,
                    "Kick-off 2 transaction confirmed. Broadcast disprove chain transaction?"
                )
            }
            PegOutVerifierStatus::PegOutDisproveAvailable => {
                write!(
                    f,
                    "Assert transaction confirmed. Broadcast disprove transaction?"
                )
            }
            PegOutVerifierStatus::PegOutFailed => {
                write!(f, "Peg-out complete, reimbursement failed. Done.")
            }
        }
    }
}

pub enum PegOutOperatorStatus {
    PegOutWait,
    PegOutComplete,    // peg-out complete
    PegOutFailed,      // timeouts or disproves executed
    PegOutStartPegOut, // should execute peg-out tx
    PegOutPegOutConfirmAvailable,
    PegOutKickOff1Available,
    PegOutStartTimeAvailable,
    PegOutKickOff2Available,
    PegOutAssertAvailable,
    PegOutTake1Available,
    PegOutTake2Available,
}

impl Display for PegOutOperatorStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegOutOperatorStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutOperatorStatus::PegOutComplete => {
                write!(f, "Peg-out complete, reimbursement succeded. Done.")
            }
            PegOutOperatorStatus::PegOutFailed => {
                write!(f, "Peg-out complete, reimbursement failed. Done.")
            }
            PegOutOperatorStatus::PegOutStartPegOut => {
                write!(
                    f,
                    "Peg-out requested. Create and broadcast peg-out transaction?"
                )
            }
            PegOutOperatorStatus::PegOutPegOutConfirmAvailable => {
                write!(
                    f,
                    "Peg-out confirmed. Broadcast peg-out-confirm transaction?"
                )
            }
            PegOutOperatorStatus::PegOutKickOff1Available => {
                write!(
                    f,
                    "Peg-out-confirm confirmed. Broadcast kick-off 1 transaction?"
                )
            }
            PegOutOperatorStatus::PegOutStartTimeAvailable => {
                write!(f, "Kick-off confirmed. Broadcast start time transaction?")
            }
            PegOutOperatorStatus::PegOutKickOff2Available => {
                write!(f, "Start time confirmed. Broadcast kick-off 2 transaction?")
            }
            PegOutOperatorStatus::PegOutAssertAvailable => {
                write!(f, "Dispute raised. Broadcast assert transaction?")
            }
            PegOutOperatorStatus::PegOutTake1Available => write!(
                f,
                "Dispute timed out, reimbursement available. Broadcast take 1 transaction?"
            ),
            PegOutOperatorStatus::PegOutTake2Available => write!(
                f,
                "Dispute timed out, reimbursement available. Broadcast take 2 transaction?"
            ),
        }
    }
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
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub enum CommitmentMessageId {
    PegOutTxIdSourceNetwork,
    PegOutTxIdDestinationNetwork,
    StartTime,
    Superblock,
    SuperblockHash,
}

impl CommitmentMessageId {
    pub fn generate_commitment_secrets() -> HashMap<CommitmentMessageId, WinternitzSecret> {
        HashMap::from([
            (
                CommitmentMessageId::PegOutTxIdSourceNetwork,
                WinternitzSecret::new(),
            ),
            (
                CommitmentMessageId::PegOutTxIdDestinationNetwork,
                WinternitzSecret::new(),
            ),
            (CommitmentMessageId::StartTime, WinternitzSecret::new()),
            (CommitmentMessageId::Superblock, WinternitzSecret::new()),
            (CommitmentMessageId::SuperblockHash, WinternitzSecret::new()),
        ])
    }
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

    peg_out_confirm_transaction: PegOutConfirmTransaction,
    assert_transaction: AssertTransaction,
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
}

impl PegOutGraph {
    pub fn new(
        context: &OperatorContext,
        peg_in_graph: &PegInGraph,
        peg_out_confirm_input: Input,
    ) -> (Self, HashMap<CommitmentMessageId, WinternitzSecret>) {
        let peg_in_confirm_transaction = peg_in_graph.peg_in_confirm_transaction_ref();
        let peg_in_confirm_txid = peg_in_confirm_transaction.tx().compute_txid();

        let commitment_secrets = CommitmentMessageId::generate_commitment_secrets();
        let connector_1_commitment_public_keys = HashMap::from([
            (
                CommitmentMessageId::Superblock,
                WinternitzPublicKeyVariant::Standard(WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::Superblock],
                )),
            ),
            (
                CommitmentMessageId::SuperblockHash,
                WinternitzPublicKeyVariant::Standard(WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::SuperblockHash],
                )),
            ),
        ]);
        let connector_2_commitment_public_keys = HashMap::from([(
            CommitmentMessageId::StartTime,
            WinternitzPublicKeyVariant::CompactN32(WinternitzPublicKey::from(
                &commitment_secrets[&CommitmentMessageId::StartTime],
            )),
        )]);
        let connector_6_commitment_public_keys = HashMap::from([
            (
                CommitmentMessageId::PegOutTxIdSourceNetwork,
                WinternitzPublicKeyVariant::Standard(WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::PegOutTxIdSourceNetwork],
                )),
            ),
            (
                CommitmentMessageId::PegOutTxIdDestinationNetwork,
                WinternitzPublicKeyVariant::Standard(WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::PegOutTxIdDestinationNetwork],
                )),
            ),
        ]);

        let connectors = Self::create_new_connectors(
            context.network,
            &context.n_of_n_taproot_public_key,
            &context.operator_taproot_public_key,
            &context.operator_public_key,
            &connector_1_commitment_public_keys,
            &connector_2_commitment_public_keys,
            &connector_6_commitment_public_keys,
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

        let input_amount_crowdfunding = Amount::from_btc(1.0).unwrap(); // TODO replace placeholder
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

        let assert_vout_0 = 1;
        let assert_transaction = AssertTransaction::new(
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_b,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: assert_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[assert_vout_0].value,
            },
        );
        let assert_txid = assert_transaction.tx().compute_txid();

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
                    txid: assert_txid,
                    vout: take_2_vout_1.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[take_2_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: take_2_vout_2.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[take_2_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: take_2_vout_3.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[take_2_vout_3].value,
            },
        );

        let script_index = 1; // TODO replace placeholder
        let disprove_vout_0 = 1;
        let disprove_vout_1 = 2;
        let disprove_transaction = DisproveTransaction::new(
            context,
            &connectors.connector_5,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout_0.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[disprove_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout_1.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[disprove_vout_1].value,
            },
            script_index,
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

        (
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
                peg_out_confirm_transaction,
                assert_transaction,
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
            },
            commitment_secrets,
        )
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
            &self.n_of_n_taproot_public_key,
            &connectors.connector_1,
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

        let input_amount_crowdfunding = Amount::from_btc(1.0).unwrap(); // TODO replace placeholder
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

        let assert_vout_0 = 1;
        let assert_transaction = AssertTransaction::new_for_validation(
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_b,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: assert_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[assert_vout_0].value,
            },
        );
        let assert_txid = assert_transaction.tx().compute_txid();

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
                    txid: assert_txid,
                    vout: take_2_vout_1.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[take_2_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: take_2_vout_2.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[take_2_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: take_2_vout_3.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[take_2_vout_3].value,
            },
        );

        let script_index = 1; // TODO replace placeholder
        let disprove_vout_0 = 1;
        let disprove_vout_1 = 2;
        let disprove_transaction = DisproveTransaction::new_for_validation(
            self.network,
            &self.connector_5,
            &self.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout_0.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[disprove_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout_1.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[disprove_vout_1].value,
            },
            script_index,
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
            peg_out_confirm_transaction,
            assert_transaction,
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

    pub fn push_nonces(
        &mut self,
        context: &VerifierContext,
    ) -> HashMap<Txid, HashMap<usize, SecNonce>> {
        let mut secret_nonces = HashMap::new();

        secret_nonces.insert(
            self.assert_transaction.tx().compute_txid(),
            self.assert_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.disprove_chain_transaction.tx().compute_txid(),
            self.disprove_chain_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.disprove_transaction.tx().compute_txid(),
            self.disprove_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.kick_off_timeout_transaction.tx().compute_txid(),
            self.kick_off_timeout_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.start_time_timeout_transaction.tx().compute_txid(),
            self.start_time_timeout_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.take_1_transaction.tx().compute_txid(),
            self.take_1_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.take_2_transaction.tx().compute_txid(),
            self.take_2_transaction.push_nonces(context),
        );

        secret_nonces
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        secret_nonces: &HashMap<Txid, HashMap<usize, SecNonce>>,
    ) {
        self.assert_transaction.pre_sign(
            context,
            &self.connector_b,
            &secret_nonces[&self.assert_transaction.tx().compute_txid()],
        );
        self.disprove_chain_transaction.pre_sign(
            context,
            &self.connector_b,
            &secret_nonces[&self.disprove_chain_transaction.tx().compute_txid()],
        );
        self.disprove_transaction.pre_sign(
            context,
            &self.connector_5,
            &secret_nonces[&self.disprove_transaction.tx().compute_txid()],
        );
        self.kick_off_timeout_transaction.pre_sign(
            context,
            &self.connector_1,
            &secret_nonces[&self.kick_off_timeout_transaction.tx().compute_txid()],
        );
        self.start_time_timeout_transaction.pre_sign(
            context,
            &self.connector_1,
            &self.connector_2,
            &secret_nonces[&self.start_time_timeout_transaction.tx().compute_txid()],
        );
        self.take_1_transaction.pre_sign(
            context,
            &self.connector_0,
            &self.connector_b,
            &secret_nonces[&self.take_1_transaction.tx().compute_txid()],
        );
        self.take_2_transaction.pre_sign(
            context,
            &self.connector_0,
            &self.connector_5,
            &secret_nonces[&self.take_2_transaction.tx().compute_txid()],
        );

        self.n_of_n_presigned = true; // TODO: set to true after collecting all n of n signatures
    }

    pub async fn verifier_status(&self, client: &AsyncClient) -> PegOutVerifierStatus {
        if self.n_of_n_presigned {
            let (
                assert_status,
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
            let blockchain_height = get_block_height(client).await;

            if kick_off_2_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                if take_1_status.as_ref().is_ok_and(|status| status.confirmed)
                    || take_2_status.as_ref().is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutComplete;
                } else if disprove_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                    || disprove_chain_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutFailed; // TODO: can be also `PegOutVerifierStatus::PegOutComplete`
                } else if assert_status.as_ref().is_ok_and(|status| status.confirmed) {
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
                            block_height + self.connector_1.num_blocks_timelock_leaf_2
                                > blockchain_height
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
                        block_height + self.connector_1.num_blocks_timelock_leaf_1
                            > blockchain_height
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
            return PegOutVerifierStatus::PegOutPresign;
        }
    }

    pub async fn operator_status(&self, client: &AsyncClient) -> PegOutOperatorStatus {
        if self.n_of_n_presigned && self.is_peg_out_initiated() {
            let (
                assert_status,
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
            let blockchain_height = get_block_height(client).await;

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
                        if assert_status.as_ref().is_ok_and(|status| status.confirmed) {
                            if assert_status.as_ref().unwrap().block_height.is_some_and(
                                |block_height| {
                                    block_height + self.connector_4.num_blocks_timelock
                                        <= blockchain_height
                                },
                            ) {
                                return PegOutOperatorStatus::PegOutTake2Available;
                            } else {
                                return PegOutOperatorStatus::PegOutWait;
                            }
                        } else {
                            if kick_off_2_status
                                .as_ref()
                                .unwrap()
                                .block_height
                                .is_some_and(|block_height| {
                                    block_height + self.connector_b.num_blocks_timelock_1
                                        <= blockchain_height
                                })
                            {
                                return PegOutOperatorStatus::PegOutAssertAvailable;
                            } else {
                                return PegOutOperatorStatus::PegOutWait;
                            }
                        }
                    } else {
                        if kick_off_2_status
                            .as_ref()
                            .unwrap()
                            .block_height
                            .is_some_and(|block_height| {
                                block_height + self.connector_3.num_blocks_timelock
                                    <= blockchain_height
                            })
                        {
                            return PegOutOperatorStatus::PegOutTake1Available;
                        } else {
                            return PegOutOperatorStatus::PegOutWait;
                        }
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
                                block_height + self.connector_1.num_blocks_timelock_leaf_0
                                    <= blockchain_height
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

        return PegOutOperatorStatus::PegOutWait;
    }

    pub fn interpret_operator_status(
        &self,
        peg_out_status: Option<&Result<TxStatus, Error>>,
    ) -> PegOutWithdrawerStatus {
        if peg_out_status.is_some() {
            if peg_out_status
                .unwrap()
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                return PegOutWithdrawerStatus::PegOutComplete;
            } else {
                return PegOutWithdrawerStatus::PegOutWait;
            }
        } else {
            return PegOutWithdrawerStatus::PegOutNotStarted;
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
        self.interpret_operator_status(peg_out_status.as_ref())
    }

    pub async fn peg_out(&mut self, client: &AsyncClient, context: &OperatorContext, input: Input) {
        if !self.is_peg_out_initiated() {
            panic!("Peg out not initiated on L2 chain");
        }

        if self.peg_out_transaction.is_some() {
            let txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid();
            verify_if_not_mined(&client, txid).await;
        } else {
            let event = self.peg_out_chain_event.as_ref().unwrap();
            let tx = PegOutTransaction::new(context, event, input);
            self.peg_out_transaction = Some(tx);
        }

        let peg_out_tx = self.peg_out_transaction.as_ref().unwrap().finalize();

        let peg_out_result = client.broadcast(&peg_out_tx).await;

        verify_tx_result(&peg_out_result);
    }

    pub async fn peg_out_confirm(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.peg_out_confirm_transaction.tx().compute_txid()).await;

        if self.peg_out_transaction.as_ref().is_some() {
            let peg_out_txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid();
            let peg_out_status = client.get_tx_status(&peg_out_txid).await;

            if peg_out_status.is_ok_and(|status| status.confirmed) {
                // complete peg-out-confirm tx
                let peg_out_confirm_tx = self.peg_out_confirm_transaction.finalize();

                // broadcast peg-out-confirm tx
                let peg_out_confirm_result = client.broadcast(&peg_out_confirm_tx).await;

                // verify peg-out-confirm tx result
                verify_tx_result(&peg_out_confirm_result);
            } else {
                panic!("Peg-out tx has not been confirmed!");
            }
        } else {
            panic!("Peg-out tx has not been created!");
        }
    }

    pub async fn kick_off_1(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        source_network_txid_commitment_secret: &WinternitzSecret,
        destination_network_txid_commitment_secret: &WinternitzSecret,
    ) {
        verify_if_not_mined(&client, self.kick_off_1_transaction.tx().compute_txid()).await;

        let peg_out_confirm_txid = self.peg_out_confirm_transaction.tx().compute_txid();
        let peg_out_confirm_status = client.get_tx_status(&peg_out_confirm_txid).await;

        if peg_out_confirm_status.is_ok_and(|status| status.confirmed) {
            // complete kick-off 1 tx
            let pegout_txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid()
                .as_byte_array()
                .to_owned();
            let source_network_txid_inputs = WinternitzSingingInputs {
                message_digits: &pegout_txid,
                signing_key: source_network_txid_commitment_secret,
            };
            let destination_network_txid_inputs = WinternitzSingingInputs {
                message_digits: self
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
            let kick_off_1_tx = self.kick_off_1_transaction.finalize();

            // broadcast kick-off 1 tx
            let kick_off_1_result = client.broadcast(&kick_off_1_tx).await;

            // verify kick-off 1 tx result
            verify_tx_result(&kick_off_1_result);
        } else {
            panic!("Peg-out-confirm tx has not been confirmed!");
        }
    }

    pub async fn challenge(
        &mut self,
        client: &AsyncClient,
        context: &dyn BaseContext,
        crowdfundng_inputs: &Vec<InputWithScript<'_>>,
        keypair: &Keypair,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        if kick_off_1_status.is_ok_and(|status| status.confirmed) {
            // complete challenge tx
            self.challenge_transaction.add_inputs_and_output(
                context,
                crowdfundng_inputs,
                keypair,
                output_script_pubkey,
            );
            let challenge_tx = self.challenge_transaction.finalize();

            // broadcast challenge tx
            let challenge_result = client.broadcast(&challenge_tx).await;

            // verify challenge tx result
            verify_tx_result(&challenge_result);
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn start_time(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        start_time_commitment_secret: &WinternitzSecret,
    ) {
        verify_if_not_mined(client, self.start_time_transaction.tx().compute_txid()).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        if kick_off_1_status.is_ok_and(|status| status.confirmed) {
            // sign start time tx
            self.start_time_transaction.sign(
                context,
                &self.connector_2,
                get_start_time_block_number(),
                start_time_commitment_secret,
            );

            // complete start time tx
            let start_time_tx = self.start_time_transaction.finalize();

            // broadcast start time tx
            let start_time_result = client.broadcast(&start_time_tx).await;

            // verify start time tx result
            verify_tx_result(&start_time_result);
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn start_time_timeout(
        &mut self,
        client: &AsyncClient,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(
            client,
            self.start_time_timeout_transaction.tx().compute_txid(),
        )
        .await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_1_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_1_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_1.num_blocks_timelock_leaf_2 <= blockchain_height
                })
            {
                // complete start time timeout tx
                self.start_time_timeout_transaction
                    .add_output(output_script_pubkey);
                let start_time_timeout_tx = self.start_time_timeout_transaction.finalize();

                // broadcast start time timeout tx
                let start_time_timeout_result = client.broadcast(&start_time_timeout_tx).await;

                // verify start time timeout tx result
                verify_tx_result(&start_time_timeout_result);
            } else {
                panic!("Kick-off 1 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn kick_off_2(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        superblock_commitment_secret: &WinternitzSecret,
        superblock_hash_commitment_secret: &WinternitzSecret,
    ) {
        verify_if_not_mined(client, self.kick_off_2_transaction.tx().compute_txid()).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_1_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_1_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_1.num_blocks_timelock_leaf_0 <= blockchain_height
                })
            {
                // complete kick-off 2 tx
                let superblock_header = find_superblock();
                self.kick_off_2_transaction.sign(
                    context,
                    &self.connector_1,
                    &WinternitzSingingInputs {
                        message_digits: &get_superblock_message_digits(&superblock_header),
                        signing_key: superblock_commitment_secret,
                    },
                    &WinternitzSingingInputs {
                        message_digits: &get_superblock_hash_message_digits(&superblock_header),
                        signing_key: superblock_hash_commitment_secret,
                    },
                );
                let kick_off_2_tx = self.kick_off_2_transaction.finalize();

                // broadcast kick-off 2 tx
                let kick_off_2_result = client.broadcast(&kick_off_2_tx).await;

                // verify kick-off 2 tx result
                verify_tx_result(&kick_off_2_result);
            } else {
                panic!("Kick-off 1 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn kick_off_timeout(
        &mut self,
        client: &AsyncClient,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(
            client,
            self.kick_off_timeout_transaction.tx().compute_txid(),
        )
        .await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_1_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_1_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_1.num_blocks_timelock_leaf_1 <= blockchain_height
                })
            {
                // complete kick-off timeout tx
                let kick_off_timeout_tx = self.kick_off_timeout_transaction.finalize();

                // broadcast kick-off timeout tx
                self.kick_off_timeout_transaction
                    .add_output(output_script_pubkey);
                let kick_off_timeout_result = client.broadcast(&kick_off_timeout_tx).await;

                // verify kick-off timeout tx result
                verify_tx_result(&kick_off_timeout_result);
            } else {
                panic!("Kick-off 1 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn assert(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.assert_transaction.tx().compute_txid()).await;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_2_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_2_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_b.num_blocks_timelock_1 <= blockchain_height
                })
            {
                // complete assert tx
                let assert_tx = self.assert_transaction.finalize();

                // broadcast assert tx
                let assert_result = client.broadcast(&assert_tx).await;

                // verify assert tx result
                verify_tx_result(&assert_result);
            } else {
                panic!("Kick-off 2 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 2 tx has not been confirmed!");
        }
    }

    pub async fn disprove(
        &mut self,
        client: &AsyncClient,
        input_script_index: u32,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await;

        let assert_txid = self.assert_transaction.tx().compute_txid();
        let assert_status = client.get_tx_status(&assert_txid).await;

        if assert_status.is_ok_and(|status| status.confirmed) {
            // complete disprove tx
            self.disprove_transaction.add_input_output(
                &self.connector_c,
                input_script_index,
                output_script_pubkey,
            );
            let disprove_tx = self.disprove_transaction.finalize();

            // broadcast disprove tx
            let disprove_result = client.broadcast(&disprove_tx).await;

            // verify disprove tx result
            verify_tx_result(&disprove_result);
        } else {
            panic!("Assert tx has not been confirmed!");
        }
    }

    pub async fn disprove_chain(&mut self, client: &AsyncClient, output_script_pubkey: ScriptBuf) {
        verify_if_not_mined(client, self.disprove_chain_transaction.tx().compute_txid()).await;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        if kick_off_2_status.is_ok_and(|status| status.confirmed) {
            // complete disprove chain tx
            self.disprove_chain_transaction
                .add_output(output_script_pubkey);
            let disprove_chain_tx = self.disprove_chain_transaction.finalize();

            // broadcast disprove chain tx
            let disprove_chain_result = client.broadcast(&disprove_chain_tx).await;

            // verify disprove chain tx result
            verify_tx_result(&disprove_chain_result);
        } else {
            panic!("Kick-off 2 tx has not been confirmed!");
        }
    }

    pub async fn take_1(&mut self, client: &AsyncClient) {
        verify_if_not_mined(&client, self.take_1_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.challenge_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.assert_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.disprove_chain_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        let blockchain_height = get_block_height(client).await;

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed)
            && kick_off_1_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            && kick_off_2_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
        {
            if kick_off_2_status
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_3.num_blocks_timelock <= blockchain_height
                })
            {
                // complete take 1 tx
                let take_1_tx = self.take_1_transaction.finalize();

                // broadcast take 1 tx
                let take_1_result = client.broadcast(&take_1_tx).await;

                // verify take 1 tx result
                verify_tx_result(&take_1_result);
            } else {
                panic!("Kick-off 2 tx timelock has not elapsed!");
            }
        } else {
            panic!("Peg-in confirm tx, kick-off 1 and kick-off 2 tx have not been confirmed!");
        }
    }

    pub async fn take_2(&mut self, client: &AsyncClient) {
        verify_if_not_mined(&client, self.take_2_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.take_1_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.disprove_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;

        let assert_txid = self.assert_transaction.tx().compute_txid();
        let assert_status = client.get_tx_status(&assert_txid).await;

        let blockchain_height = get_block_height(client).await;

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed)
            && assert_status.as_ref().is_ok_and(|status| status.confirmed)
        {
            if assert_status
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_4.num_blocks_timelock <= blockchain_height
                })
            {
                // complete take 2 tx
                let take_2_tx = self.take_2_transaction.finalize();

                // broadcast take 2 tx
                let take_2_result = client.broadcast(&take_2_tx).await;

                // verify take 2 tx result
                verify_tx_result(&take_2_result);
            } else {
                panic!("Assert tx timelock has not elapsed!");
            }
        } else {
            panic!("Peg-in confirm tx and assert tx have not been confirmed!");
        }
    }

    pub fn is_peg_out_initiated(&self) -> bool { return self.peg_out_chain_event.is_some(); }

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
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Option<Result<TxStatus, Error>>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
    ) {
        let assert_status = client
            .get_tx_status(&self.assert_transaction.tx().compute_txid())
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

        let mut peg_out_status: Option<Result<TxStatus, Error>> = None;
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

        return (
            assert_status,
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
        );
    }

    pub fn validate(&self) -> bool {
        let mut ret_val = true;
        let peg_out_graph = self.new_for_validation();
        if !validate_transaction(
            self.assert_transaction.tx(),
            peg_out_graph.assert_transaction.tx(),
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

        if !verify_public_nonces_for_tx(&self.assert_transaction) {
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
        self.assert_transaction
            .merge(&source_peg_out_graph.assert_transaction);

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

    fn create_new_connectors(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        operator_public_key: &PublicKey,
        connector_1_commitment_public_keys: &HashMap<
            CommitmentMessageId,
            WinternitzPublicKeyVariant,
        >,
        connector_2_commitment_public_keys: &HashMap<
            CommitmentMessageId,
            WinternitzPublicKeyVariant,
        >,
        connector_6_commitment_public_keys: &HashMap<
            CommitmentMessageId,
            WinternitzPublicKeyVariant,
        >,
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
        let connector_b = ConnectorB::new(network, n_of_n_taproot_public_key);
        let connector_c = ConnectorC::new(network, operator_taproot_public_key);

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
        }
    }
}

pub fn generate_id(peg_in_graph: &PegInGraph, operator_public_key: &PublicKey) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_graph.id().to_string() + &operator_public_key.to_string());

    hasher.finalize().to_hex_string(Upper)
}
