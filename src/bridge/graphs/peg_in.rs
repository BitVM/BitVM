use bitcoin::{
    hex::{Case::Upper, DisplayHex},
    Network, OutPoint, PublicKey, Txid, XOnlyPublicKey,
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

use super::{
    super::{
        contexts::{depositor::DepositorContext, verifier::VerifierContext},
        graphs::base::get_block_height,
        transactions::{
            base::{validate_transaction, BaseTransaction, Input},
            peg_in_confirm::PegInConfirmTransaction,
            peg_in_deposit::PegInDepositTransaction,
            peg_in_refund::PegInRefundTransaction,
            pre_signed::PreSignedTransaction,
        },
        utils::get_num_blocks_per_2_weeks,
    },
    base::{verify_if_not_mined, verify_tx_result, BaseGraph, GRAPH_VERSION},
};

pub enum PegInDepositorStatus {
    PegInDepositWait,     // peg-in deposit not yet confirmed
    PegInConfirmWait, // peg-in confirm not yet confirmed, wait for operator to complete peg-in, refund not available yet
    PegInConfirmComplete, // peg-in complete
    PegInRefundAvailable, // peg-in refund available
    PegInRefundComplete, // peg-in failed, refund complete
}

impl Display for PegInDepositorStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegInDepositorStatus::PegInDepositWait => {
                write!(f, "Peg-in deposit transaction not confirmed yet. Wait...")
            }
            PegInDepositorStatus::PegInConfirmWait => {
                write!(f, "Peg-in confirm transaction not confirmed yet. Wait...")
            }
            PegInDepositorStatus::PegInConfirmComplete => {
                write!(f, "Peg-in complete. Done.")
            }
            PegInDepositorStatus::PegInRefundAvailable => {
                write!(f, "Peg-in timed out. Broadcast refund transaction?")
            }
            PegInDepositorStatus::PegInRefundComplete => {
                write!(f, "Peg-in refund complete, funds reclaimed. Done.")
            }
        }
    }
}

pub enum PegInVerifierStatus {
    PegInWait,     // no action required, wait
    PegInPresign,  // should presign peg-in confirm
    PegInComplete, // peg-in complete
}

impl Display for PegInVerifierStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegInVerifierStatus::PegInWait => write!(f, "No action available. Wait..."),
            PegInVerifierStatus::PegInPresign => {
                write!(f, "Signature required. Presign peg-in confirm transaction?")
            }
            PegInVerifierStatus::PegInComplete => write!(f, "Peg-in complete. Done."),
        }
    }
}

pub enum PegInOperatorStatus {
    PegInWait,             // peg-in not yet complete, no action required yet, wait
    PegInConfirmAvailable, // should execute peg-in confirm
    PegInComplete,         // peg-in complete
}

impl Display for PegInOperatorStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegInOperatorStatus::PegInWait => {
                write!(f, "No action available. Wait...")
            }
            PegInOperatorStatus::PegInConfirmAvailable => {
                write!(
                    f,
                    "Peg-in confirm transaction ready. Broadcast peg-in confirm transaction?"
                )
            }
            PegInOperatorStatus::PegInComplete => write!(f, "Peg-in complete. Done."),
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInGraph {
    version: String,
    network: Network,
    id: String,

    pub peg_in_deposit_transaction: PegInDepositTransaction,
    peg_in_refund_transaction: PegInRefundTransaction,
    peg_in_confirm_transaction: PegInConfirmTransaction,

    n_of_n_presigned: bool,
    n_of_n_public_key: PublicKey,
    n_of_n_taproot_public_key: XOnlyPublicKey,

    pub depositor_public_key: PublicKey,
    depositor_taproot_public_key: XOnlyPublicKey,
    depositor_evm_address: String,
}

impl BaseGraph for PegInGraph {
    fn network(&self) -> Network { self.network }

    fn id(&self) -> &String { &self.id }
}

impl PegInGraph {
    pub fn new(context: &DepositorContext, deposit_input: Input, evm_address: &str) -> Self {
        let peg_in_deposit_transaction =
            PegInDepositTransaction::new(context, evm_address, deposit_input);
        let peg_in_deposit_txid = peg_in_deposit_transaction.tx().compute_txid();

        let peg_in_refund_vout0: usize = 0;
        let peg_in_refund_transaction = PegInRefundTransaction::new(
            context,
            evm_address,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_deposit_txid,
                    vout: peg_in_refund_vout0.to_u32().unwrap(),
                },
                amount: peg_in_deposit_transaction.tx().output[peg_in_refund_vout0].value,
            },
        );

        let peg_in_confirm_vout0: usize = 0;
        let peg_in_confirm_transaction = PegInConfirmTransaction::new(
            context,
            evm_address,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_deposit_txid,
                    vout: peg_in_confirm_vout0.to_u32().unwrap(),
                },
                amount: peg_in_deposit_transaction.tx().output[peg_in_confirm_vout0].value,
            },
        );

        PegInGraph {
            version: GRAPH_VERSION.to_string(),
            network: context.network,
            id: generate_id(&peg_in_deposit_transaction),
            peg_in_deposit_transaction,
            peg_in_refund_transaction,
            peg_in_confirm_transaction,
            n_of_n_presigned: false,
            n_of_n_public_key: context.n_of_n_public_key,
            n_of_n_taproot_public_key: context.n_of_n_taproot_public_key,
            depositor_public_key: context.depositor_public_key,
            depositor_taproot_public_key: context.depositor_taproot_public_key,
            depositor_evm_address: evm_address.to_string(),
        }
    }

    pub fn new_for_validation(&self) -> Self {
        let peg_in_deposit_transaction = PegInDepositTransaction::new_for_validation(
            self.network,
            &self.depositor_public_key,
            &self.depositor_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            &self.depositor_evm_address,
            Input {
                outpoint: self.peg_in_deposit_transaction.tx().input[0].previous_output, // Self-referencing
                amount: self.peg_in_deposit_transaction.prev_outs()[0].value, // Self-referencing
            },
        );
        let peg_in_deposit_txid = peg_in_deposit_transaction.tx().compute_txid();

        let peg_in_refund_vout0: usize = 0;
        let peg_in_refund_transaction = PegInRefundTransaction::new_for_validation(
            self.network,
            &self.depositor_public_key,
            &self.depositor_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            &self.depositor_evm_address,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_deposit_txid,
                    vout: peg_in_refund_vout0.to_u32().unwrap(),
                },
                amount: peg_in_deposit_transaction.tx().output[peg_in_refund_vout0].value,
            },
        );

        let peg_in_confirm_vout0: usize = 0;
        let peg_in_confirm_transaction = PegInConfirmTransaction::new_for_validation(
            self.network,
            &self.depositor_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            &self.depositor_evm_address,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_deposit_txid,
                    vout: peg_in_confirm_vout0.to_u32().unwrap(),
                },
                amount: peg_in_deposit_transaction.tx().output[peg_in_confirm_vout0].value,
            },
        );

        PegInGraph {
            version: GRAPH_VERSION.to_string(),
            network: self.network,
            id: generate_id(&peg_in_deposit_transaction),
            peg_in_deposit_transaction,
            peg_in_refund_transaction,
            peg_in_confirm_transaction,
            n_of_n_presigned: false,
            n_of_n_public_key: self.n_of_n_public_key,
            n_of_n_taproot_public_key: self.n_of_n_taproot_public_key,
            depositor_public_key: self.depositor_public_key,
            depositor_taproot_public_key: self.depositor_taproot_public_key,
            depositor_evm_address: self.depositor_evm_address.clone(),
        }
    }

    pub fn push_nonces(
        &mut self,
        context: &VerifierContext,
    ) -> HashMap<Txid, HashMap<usize, SecNonce>> {
        let mut secret_nonces = HashMap::new();

        secret_nonces.insert(
            self.peg_in_confirm_transaction.tx().compute_txid(),
            self.peg_in_confirm_transaction.push_nonces(context),
        );

        secret_nonces
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        secret_nonces: &HashMap<Txid, HashMap<usize, SecNonce>>,
    ) {
        self.peg_in_confirm_transaction.pre_sign(
            context,
            &secret_nonces[&self.peg_in_confirm_transaction.tx().compute_txid()],
        );

        self.n_of_n_presigned = true; // TODO: set to true after collecting all n of n signatures
    }

    pub fn peg_in_confirm_transaction_ref(&self) -> &PegInConfirmTransaction {
        &self.peg_in_confirm_transaction
    }

    pub async fn verifier_status(&self, client: &AsyncClient) -> PegInVerifierStatus {
        let (peg_in_deposit_status, peg_in_confirm_status, _) =
            Self::get_peg_in_statuses(self, client).await;

        if peg_in_deposit_status.is_ok_and(|status| status.confirmed) {
            if peg_in_confirm_status.is_ok_and(|status| status.confirmed) {
                // peg in complete
                return PegInVerifierStatus::PegInComplete;
            } else {
                if self.n_of_n_presigned {
                    // peg-in confirm presigned, wait
                    return PegInVerifierStatus::PegInWait;
                } else {
                    // should presign peg-in confirm
                    return PegInVerifierStatus::PegInPresign;
                }
            }
        } else {
            // peg-in deposit not confirmed yet, wait
            return PegInVerifierStatus::PegInWait;
        }
    }

    pub async fn operator_status(&self, client: &AsyncClient) -> PegInOperatorStatus {
        let (peg_in_deposit_status, peg_in_confirm_status, _) =
            Self::get_peg_in_statuses(self, client).await;

        if peg_in_deposit_status.is_ok_and(|status| status.confirmed) {
            if peg_in_confirm_status.is_ok_and(|status| status.confirmed) {
                // peg in complete
                return PegInOperatorStatus::PegInComplete;
            } else {
                if self.n_of_n_presigned {
                    // should execute peg-in confirm
                    return PegInOperatorStatus::PegInConfirmAvailable;
                } else {
                    // peg-in confirm not yet presigned, wait
                    return PegInOperatorStatus::PegInWait;
                }
            }
        } else {
            // peg-in deposit not confirmed yet, wait
            return PegInOperatorStatus::PegInWait;
        }
    }

    pub async fn depositor_status(&self, client: &AsyncClient) -> PegInDepositorStatus {
        let (peg_in_deposit_status, peg_in_confirm_status, peg_in_refund_status) =
            Self::get_peg_in_statuses(self, client).await;

        let blockchain_height = get_block_height(client).await;

        if peg_in_deposit_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if peg_in_confirm_status.is_ok_and(|status| status.confirmed) {
                // peg-in complete
                return PegInDepositorStatus::PegInConfirmComplete;
            } else {
                if peg_in_deposit_status
                    .unwrap()
                    .block_height
                    .is_some_and(|block_height| {
                        block_height + get_num_blocks_per_2_weeks(self.network) <= blockchain_height
                    })
                {
                    if peg_in_refund_status.is_ok_and(|status| status.confirmed) {
                        // peg-in refund complete
                        return PegInDepositorStatus::PegInRefundComplete;
                    } else {
                        // peg-in refund available
                        return PegInDepositorStatus::PegInRefundAvailable;
                    }
                } else {
                    // peg-in confirm not confirmed yet, refund not available yet, wait
                    return PegInDepositorStatus::PegInConfirmWait;
                }
            }
        } else {
            // peg-in deposit not confirmed yet, wait
            return PegInDepositorStatus::PegInDepositWait;
        }
    }

    pub async fn deposit(&self, client: &AsyncClient) {
        verify_if_not_mined(client, self.peg_in_deposit_transaction.tx().compute_txid()).await;

        // complete deposit tx
        let deposit_tx = self.peg_in_deposit_transaction.finalize();

        // broadcast deposit tx
        let deposit_result = client.broadcast(&deposit_tx).await;

        // verify deposit result
        verify_tx_result(&deposit_result);
    }

    pub async fn confirm(&self, client: &AsyncClient) {
        verify_if_not_mined(client, self.peg_in_confirm_transaction.tx().compute_txid()).await;

        let deposit_status = client
            .get_tx_status(&self.peg_in_deposit_transaction.tx().compute_txid())
            .await;

        if deposit_status.is_ok_and(|status| status.confirmed) {
            // complete confirm tx
            let confirm_tx = self.peg_in_confirm_transaction.finalize();

            // broadcast confirm tx
            let confirm_result = client.broadcast(&confirm_tx).await;

            // verify confirm result
            verify_tx_result(&confirm_result);
        } else {
            panic!("Deposit tx has not been yet confirmed!");
        }
    }

    pub async fn refund(&self, client: &AsyncClient) {
        verify_if_not_mined(client, self.peg_in_refund_transaction.tx().compute_txid()).await;

        let deposit_status = client
            .get_tx_status(&self.peg_in_deposit_transaction.tx().compute_txid())
            .await;

        if deposit_status.is_ok_and(|status| status.confirmed) {
            // complete refund tx
            let refund_tx = self.peg_in_refund_transaction.finalize();

            // broadcast refund tx
            let refund_result = client.broadcast(&refund_tx).await;

            // verify refund result
            verify_tx_result(&refund_result);
        } else {
            panic!("Deposit tx has not been yet confirmed!");
        }
    }

    async fn get_peg_in_statuses(
        &self,
        client: &AsyncClient,
    ) -> (
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
    ) {
        let peg_in_deposit_status = client
            .get_tx_status(&self.peg_in_deposit_transaction.tx().compute_txid())
            .await;
        let peg_in_confirm_status = client
            .get_tx_status(&self.peg_in_confirm_transaction.tx().compute_txid())
            .await;
        let peg_in_refund_status = client
            .get_tx_status(&self.peg_in_refund_transaction.tx().compute_txid())
            .await;

        return (
            peg_in_deposit_status,
            peg_in_confirm_status,
            peg_in_refund_status,
        );
    }

    pub fn validate(&self) -> bool {
        let peg_in_graph = self.new_for_validation();
        if !validate_transaction(
            self.peg_in_deposit_transaction.tx(),
            peg_in_graph.peg_in_deposit_transaction.tx(),
        ) || !validate_transaction(
            self.peg_in_refund_transaction.tx(),
            peg_in_graph.peg_in_refund_transaction.tx(),
        ) || !validate_transaction(
            self.peg_in_confirm_transaction.tx(),
            peg_in_graph.peg_in_confirm_transaction.tx(),
        ) {
            return false;
        }

        true
    }

    pub fn merge(&mut self, source_peg_in_graph: &PegInGraph) {
        // merge peg_in_confirm tx
        self.peg_in_confirm_transaction
            .merge(&source_peg_in_graph.peg_in_confirm_transaction);
    }
}

pub fn generate_id(peg_in_deposit_transaction: &PegInDepositTransaction) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_deposit_transaction.tx().compute_txid().to_string());

    hasher.finalize().to_hex_string(Upper)
}
