use bitcoin::{
    hex::{Case::Upper, DisplayHex},
    Network, OutPoint, PublicKey, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, Error, TxStatus};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bridge::{constants::NUM_BLOCKS_PER_2_WEEKS, graphs::base::get_block_height};

use super::{
    super::{
        contexts::{depositor::DepositorContext, verifier::VerifierContext},
        transactions::{
            base::Input, peg_in_confirm::PegInConfirmTransaction,
            peg_in_deposit::PegInDepositTransaction, peg_in_refund::PegInRefundTransaction,
            pre_signed::PreSignedTransaction,
        },
    },
    base::{BaseGraph, GRAPH_VERSION},
};

pub enum PegInDepositorStatus {
    PegInDepositWait,     // peg-in deposit not yet confirmed
    PegInConfirmWait, // peg-in confirm not yet confirmed, wait for operator to complete peg-in, refund not available yet
    PegInConfirmComplete, // peg-in complete
    PegInRefundAvailable, // peg-in refund available
    PegInRefundComplete, // peg-in failed, refund complete
}

pub enum PegInVerifierStatus {
    PegInWait,    // no action required, wait
    PegInPresign, // should presign peg-in confirm
    PegInComplete, // peg-in complete
                  // PegOutPresign, // should presign peg-out graph
}

pub enum PegInOperatorStatus {
    PegInWait,             // peg-in not yet complete, no action required yet, wait
    PegInConfirmAvailable, // should execute peg-in confirm
    PegInComplete,         // peg-in complete
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PegInGraph {
    version: String,
    network: Network,
    id: String,

    peg_in_deposit_transaction: PegInDepositTransaction,
    peg_in_refund_transaction: PegInRefundTransaction,
    peg_in_confirm_transaction: PegInConfirmTransaction,

    n_of_n_presigned: bool,

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
            depositor_public_key: context.depositor_public_key,
            depositor_taproot_public_key: context.depositor_taproot_public_key,
            depositor_evm_address: evm_address.to_string(),
        }
    }

    pub fn pre_sign(&mut self, context: &VerifierContext) {
        self.peg_in_confirm_transaction.pre_sign(context);

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

    pub async fn depositor_status(&mut self, client: &AsyncClient) -> PegInDepositorStatus {
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
                        block_height + NUM_BLOCKS_PER_2_WEEKS <= blockchain_height
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
}

pub fn generate_id(peg_in_deposit_transaction: &PegInDepositTransaction) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_deposit_transaction.tx().compute_txid().to_string());

    hasher.finalize().to_hex_string(Upper)
}
