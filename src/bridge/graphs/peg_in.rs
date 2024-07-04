use bitcoin::{
    hex::{Case::Upper, DisplayHex},
    Network, OutPoint, PublicKey, XOnlyPublicKey,
};
use num_traits::ToPrimitive;
use sha2::{Digest, Sha256};

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

pub struct PegInGraph {
    version: String,
    network: Network,
    id: String,

    peg_in_deposit_transaction: PegInDepositTransaction,
    peg_in_refund_transaction: PegInRefundTransaction,
    peg_in_confirm_transaction: PegInConfirmTransaction,

    pub depositor_public_key: PublicKey,
    depositor_taproot_public_key: XOnlyPublicKey,
    depositor_evm_address: String,
}

impl BaseGraph for PegInGraph {
    fn network(&self) -> Network { self.network }

    fn id(&self) -> &String { &self.id }
}

impl PegInGraph {
    pub fn new(context: &DepositorContext, input: Input, evm_address: &str) -> Self {
        let mut peg_in_deposit_transaction =
            PegInDepositTransaction::new(context, evm_address, input);
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
            depositor_public_key: context.depositor_public_key,
            depositor_taproot_public_key: context.depositor_taproot_public_key,
            depositor_evm_address: evm_address.to_string(),
        }
    }

    pub fn pre_sign(&mut self, context: &VerifierContext) {
        self.peg_in_confirm_transaction.pre_sign(context);
    }

    pub fn peg_in_confirm_transaction_ref(&self) -> &PegInConfirmTransaction {
        &self.peg_in_confirm_transaction
    }
}

pub fn generate_id(peg_in_deposit_transaction: &PegInDepositTransaction) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_deposit_transaction.tx().compute_txid().to_string());

    hasher.finalize().to_hex_string(Upper)
}
