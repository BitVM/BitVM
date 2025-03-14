use bitcoin::{
    hex::{Case::Upper, DisplayHex},
    Network, OutPoint, PublicKey, Transaction, Txid, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, TxStatus};
use itertools::Itertools;
use musig2::SecNonce;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::{
    client::sdk::{
        query::GraphCliQuery, query_contexts::depositor_signatures::DepositorSignatures,
    },
    error::{Error, GraphError, NamedTx},
    transactions::pre_signed_musig2::PreSignedMusig2Transaction,
};

use super::{
    super::{
        connectors::{connector_0::Connector0, connector_z::ConnectorZ},
        contexts::{depositor::DepositorContext, verifier::VerifierContext},
        transactions::{
            base::{validate_transaction, verify_public_nonces_for_tx, BaseTransaction, Input},
            peg_in_confirm::PegInConfirmTransaction,
            peg_in_deposit::PegInDepositTransaction,
            peg_in_refund::PegInRefundTransaction,
            pre_signed::PreSignedTransaction,
        },
    },
    base::{
        get_tx_statuses, verify_if_not_mined, BaseGraph, GraphId, GRAPH_VERSION,
        NUM_REQUIRED_OPERATORS,
    },
    peg_out::{PegOutGraph, PegOutId},
};

#[derive(derive_more::Display)]
pub enum PegInDepositorStatus {
    #[display("Peg-in deposit transaction not confirmed yet. Wait...")]
    PegInDepositWait, // peg-in deposit not yet confirmed
    #[display("Peg-in confirm transaction not confirmed yet. Wait...")]
    PegInConfirmWait, // peg-in confirm not yet confirmed, wait for operator to complete peg-in, refund not available yet
    #[display("Peg-in complete. Done.")]
    PegInConfirmComplete, // peg-in complete
    #[display("Peg-in timed out. Broadcast refund transaction?")]
    PegInRefundAvailable, // peg-in refund available
    #[display("Peg-in refund complete, funds reclaimed. Done.")]
    PegInRefundComplete, // peg-in failed, refund complete
}

#[derive(Debug, PartialEq, derive_more::Display)]
pub enum PegInVerifierStatus {
    #[display("Peg-in deposit transaction not confirmed yet. Wait...")]
    AwaitingDeposit, // no action required, wait
    #[display("No peg-out graph available yet. Wait...")]
    AwaitingPegOutCreation, // need operator(s) to come online to create peg-out grah
    #[display("Nonce required. Share nonce?")]
    PendingOurNonces(Vec<GraphId>), // the given verifier needs to submit nonces
    #[display("Awaiting nonces. Wait...")]
    AwaitingNonces, // the given verifier submitted nonces, awaiting other verifier's nonces
    #[display("Signature required. Pre-sign transactions?")]
    PendingOurSignature(Vec<GraphId>), // the given verifier needs to submit signature
    #[display("Awaiting peg-in confirm signatures. Wait...")]
    AwaitingSignatures, // the given verifier submitted signatures, awaiting other verifier's signatures
    #[display("Peg-in confirm transaction pre-signed. Broadcast confirm transaction?")]
    ReadyToSubmit, // all signatures collected, can now submit
    #[display("Peg-in done.")]
    Complete, // peg-in complete
}

#[derive(derive_more::Display)]
pub enum PegInOperatorStatus {
    #[display("No action available. Wait...")]
    PegInWait, // peg-in not yet complete, no action required yet, wait
    #[display("Peg-in confirm transaction ready. Broadcast peg-in confirm transaction?")]
    PegInConfirmAvailable, // should execute peg-in confirm
    #[display("Peg-in complete. Done.")]
    PegInComplete, // peg-in complete
}

struct PegInConnectors {
    connector_0: Connector0,
    connector_z: ConnectorZ,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInGraph {
    version: String,
    network: Network,
    id: String,

    pub peg_in_deposit_transaction: PegInDepositTransaction,
    pub peg_in_refund_transaction: PegInRefundTransaction,
    pub peg_in_confirm_transaction: PegInConfirmTransaction,

    n_of_n_public_key: PublicKey,
    n_of_n_public_keys: Vec<PublicKey>,
    n_of_n_taproot_public_key: XOnlyPublicKey,

    pub depositor_public_key: PublicKey,
    depositor_taproot_public_key: XOnlyPublicKey,
    pub depositor_evm_address: String,

    connector_0: Connector0,
    connector_z: ConnectorZ,

    pub peg_out_graphs: Vec<PegOutId>,
}

impl BaseGraph for PegInGraph {
    fn network(&self) -> Network {
        self.network
    }

    fn id(&self) -> &String {
        &self.id
    }

    fn verifier_sign(
        &mut self,
        verifier_context: &VerifierContext,
        secret_nonces: &HashMap<Txid, HashMap<usize, SecNonce>>,
    ) {
        self.peg_in_confirm_transaction.pre_sign(
            verifier_context,
            &self.connector_z,
            &secret_nonces[&self.peg_in_confirm_transaction.tx().compute_txid()],
        );
    }

    fn push_verifier_nonces(
        &mut self,
        verifier_context: &VerifierContext,
    ) -> HashMap<Txid, HashMap<usize, SecNonce>> {
        [(
            self.peg_in_confirm_transaction.tx().compute_txid(),
            self.peg_in_confirm_transaction
                .push_nonces(verifier_context),
        )]
        .into()
    }
}

impl PegInGraph {
    pub fn new(context: &DepositorContext, deposit_input: Input, evm_address: &str) -> Self {
        let connectors = create_new_connectors(
            context.network,
            &context.n_of_n_taproot_public_key,
            &context.depositor_taproot_public_key,
            evm_address,
        );

        let peg_in_deposit_transaction =
            PegInDepositTransaction::new(context, &connectors.connector_z, deposit_input);

        let peg_in_refund_vout_0: usize = 0;
        let peg_in_refund_transaction = PegInRefundTransaction::new(
            context,
            &connectors.connector_z,
            generate_input(peg_in_deposit_transaction.tx(), peg_in_refund_vout_0),
        );

        let peg_in_confirm_vout_0: usize = 0;
        let peg_in_confirm_transaction = PegInConfirmTransaction::new(
            context,
            &connectors.connector_0,
            &connectors.connector_z,
            generate_input(peg_in_deposit_transaction.tx(), peg_in_confirm_vout_0),
        );

        PegInGraph {
            version: GRAPH_VERSION.to_string(),
            network: context.network,
            id: generate_id(&peg_in_deposit_transaction),
            peg_in_deposit_transaction,
            peg_in_refund_transaction,
            peg_in_confirm_transaction,
            n_of_n_public_key: context.n_of_n_public_key,
            n_of_n_public_keys: context.n_of_n_public_keys.clone(),
            n_of_n_taproot_public_key: context.n_of_n_taproot_public_key,
            depositor_public_key: context.depositor_public_key,
            depositor_taproot_public_key: context.depositor_taproot_public_key,
            depositor_evm_address: evm_address.to_string(),
            connector_0: connectors.connector_0,
            connector_z: connectors.connector_z,
            peg_out_graphs: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_query(
        network: Network,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        n_of_n_public_key: &PublicKey,
        n_of_n_public_keys: &[PublicKey],
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        depositor_evm_address: &str,
        deposit_input: Input,
    ) -> Self {
        create_graph_without_signing(
            network,
            depositor_public_key,
            depositor_taproot_public_key,
            n_of_n_public_key,
            n_of_n_public_keys,
            n_of_n_taproot_public_key,
            depositor_evm_address,
            deposit_input,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_depositor_signatures(
        network: Network,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        n_of_n_public_key: &PublicKey,
        n_of_n_public_keys: &[PublicKey],
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        depositor_evm_address: &str,
        deposit_input: Input,
        signatures: &DepositorSignatures,
    ) -> Self {
        let connectors = create_new_connectors(
            network,
            n_of_n_taproot_public_key,
            depositor_taproot_public_key,
            depositor_evm_address,
        );

        let peg_in_deposit_transaction = PegInDepositTransaction::new_with_signature(
            network,
            depositor_public_key,
            &connectors.connector_z,
            deposit_input,
            signatures.deposit,
        );

        let peg_in_refund_vout_0: usize = 0;
        let peg_in_refund_transaction = PegInRefundTransaction::new_with_signature(
            network,
            depositor_public_key,
            &connectors.connector_z,
            generate_input(peg_in_deposit_transaction.tx(), peg_in_refund_vout_0),
            signatures.refund,
        );

        let peg_in_confirm_vout_0: usize = 0;
        let peg_in_confirm_transaction = PegInConfirmTransaction::new_with_depositor_signature(
            &connectors.connector_0,
            &connectors.connector_z,
            generate_input(peg_in_deposit_transaction.tx(), peg_in_confirm_vout_0),
            n_of_n_public_keys,
            signatures.confirm,
        );

        PegInGraph {
            version: GRAPH_VERSION.to_string(),
            network,
            id: generate_id(&peg_in_deposit_transaction),
            peg_in_deposit_transaction,
            peg_in_refund_transaction,
            peg_in_confirm_transaction,
            n_of_n_public_key: *n_of_n_public_key,
            n_of_n_public_keys: n_of_n_public_keys.to_owned(),
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            depositor_public_key: *depositor_public_key,
            depositor_taproot_public_key: *depositor_taproot_public_key,
            depositor_evm_address: depositor_evm_address.to_string(),
            connector_0: connectors.connector_0,
            connector_z: connectors.connector_z,
            peg_out_graphs: Vec::new(),
        }
    }

    pub fn new_for_validation(&self) -> Self {
        create_graph_without_signing(
            self.network,
            &self.depositor_public_key,
            &self.depositor_taproot_public_key,
            &self.n_of_n_public_key,
            &self.n_of_n_public_keys,
            &self.n_of_n_taproot_public_key,
            &self.depositor_evm_address,
            Input {
                outpoint: self.peg_in_deposit_transaction.tx().input[0].previous_output, // Self-referencing
                amount: self.peg_in_deposit_transaction.prev_outs()[0].value, // Self-referencing
            },
        )
    }

    pub fn peg_in_confirm_transaction_ref(&self) -> &PegInConfirmTransaction {
        &self.peg_in_confirm_transaction
    }

    pub async fn verifier_status(
        &self,
        client: &AsyncClient,
        verifier_context: &VerifierContext,
        peg_outs: &[&PegOutGraph],
    ) -> PegInVerifierStatus {
        // check that the supplied peg out graphs match our expectation
        let supplied_peg_out_ids = peg_outs.iter().map(|x| x.id()).sorted().collect::<Vec<_>>();
        let expected_peg_out_ids = self.peg_out_graphs.iter().sorted().collect::<Vec<_>>();
        if supplied_peg_out_ids != expected_peg_out_ids {
            panic!("Invalid peg outs supplied as argument");
        }

        let (peg_in_deposit_status, peg_in_confirm_status, _) =
            Self::get_peg_in_statuses(self, client).await;

        if !peg_in_deposit_status.is_ok_and(|status| status.confirmed) {
            // peg-in deposit not confirmed yet, wait
            return PegInVerifierStatus::AwaitingDeposit;
        }

        if peg_outs.len() < NUM_REQUIRED_OPERATORS {
            return PegInVerifierStatus::AwaitingPegOutCreation;
        }

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed) {
            // peg in complete
            return PegInVerifierStatus::Complete;
        }

        if !self
            .peg_in_confirm_transaction
            .has_nonce_of(verifier_context)
        {
            return PegInVerifierStatus::PendingOurNonces(vec![self.id.clone()]);
        }

        let has_all_pegin_nonces = self.peg_in_confirm_transaction.has_all_nonces();
        if !has_all_pegin_nonces {
            return PegInVerifierStatus::AwaitingNonces;
        }

        if !self
            .peg_in_confirm_transaction
            .has_signatures_for(verifier_context.verifier_public_key)
        {
            return PegInVerifierStatus::PendingOurSignature(vec![self.id.clone()]);
        }

        let has_all_pegin_signatures = self.peg_in_confirm_transaction.has_all_signatures();
        if !has_all_pegin_signatures {
            return PegInVerifierStatus::AwaitingSignatures;
        }

        // we have all signature, but confirm wasn't included in a block yet
        PegInVerifierStatus::ReadyToSubmit
    }

    pub async fn operator_status(&self, client: &AsyncClient) -> PegInOperatorStatus {
        let (peg_in_deposit_status, peg_in_confirm_status, _) =
            Self::get_peg_in_statuses(self, client).await;

        if peg_in_deposit_status.is_ok_and(|status| status.confirmed) {
            if peg_in_confirm_status.is_ok_and(|status| status.confirmed) {
                // peg in complete
                PegInOperatorStatus::PegInComplete
            } else if self.peg_in_confirm_transaction.has_all_signatures() {
                // should execute peg-in confirm
                PegInOperatorStatus::PegInConfirmAvailable
            } else {
                // peg-in confirm not yet presigned, wait
                PegInOperatorStatus::PegInWait
            }
        } else {
            // peg-in deposit not confirmed yet, wait
            PegInOperatorStatus::PegInWait
        }
    }

    pub fn interpret_depositor_status(
        &self,
        peg_in_deposit_status: &Result<TxStatus, esplora_client::Error>,
        peg_in_confirm_status: &Result<TxStatus, esplora_client::Error>,
        peg_in_refund_status: &Result<TxStatus, esplora_client::Error>,
        blockchain_height: Result<u32, esplora_client::Error>,
    ) -> PegInDepositorStatus {
        if peg_in_deposit_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if peg_in_confirm_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                // peg-in complete
                PegInDepositorStatus::PegInConfirmComplete
            } else if peg_in_deposit_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    blockchain_height.is_ok_and(|height| {
                        block_height + self.connector_z.num_blocks_timelock_0 <= height
                    })
                })
            {
                if peg_in_refund_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    // peg-in refund complete
                    PegInDepositorStatus::PegInRefundComplete
                } else {
                    // peg-in refund available
                    PegInDepositorStatus::PegInRefundAvailable
                }
            } else {
                // peg-in confirm not confirmed yet, refund not available yet, wait
                PegInDepositorStatus::PegInConfirmWait
            }
        } else {
            // peg-in deposit not confirmed yet, wait
            PegInDepositorStatus::PegInDepositWait
        }
    }

    pub async fn depositor_status(&self, client: &AsyncClient) -> PegInDepositorStatus {
        let tx_statuses = get_tx_statuses(
            client,
            &[
                self.peg_in_deposit_transaction.tx().compute_txid(),
                self.peg_in_confirm_transaction.tx().compute_txid(),
                self.peg_in_refund_transaction.tx().compute_txid(),
            ],
        )
        .await;
        let (peg_in_deposit_status, peg_in_confirm_status, peg_in_refund_status) =
            match &tx_statuses[..] {
                [stat1, stat2, stat3, ..] => (stat1, stat2, stat3),
                // make sure vectors size are the same or will panic
                _ => unreachable!(),
            };

        self.interpret_depositor_status(
            peg_in_deposit_status,
            peg_in_confirm_status,
            peg_in_refund_status,
            client.get_height().await,
        )
    }

    pub async fn deposit(&mut self, client: &AsyncClient) -> Result<Transaction, Error> {
        let txid = self.peg_in_deposit_transaction.tx().compute_txid();
        verify_if_not_mined(client, txid).await?;
        Ok(self.peg_in_deposit_transaction.finalize())
    }

    pub async fn confirm(&mut self, client: &AsyncClient) -> Result<Transaction, Error> {
        let txid = self.peg_in_confirm_transaction.tx().compute_txid();
        verify_if_not_mined(client, txid).await?;

        let deposit_txid = self.peg_in_deposit_transaction.tx().compute_txid();
        let deposit_status = client.get_tx_status(&deposit_txid).await;

        match deposit_status {
            Ok(status) => match status.confirmed {
                true => Ok(self.peg_in_confirm_transaction.finalize()),
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.peg_in_deposit_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    pub async fn refund(&mut self, client: &AsyncClient) -> Result<Transaction, Error> {
        let txid = self.peg_in_refund_transaction.tx().compute_txid();
        verify_if_not_mined(client, txid).await?;

        let deposit_txid = self.peg_in_deposit_transaction.tx().compute_txid();
        let deposit_status = client.get_tx_status(&deposit_txid).await;

        match deposit_status {
            Ok(status) => match status.confirmed {
                true => Ok(self.peg_in_refund_transaction.finalize()),
                false => Err(Error::Graph(GraphError::PrecedingTxNotConfirmed(vec![
                    NamedTx::for_tx(&self.peg_in_deposit_transaction, status.confirmed),
                ]))),
            },
            Err(e) => Err(Error::Esplora(e)),
        }
    }

    async fn get_peg_in_statuses(
        &self,
        client: &AsyncClient,
    ) -> (
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
        Result<TxStatus, esplora_client::Error>,
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

        (
            peg_in_deposit_status,
            peg_in_confirm_status,
            peg_in_refund_status,
        )
    }

    pub fn validate(&self) -> bool {
        let mut ret_val = true;
        let peg_in_graph = self.new_for_validation();
        if !validate_transaction(
            self.peg_in_deposit_transaction.tx(),
            peg_in_graph.peg_in_deposit_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.peg_in_refund_transaction.tx(),
            peg_in_graph.peg_in_refund_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.peg_in_confirm_transaction.tx(),
            peg_in_graph.peg_in_confirm_transaction.tx(),
        ) {
            ret_val = false;
        }

        if !verify_public_nonces_for_tx(&self.peg_in_confirm_transaction) {
            ret_val = false;
        }

        ret_val
    }

    pub fn merge(&mut self, source_peg_in_graph: &PegInGraph) {
        self.peg_in_confirm_transaction
            .merge(&source_peg_in_graph.peg_in_confirm_transaction);

        self.peg_out_graphs
            .extend(source_peg_in_graph.peg_out_graphs.clone());
        self.peg_out_graphs.sort();
        self.peg_out_graphs.dedup();
    }
}

impl GraphCliQuery for PegInGraph {
    async fn broadcast_deposit(&self, client: &AsyncClient) -> Result<(), String> {
        let txid = self.peg_in_deposit_transaction.tx().compute_txid();
        let tx_status = client.get_tx_status(&txid).await;
        match tx_status {
            Ok(status) => {
                match status.confirmed {
                    true => Err("Transaction already mined!".into()),
                    false => {
                        // complete deposit tx
                        let deposit_tx = self.peg_in_deposit_transaction.finalize();
                        // broadcast deposit tx
                        let deposit_result = client.broadcast(&deposit_tx).await;
                        match deposit_result {
                            Ok(_) => Ok(()),
                            Err(e) => Err(e.to_string()),
                        }
                    }
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

pub fn generate_id(peg_in_deposit_transaction: &PegInDepositTransaction) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_deposit_transaction.tx().compute_txid().to_string());

    hasher.finalize().to_hex_string(Upper)
}

fn create_new_connectors(
    network: Network,
    n_of_n_taproot_public_key: &XOnlyPublicKey,
    depositor_taproot_public_key: &XOnlyPublicKey,
    evm_address: &str,
) -> PegInConnectors {
    let connector_0 = Connector0::new(network, n_of_n_taproot_public_key);
    let connector_z = ConnectorZ::new(
        network,
        evm_address,
        depositor_taproot_public_key,
        n_of_n_taproot_public_key,
    );

    PegInConnectors {
        connector_0,
        connector_z,
    }
}

#[allow(clippy::too_many_arguments)]
fn create_graph_without_signing(
    network: Network,
    depositor_public_key: &PublicKey,
    depositor_taproot_public_key: &XOnlyPublicKey,
    n_of_n_public_key: &PublicKey,
    n_of_n_public_keys: &[PublicKey],
    n_of_n_taproot_public_key: &XOnlyPublicKey,
    depositor_evm_address: &str,
    deposit_input: Input,
) -> PegInGraph {
    let connectors = create_new_connectors(
        network,
        n_of_n_taproot_public_key,
        depositor_taproot_public_key,
        depositor_evm_address,
    );
    let peg_in_deposit_transaction = PegInDepositTransaction::new_for_validation(
        network,
        depositor_public_key,
        &connectors.connector_z,
        deposit_input,
    );

    let peg_in_refund_vout_0: usize = 0;
    let peg_in_refund_transaction = PegInRefundTransaction::new_for_validation(
        network,
        depositor_public_key,
        &connectors.connector_z,
        generate_input(peg_in_deposit_transaction.tx(), peg_in_refund_vout_0),
    );

    let peg_in_confirm_vout_0: usize = 0;
    let peg_in_confirm_transaction = PegInConfirmTransaction::new_for_validation(
        &connectors.connector_0,
        &connectors.connector_z,
        generate_input(peg_in_deposit_transaction.tx(), peg_in_confirm_vout_0),
        n_of_n_public_keys.to_owned(),
    );

    PegInGraph {
        version: GRAPH_VERSION.to_string(),
        network,
        id: generate_id(&peg_in_deposit_transaction),
        peg_in_deposit_transaction,
        peg_in_refund_transaction,
        peg_in_confirm_transaction,
        n_of_n_public_key: *n_of_n_public_key,
        n_of_n_public_keys: n_of_n_public_keys.to_owned(),
        n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
        depositor_public_key: *depositor_public_key,
        depositor_taproot_public_key: *depositor_taproot_public_key,
        depositor_evm_address: depositor_evm_address.to_string(),
        connector_0: connectors.connector_0,
        connector_z: connectors.connector_z,
        peg_out_graphs: Vec::new(),
    }
}

fn generate_input(tx: &Transaction, vout: usize) -> Input {
    Input {
        outpoint: OutPoint {
            txid: tx.compute_txid(),
            vout: vout.to_u32().unwrap(),
        },
        amount: tx.output[vout].value,
    }
}
