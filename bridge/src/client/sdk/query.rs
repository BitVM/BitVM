use std::future::Future;

use bitcoin::{PublicKey, XOnlyPublicKey};
use esplora_client::AsyncClient;
use serde_json::Value;

use crate::transactions::base::Input;

use super::query_contexts::depositor_signatures::DepositorSignatures;

pub trait ClientCliQuery {
    fn get_unused_peg_in_graphs(&self) -> impl Future<Output = Vec<Value>>;
    fn get_depositor_status(
        &self,
        depositor_public_key: &PublicKey,
    ) -> impl Future<Output = Vec<Value>>;
    fn get_withdrawer_status(
        &self,
        withdrawer_chain_address: &str,
    ) -> impl Future<Output = Vec<Value>>;
    fn get_depositor_transactions(
        &self,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        deposit_input: Input,
        depositor_evm_address: &str,
    ) -> impl Future<Output = Result<Value, String>>;
    fn create_peg_in_graph_with_depositor_signatures(
        &mut self,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        deposit_input: Input,
        depositor_evm_address: &str,
        signatures: &DepositorSignatures,
    ) -> impl Future<Output = Result<Value, String>>;
    fn retry_broadcast_peg_in_deposit(
        &self,
        peg_in_graph_id: &str,
    ) -> impl Future<Output = Result<Value, String>>;
}

pub trait GraphCliQuery {
    fn broadcast_deposit(&self, client: &AsyncClient) -> impl Future<Output = Result<(), String>>;
}
