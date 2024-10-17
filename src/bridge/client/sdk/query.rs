use std::future::Future;

use bitcoin::PublicKey;
use serde_json::Value;

pub trait GraphQuery {
    fn get_depositor_status(
        &self,
        depositor_public_key: &PublicKey,
    ) -> impl Future<Output = Vec<Value>>;
    fn get_withdrawer_status(
        &self,
        withdrawer_chain_address: &str,
    ) -> impl Future<Output = Vec<Value>>;
}
