use std::collections::HashMap;

use bitcoin::{
    policy::{DEFAULT_MIN_RELAY_TX_FEE, DUST_RELAY_TX_FEE},
    Network, Transaction, Txid,
};
use esplora_client::{AsyncClient, TxStatus};
use futures::future::join_all;
use musig2::SecNonce;

use crate::bridge::{
    contexts::verifier::VerifierContext,
    error::{Error, TransactionError},
    transactions::base::{
        MIN_RELAY_FEE_KICK_OFF_1, MIN_RELAY_FEE_KICK_OFF_2, MIN_RELAY_FEE_PEG_IN_CONFIRM,
        MIN_RELAY_FEE_PEG_IN_DEPOSIT, MIN_RELAY_FEE_PEG_IN_REFUND, MIN_RELAY_FEE_START_TIME,
        MIN_RELAY_FEE_TAKE_1,
    },
};

pub const NUM_REQUIRED_OPERATORS: usize = 1;

pub const GRAPH_VERSION: &str = "0.1";

pub const FEE_AMOUNT: u64 = 10_000;
// for commonly used type in codebase - p2wsh txout
// 67 = (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4) for segwit TxOut
// TODO: Use lower dust amount for other txout types
pub const DUST_AMOUNT: u64 = (43 + 67) * DUST_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_RATE: u64 = (DEFAULT_MIN_RELAY_TX_FEE / 1000) as u64;
pub const DUST_RELAY_FEE_RATE: u64 = (DUST_RELAY_TX_FEE / 1000) as u64;

// set reward percentage as 2% of peg in deposit
pub const REWARD_PRECISION: u64 = 1000;
pub const REWARD_MULTIPLIER: u64 = 20;
// (kick-off 1 /w start time + 2 dusts) + kick-off 2 + take 1
// subsequent tx dust is taken from kick-off 1
pub const PEG_OUT_FEE_FOR_TAKE_1: u64 = MIN_RELAY_FEE_KICK_OFF_1
    + MIN_RELAY_FEE_START_TIME
    + DUST_AMOUNT * 2
    + MIN_RELAY_FEE_KICK_OFF_2
    + MIN_RELAY_FEE_TAKE_1;
pub const PEG_IN_FEE: u64 =
    MIN_RELAY_FEE_PEG_IN_DEPOSIT + max(MIN_RELAY_FEE_PEG_IN_CONFIRM, MIN_RELAY_FEE_PEG_IN_REFUND);

// TODO delete
// DEMO SECRETS
pub const OPERATOR_SECRET: &str =
    "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac";

pub const VERIFIER_0_SECRET: &str =
    "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2";

pub const VERIFIER_1_SECRET: &str =
    "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f";

pub const DEPOSITOR_SECRET: &str =
    "b8f17ea979be24199e7c3fec71ee88914d92fd4ca508443f765d56ce024ef1d7";

pub const WITHDRAWER_SECRET: &str =
    "fffd54f6d8f8ad470cb507fd4b6e9b3ea26b4221a4900cc5ad5916ce67c02f1e";

pub const DEPOSITOR_EVM_ADDRESS: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"; // l2 local test network account 1
pub const WITHDRAWER_EVM_ADDRESS: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"; // l2 local test network account 2

pub type GraphId = String;

pub trait BaseGraph {
    fn network(&self) -> Network;
    fn id(&self) -> &String;
    fn push_verifier_nonces(
        &mut self,
        verifier_context: &VerifierContext,
    ) -> HashMap<Txid, HashMap<usize, SecNonce>>;
    fn verifier_sign(
        &mut self,
        verifier_context: &VerifierContext,
        secret_nonces: &HashMap<Txid, HashMap<usize, SecNonce>>,
    );
}

pub const fn max(a: u64, b: u64) -> u64 { [a, b][(a < b) as usize] }

pub async fn get_block_height(client: &AsyncClient) -> Result<u32, Error> {
    match client.get_height().await {
        Ok(height) => Ok(height),
        Err(e) => Err(Error::Esplora(e)),
    }
}

pub async fn verify_if_not_mined(client: &AsyncClient, txid: Txid) -> Result<(), Error> {
    match is_confirmed(client, txid).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(Error::Transaction(TransactionError::AlreadyMined(txid))),
        Err(e) => Err(Error::Esplora(e)),
    }
}

pub async fn is_confirmed(client: &AsyncClient, txid: Txid) -> Result<bool, esplora_client::Error> {
    let tx_status = client.get_tx_status(&txid).await;
    tx_status.map(|x| x.confirmed)
}

pub async fn broadcast_and_verify(
    client: &AsyncClient,
    transaction: &Transaction,
) -> Result<&'static str, Error> {
    let txid = transaction.compute_txid();

    if let Ok(Some(_)) = client.get_tx(&txid).await {
        return Ok("Tx already submitted.");
    }

    let tx_result = client.broadcast(transaction).await;

    match (tx_result, is_confirmed(client, txid).await) {
        (Ok(_), _) | (Err(_), Ok(true)) => Ok("Tx mined successfully."),
        (Err(e), _) => Err(Error::Esplora(e)),
    }
}

pub async fn get_tx_statuses(
    client: &AsyncClient,
    txids: &[Txid],
) -> Vec<Result<TxStatus, esplora_client::Error>> {
    join_all(txids.iter().map(|txid| client.get_tx_status(txid))).await
}
