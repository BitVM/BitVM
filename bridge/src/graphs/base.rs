use std::collections::HashMap;

use bitcoin::{
    policy::{DEFAULT_MIN_RELAY_TX_FEE, DUST_RELAY_TX_FEE},
    Network, Transaction, Txid,
};
use esplora_client::{AsyncClient, TxStatus};
use futures::future::join_all;
use musig2::SecNonce;

use crate::{
    contexts::verifier::VerifierContext,
    error::{Error, TransactionError},
    transactions::base::{
        MIN_RELAY_FEE_ASSERT_COMMIT1, MIN_RELAY_FEE_ASSERT_COMMIT2, MIN_RELAY_FEE_ASSERT_FINAL,
        MIN_RELAY_FEE_ASSERT_INITIAL, MIN_RELAY_FEE_DISPROVE, MIN_RELAY_FEE_KICK_OFF_1,
        MIN_RELAY_FEE_KICK_OFF_2, MIN_RELAY_FEE_PEG_IN_CONFIRM, MIN_RELAY_FEE_PEG_IN_DEPOSIT,
        MIN_RELAY_FEE_PEG_IN_REFUND, MIN_RELAY_FEE_PEG_OUT_CONFIRM, MIN_RELAY_FEE_START_TIME,
    },
};

pub const NUM_REQUIRED_OPERATORS: usize = 1;

pub const GRAPH_VERSION: &str = "0.1";

//1 btc
pub const CROWDFUNDING_AMOUNT: f64 = 1.0;
// for commonly used type in codebase - p2wsh txout
// 67 = (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4) for segwit TxOut
// TODO: Use lower dust amount for other txout types
pub const DUST_AMOUNT: u64 = (43 + 67) * DUST_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_RATE: u64 = (DEFAULT_MIN_RELAY_TX_FEE / 1000) as u64;
pub const DUST_RELAY_FEE_RATE: u64 = (DUST_RELAY_TX_FEE / 1000) as u64;

// set reward percentage as 2% of peg in deposit
pub const REWARD_PRECISION: u64 = 1000;
pub const REWARD_MULTIPLIER: u64 = 20;

pub const MIN_RELAY_FEE_ASSERT_SET: u64 = MIN_RELAY_FEE_ASSERT_INITIAL
    + MIN_RELAY_FEE_ASSERT_COMMIT1
    + MIN_RELAY_FEE_ASSERT_COMMIT2
    + MIN_RELAY_FEE_ASSERT_FINAL;
// use largest fee from each depth
// assert fee is big enough to cover disprove chain or take 1
// disprove fee is big enough to cover take 2
pub const PEG_OUT_FEE: u64 = MIN_RELAY_FEE_PEG_OUT_CONFIRM // depth 0
    + MIN_RELAY_FEE_KICK_OFF_1 // depth 1
    + MIN_RELAY_FEE_START_TIME // include START_TIME tx, spent in kickoff 1
    + MIN_RELAY_FEE_KICK_OFF_2 // depth 2
    + MIN_RELAY_FEE_ASSERT_SET // depth 3
    + MIN_RELAY_FEE_DISPROVE; // depth 4
pub const PEG_IN_FEE: u64 =
    MIN_RELAY_FEE_PEG_IN_DEPOSIT + max(MIN_RELAY_FEE_PEG_IN_CONFIRM, MIN_RELAY_FEE_PEG_IN_REFUND);

pub type GraphId = String;

pub trait BaseGraph {
    fn network(&self) -> Network;
    fn id(&self) -> &str;
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

pub const fn max(a: u64, b: u64) -> u64 {
    [a, b][(a < b) as usize]
}

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
        return Ok("Tx already broadcasted.");
    }

    let tx_result = client.broadcast(transaction).await;

    match (tx_result, is_confirmed(client, txid).await) {
        (Ok(_), Ok(false)) | (Ok(_), Err(_)) => Ok("Tx broadcasted successfully."),
        (Ok(_), Ok(true)) | (Err(_), Ok(true)) => Ok("Tx mined successfully."),
        (Err(e), _) => Err(Error::Esplora(e)),
    }
}

pub async fn get_tx_statuses(
    client: &AsyncClient,
    txids: &[Txid],
) -> Vec<Result<TxStatus, esplora_client::Error>> {
    join_all(txids.iter().map(|txid| client.get_tx_status(txid))).await
}

pub async fn get_onchain_txs(
    client: &AsyncClient,
    txids: &[Txid],
) -> Vec<Result<Option<Transaction>, esplora_client::Error>> {
    join_all(txids.iter().map(|txid| client.get_tx(txid))).await
}
