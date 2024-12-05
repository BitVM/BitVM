use bitcoin::{Network, Transaction, Txid};
use esplora_client::{AsyncClient, Error, TxStatus};
use futures::future::join_all;

pub const GRAPH_VERSION: &str = "0.1";

pub const INITIAL_AMOUNT: u64 = 2 << 16; // 131072
pub const FEE_AMOUNT: u64 = 10_000;
// TODO: Either repalce this with a routine that calculates 'min relay fee' for
// every tx, or define local constants with appropriate values in every tx file
// (see MIN_RELAY_FEE_AMOUNT in kick_off_2.rs).
pub const MESSAGE_COMMITMENT_FEE_AMOUNT: u64 = 27_182;
pub const DUST_AMOUNT: u64 = 10_000;
pub const ONE_HUNDRED: u64 = 2 << 26; // 134217728

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

pub const DEPOSITOR_EVM_ADDRESS: &str = "0xDDdDddDdDdddDDddDDddDDDDdDdDDdDDdDDDDDDd";
pub const WITHDRAWER_EVM_ADDRESS: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

pub trait BaseGraph {
    fn network(&self) -> Network;
    fn id(&self) -> &String;
}

pub async fn get_block_height(client: &AsyncClient) -> u32 {
    let blockchain_height_result = client.get_height().await;
    if blockchain_height_result.is_err() {
        panic!(
            "Failed to fetch blockchain height! Error occurred {:?}",
            blockchain_height_result
        );
    }

    blockchain_height_result.unwrap()
}

pub async fn verify_if_not_mined(client: &AsyncClient, txid: Txid) {
    if is_confirmed(client, txid).await {
        panic!("Transaction already mined!");
    }
}

pub async fn is_confirmed(client: &AsyncClient, txid: Txid) -> bool {
    let tx_status = client.get_tx_status(&txid).await;
    tx_status
        .map(|x| x.confirmed)
        .unwrap_or_else(|err| panic!("Failed to get transaction status, error occurred {err:?}"))
}

pub async fn broadcast_and_verify(
    client: &AsyncClient,
    transaction: &Transaction,
) {
    let txid = transaction.txid();

    if let Ok(Some(_)) = client.get_tx(&txid).await {
        println!("Tx already submitted.");
        return;
    }

    let tx_result = client.broadcast(transaction).await;

    if tx_result.is_ok() || is_confirmed(client, txid).await {
        println!("Tx mined successfully.");
    } else {
        panic!("Error occurred {:?}", tx_result);
    }
}

pub async fn get_tx_statuses(
    client: &AsyncClient,
    txids: &Vec<Txid>,
) -> Vec<Result<TxStatus, Error>> {
    join_all(txids.iter().map(|txid| client.get_tx_status(txid))).await
}
