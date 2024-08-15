use bitcoin::{Network, Txid};
use esplora_client::{AsyncClient, Error};

pub const GRAPH_VERSION: &str = "0.1";

pub const INITIAL_AMOUNT: u64 = 2 << 16; // 131072
pub const FEE_AMOUNT: u64 = 1_000;
pub const DUST_AMOUNT: u64 = 10_000;
pub const ONE_HUNDRED: u64 = 2 << 26; // 134217728

// TODO delete
// DEMO SECRETS
pub const OPERATOR_SECRET: &str =
    "d898098e09898a0980989b980809809809f09809884324874302975287524398";
pub const N_OF_N_SECRET: &str = "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497";
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
    let tx_status = client.get_tx_status(&txid).await;
    if tx_status.as_ref().is_ok_and(|status| status.confirmed) {
        panic!("Transaction already mined!");
    } else if tx_status.is_err() {
        panic!(
            "Failed to get transaction status, error occurred {:?}",
            tx_status
        );
    }
}

pub fn verify_tx_result(tx_result: &Result<(), Error>) {
    if tx_result.is_ok() {
        println!("Tx mined successfully.");
    } else {
        panic!("Error occurred {:?}", tx_result);
    }
}
