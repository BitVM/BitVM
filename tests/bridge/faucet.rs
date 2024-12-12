use alloy::transports::http::{
    reqwest::{Error, Response, StatusCode},
    Client,
};
use bitcoin::{Address, Amount, Txid};
use bitvm::bridge::client::client::BitVMClient;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use tokio::time::sleep;

use crate::bridge::helper::{ESPLORA_FUNDING_URL, TX_WAIT_TIME};

const ESPLORA_RETRIES: usize = 5;
const ESPLORA_RETRY_WAIT_TIME: u64 = 10;

#[derive(Serialize, Deserialize)]
struct FundResult {
    txid: Txid,
    address: String,
}

pub struct Faucet {
    client: Client,
}

impl Default for Faucet {
    fn default() -> Self {
        Self::new()
    }
}

impl Faucet {
    pub fn new() -> Self {
        let client = Client::builder()
            .build()
            .expect("Unable to build reqwest client");
        Self { client }
    }

    pub async fn fund_input_and_wait(&self, address: &Address, amount: Amount) -> Txid {
        let txid = self.fund_input_with_retry(address, amount).await;
        println!("Waiting for funding inputs tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;
        txid
    }

    pub async fn verify_and_fund_inputs(
        &self,
        client: &BitVMClient,
        funding_inputs: &Vec<(&Address, Amount)>,
    ) {
        let addr_count =
            funding_inputs
                .iter()
                .fold(HashMap::<&Address, usize>::new(), |mut map, input| {
                    *map.entry(input.0).or_insert(0) += 1;
                    map
                });
        for input in funding_inputs {
            let utxos = client.get_initial_utxos(input.0.clone(), input.1).await;
            let expected_count = *addr_count.get(input.0).unwrap_or(&0);
            if utxos.is_none() || utxos.is_some_and(|x| x.len() < expected_count) {
                self.fund_input_with_retry(input.0, input.1).await;
            }
        }
    }

    async fn fund_input_with_retry(&self, address: &Address, amount: Amount) -> Txid {
        let client_err_handler = |e: Error| {
            panic!("Could not fund {} due to {:?}", address, e);
        };
        let mut resp = self
            .fund_input(address, amount)
            .await
            .unwrap_or_else(client_err_handler);

        let mut retry = 0;
        while resp.status().eq(&StatusCode::SERVICE_UNAVAILABLE) && retry <= ESPLORA_RETRIES {
            retry += 1;
            eprintln!("Retrying({}/{}) {:?}...", retry, ESPLORA_RETRIES, address);
            sleep(Duration::from_millis(Self::get_random_millis(
                ESPLORA_RETRY_WAIT_TIME * 1000,
                ESPLORA_RETRY_WAIT_TIME * 10000,
            )))
            .await;
            // sleep(Duration::from_secs(ESPLORA_RETRY_WAIT_TIME)).await;
            resp = self
                .fund_input(address, amount)
                .await
                .unwrap_or_else(client_err_handler);
        }

        if resp.status().is_client_error() || resp.status().is_server_error() {
            panic!(
                "Could not fund {} with respond code {:?}",
                address,
                resp.status()
            );
        }

        let result = resp.json::<FundResult>().await.unwrap();
        println!("Funded at: {}", result.txid);

        result.txid
    }

    async fn fund_input(&self, address: &Address, amount: Amount) -> Result<Response, Error> {
        let payload = format!(
            "{{\"sats\":{},\"address\":\"{}\"}}",
            amount.to_sat(),
            address
        );

        println!(
            "Funding {:?} with {} sats at {}",
            address,
            amount.to_sat(),
            ESPLORA_FUNDING_URL,
        );

        Self::http_post(
            &self.client,
            format!("{}api/onchain", ESPLORA_FUNDING_URL),
            payload,
        )
        .await
    }

    pub async fn http_post(
        client: &Client,
        url: String,
        payload: String,
    ) -> Result<Response, Error> {
        let resp = client
            .post(url)
            .body(payload)
            .header("CONTENT-TYPE", "application/json")
            .send()
            .await;

        // recreate Result due to Response/Error version mismatch
        match resp {
            Ok(resp) => Ok(resp),
            Err(e) => Err(e),
        }
    }

    pub fn get_random_millis(from: u64, to: u64) -> u64 {
        let mut rng = rand::thread_rng();
        rng.gen_range(from..to)
    }
}
