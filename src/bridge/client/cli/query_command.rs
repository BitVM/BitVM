use alloy::primitives::Address;
use bitcoin::Network;
use bitcoin::PublicKey;
use clap::{arg, ArgMatches, Command};
use core::str::FromStr;

use super::query_response::Response;
use super::query_response::ResponseStatus;
use crate::bridge::client::client::BitVMClient;
use crate::bridge::client::sdk::query::GraphQuery;
use crate::bridge::constants::DestinationNetwork;
use crate::bridge::contexts::base::generate_keys_from_secret;
use crate::bridge::graphs::base::{VERIFIER_0_SECRET, VERIFIER_1_SECRET};

pub struct QueryCommand {
    client: BitVMClient,
}

pub const FAKE_SECRET: &str = "1000000000000000000000000000000000000000000000000000000000000000";

impl QueryCommand {
    pub async fn new(
        source_network: Network,
        destination_network: DestinationNetwork,
        path_prefix: Option<&str>,
    ) -> Self {
        let (_, _, verifier_0_public_key) =
            generate_keys_from_secret(Network::Bitcoin, VERIFIER_0_SECRET);
        let (_, _, verifier_1_public_key) =
            generate_keys_from_secret(Network::Bitcoin, VERIFIER_1_SECRET);

        let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
        n_of_n_public_keys.push(verifier_0_public_key);
        n_of_n_public_keys.push(verifier_1_public_key);

        let mut bitvm_client = BitVMClient::new(
            source_network,
            destination_network,
            &n_of_n_public_keys,
            Some(FAKE_SECRET),
            Some(FAKE_SECRET),
            Some(FAKE_SECRET),
            Some(FAKE_SECRET),
            path_prefix,
        )
        .await;

        bitvm_client.sync().await;
        bitvm_client.sync_l2().await;

        Self {
            client: bitvm_client,
        }
    }

    pub fn depositor_command() -> Command {
        Command::new("depositor")
            .about("fetch peg-in graphs related to the specified depositor")
            .arg(arg!(<DEPOSITOR_PUBLIC_KEY> "Depositor public key").required(true))
    }

    pub async fn handle_depositor_command(&self, sub_matches: &ArgMatches) -> Response {
        let pubkey = PublicKey::from_str(
            sub_matches
                .get_one::<String>("DEPOSITOR_PUBLIC_KEY")
                .unwrap(),
        );
        if pubkey.is_err() {
            return Response::new(
                ResponseStatus::NOK(format!(
                    "Invalid public key. Use bitcoin public key format."
                )),
                None,
            );
        }

        // synced in constructor
        let result = self
            .client
            .get_depositor_status(&pubkey.clone().unwrap())
            .await;
        if result.len() > 0 {
            let data = Some(serde_json::to_value(result).expect("Failed to merge value vector"));
            return Response::new(ResponseStatus::OK, data);
        } else {
            return Response::new(ResponseStatus::NOK(format!("Depositor not found.")), None);
        }
    }

    pub fn withdrawer_command() -> Command {
        Command::new("withdrawer")
            .about("fetch peg-out graphs related to the specified withdrawer")
            .arg(arg!(<WITHDRAWER_CHAIN_ADDRESS> "WITHDRAWER L2 Chain address").required(true))
    }

    pub async fn handle_withdrawer_command(
        &self,
        sub_matches: &ArgMatches,
        destination_network: DestinationNetwork,
    ) -> Response {
        let chain_address = Address::from_str(
            sub_matches
                .get_one::<String>("WITHDRAWER_CHAIN_ADDRESS")
                .unwrap(),
        );
        if chain_address.is_err() {
            return Response::new(
                ResponseStatus::NOK(format!(
                    "Invalid chain address. Use {} address format.",
                    destination_network
                )),
                None,
            );
        }

        // synced in constructor
        let result = self
            .client
            .get_withdrawer_status(&chain_address.unwrap().to_string().as_str())
            .await;
        if result.len() > 0 {
            let data = Some(serde_json::to_value(result).expect("Failed to merge value vector"));
            return Response::new(ResponseStatus::OK, data);
        } else {
            return Response::new(ResponseStatus::NOK(format!("Withdrawer not found.")), None);
        }
    }

    pub fn history_command() -> Command {
        Command::new("history")
            .about("fetch peg-in / peg-out graphs with bitcoin public key and ethereum address at the same time")
            .arg(arg!(<DEPOSITOR_PUBLIC_KEY> "Depositor public key").required(true))
            .arg(arg!(<WITHDRAWER_CHAIN_ADDRESS> "WITHDRAWER L2 Chain address").required(true))
    }

    pub async fn handle_history_command(
        &self,
        sub_matches: &ArgMatches,
        destination_network: DestinationNetwork,
    ) -> Response {
        let pubkey = PublicKey::from_str(
            sub_matches
                .get_one::<String>("DEPOSITOR_PUBLIC_KEY")
                .unwrap(),
        );
        if pubkey.is_err() {
            return Response::new(
                ResponseStatus::NOK(format!(
                    "Invalid public key. Use bitcoin public key format."
                )),
                None,
            );
        }
        let chain_address = Address::from_str(
            sub_matches
                .get_one::<String>("WITHDRAWER_CHAIN_ADDRESS")
                .unwrap(),
        );
        if chain_address.is_err() {
            return Response::new(
                ResponseStatus::NOK(format!(
                    "Invalid chain address. Use {} address format.",
                    destination_network
                )),
                None,
            );
        }

        // synced in constructor
        let mut result_depositor = self
            .client
            .get_depositor_status(&pubkey.clone().unwrap())
            .await;
        let mut result_withdrawer = self
            .client
            .get_withdrawer_status(&chain_address.unwrap().to_string().as_str())
            .await;

        let result = match (result_depositor.len(), result_withdrawer.len()) {
            (0, 0) => vec![],
            (0, _) => result_withdrawer,
            (_, 0) => result_depositor,
            _ => {
                result_depositor.append(&mut result_withdrawer);
                result_depositor
            }
        };

        if result.len() > 0 {
            let data = Some(serde_json::to_value(result).expect("Failed to merge value vector"));
            return Response::new(ResponseStatus::OK, data);
        } else {
            return Response::new(ResponseStatus::NOK(format!("Withdrawer not found.")), None);
        }
    }
}
