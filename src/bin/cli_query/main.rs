use bitcoin::Network;
use bitvm::bridge::{
    client::cli::{query_command::QueryCommand, query_response::Response},
    constants::DestinationNetwork,
};
use clap::{arg, command};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let command = command!() // requires `cargo` feature
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(QueryCommand::depositor_command())
        .subcommand(QueryCommand::withdrawer_command())
        .subcommand(QueryCommand::history_command())
        .arg(arg!(-e --environment <ENVIRONMENT> "Specify the Bitcoin and L2 network environment (mainnet, testnet)").required(false)
        .default_value("mainnet"))
        .arg(arg!(-p --prefix <PREFIX> "Prefix for local file cache path").required(false));

    let matches = command.clone().get_matches();
    let (source_network, destination_network) =
        match matches.get_one::<String>("environment").unwrap().as_str() {
            "mainnet" => (Network::Bitcoin, DestinationNetwork::Ethereum),
            "testnet" => (Network::Testnet, DestinationNetwork::EthereumSepolia),
            _ => {
                eprintln!("Invalid environment. Use mainnet, testnet.");
                std::process::exit(1);
            }
        };
    let prefix = matches.get_one::<String>("prefix").map(|s| s.as_str());

    let query_command = QueryCommand::new(source_network, destination_network, prefix).await;
    let mut resp = Response::default();
    if let Some(sub_matches) = matches.subcommand_matches("depositor") {
        resp = query_command.handle_depositor_command(sub_matches).await;
    } else if let Some(sub_matches) = matches.subcommand_matches("withdrawer") {
        resp = query_command
            .handle_withdrawer_command(sub_matches, destination_network)
            .await;
    } else if let Some(sub_matches) = matches.subcommand_matches("history") {
        resp = query_command
            .handle_history_command(sub_matches, destination_network)
            .await;
    }

    resp.flush();
    Ok(())
}
