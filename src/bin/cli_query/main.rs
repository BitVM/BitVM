use bitcoin::Network;
use bitvm::bridge::{client::cli::query_command::QueryCommand, constants::DestinationNetwork};
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
        .subcommand(QueryCommand::transactions_command())
        .subcommand(QueryCommand::signatures_command())
        .subcommand(QueryCommand::broadcast_command())
        .subcommand(QueryCommand::peg_in_graphs_command())
        .arg(arg!(-e --environment <ENVIRONMENT> "Specify the Bitcoin and L2 network environment (mainnet, testnet, local)").required(false)
        .default_value("mainnet"))
        .arg(arg!(-p --prefix <PREFIX> "Prefix for local file cache path").required(false));

    let matches = command.clone().get_matches();
    let (source_network, destination_network) =
        match matches.get_one::<String>("environment").unwrap().as_str() {
            "mainnet" => (Network::Bitcoin, DestinationNetwork::Ethereum),
            "testnet" => (Network::Testnet, DestinationNetwork::EthereumSepolia),
            "local" => (Network::Regtest, DestinationNetwork::Local),
            _ => {
                eprintln!("Invalid environment. Use mainnet, testnet.");
                std::process::exit(1);
            }
        };
    let prefix = matches.get_one::<String>("prefix").map(|s| s.as_str());

    let mut query = QueryCommand::new(source_network, destination_network, prefix).await;
    let resp = match matches.subcommand() {
        Some(("depositor", sub)) => query.handle_depositor(sub).await,
        Some(("withdrawer", sub)) => query.handle_withdrawer(sub, destination_network).await,
        Some(("history", sub)) => query.handle_history(sub, destination_network).await,
        Some(("transactions", sub)) => query.handle_transactions(sub, destination_network).await,
        Some(("signatures", sub)) => query.handle_signatures(sub, destination_network).await,
        Some(("broadcast", sub)) => query.handle_broadcast(sub).await,
        Some(("pegins", _)) => query.handle_peg_in_graphs().await,
        _ => unreachable!(),
    };

    resp.flush();
    Ok(())
}
