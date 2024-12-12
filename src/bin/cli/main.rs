use bitcoin::PublicKey;
use bitvm::bridge::client::cli::client_command::{ClientCommand, CommonArgs};
use bitvm::bridge::client::cli::key_command::KeysCommand;
use clap::{arg, command};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let command = command!() // requires `cargo` feature
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            arg!(--"key-dir" <DIRECTORY> "The directory containing the private keys").required(false).env("KEY_DIR"),
        )
        .arg(
            arg!(-r --verifiers [VERIFIER_PUBKEYS] "Pubkeys of the verifiers")
                .required(false)
                .num_args(0..1000)
                .value_delimiter(',')
                .value_parser(clap::value_parser!(PublicKey))
                .env("VERIFIERS"),
        )
        .arg(arg!(-e --environment <ENVIRONMENT> "Specify the Bitcoin network environment (mainnet, testnet). Defaults to mainnet.").required(false).default_value("mainnet").env("ENVIRONMENT"))
        .subcommand(KeysCommand::get_command())
        .subcommand(ClientCommand::get_depositor_address_command())
        .subcommand(ClientCommand::get_depositor_utxos_command())
        .subcommand(ClientCommand::get_initiate_peg_in_command())
        .subcommand(ClientCommand::get_status_command())
        .subcommand(ClientCommand::get_broadcast_command())
        .subcommand(ClientCommand::get_automatic_command())
        .subcommand(ClientCommand::get_interactive_command());

    let matches = command.clone().get_matches();

    let global_args = CommonArgs {
        key_dir: matches.get_one::<String>("key-dir").cloned(),
        verifiers: matches
            .get_many::<PublicKey>("verifiers")
            .map(|x| x.cloned().collect::<Vec<PublicKey>>()),
        environment: matches.get_one::<String>("environment").cloned(),
    };

    if let Some(sub_matches) = matches.subcommand_matches("keys") {
        let keys_command = KeysCommand::new(global_args.key_dir);
        keys_command.handle_command(sub_matches)?;
    } else if matches
        .subcommand_matches("get-depositor-address")
        .is_some()
    {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_get_depositor_address().await;
    } else if matches.subcommand_matches("get-depositor-utxos").is_some() {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_get_depositor_utxos().await;
    } else if let Some(sub_matches) = matches.subcommand_matches("initiate-peg-in") {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command
            .handle_initiate_peg_in_command(sub_matches)
            .await;
    } else if matches.subcommand_matches("status").is_some() {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_status_command().await;
    } else if let Some(sub_matches) = matches.subcommand_matches("broadcast") {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_broadcast_command(sub_matches).await;
    } else if matches.subcommand_matches("automatic").is_some() {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_automatic_command().await;
    } else if matches.subcommand_matches("interactive").is_some() {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_interactive_command(&command).await;
    }

    Ok(())
}
