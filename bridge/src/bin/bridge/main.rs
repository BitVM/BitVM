use bitcoin::PublicKey;
use bridge::client::cli::client_command::{ClientCommand, CommonArgs};
use bridge::client::cli::key_command::KeysCommand;
use clap::{arg, command};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    let command = command!() // requires `cargo` feature
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            arg!(--"key-dir" <DIRECTORY> "The directory containing the private keys").required(false).env("KEY_DIR"),
        )
        .arg(
            arg!(-f --verifiers [VERIFIER_PUBKEYS] "Comma-separated list of verifier public keys")
                .required(false)
                .num_args(0..1000)
                .value_delimiter(',')
                .value_parser(clap::value_parser!(PublicKey))
                .env("VERIFIERS"),
        )
        .arg(arg!(-e --environment <ENVIRONMENT> "Specify the Bitcoin network environment (mainnet, testnet, regtest)").required(false).default_value("testnet").env("ENVIRONMENT"))
        .arg(arg!(-p --"user-profile" <USER_PROFILE> "Name of the protocol participant (e.g. 'operator_one', 'verifier_0'). Used as a namespace separator in the local file path for storing private and public client data").required(false).default_value("default_user").env("USER_PROFILE"))
        .subcommand(KeysCommand::get_command())
        .subcommand(ClientCommand::get_operator_address_command())
        .subcommand(ClientCommand::get_operator_utxos_command())
        .subcommand(ClientCommand::get_depositor_address_command())
        .subcommand(ClientCommand::get_depositor_utxos_command())
        .subcommand(ClientCommand::get_initiate_peg_in_command())
        .subcommand(ClientCommand::get_create_peg_out_graph_command())
        .subcommand(ClientCommand::get_push_nonces_command())
        .subcommand(ClientCommand::get_push_signature_command())
        .subcommand(ClientCommand::get_mock_l2_pegout_event_command())
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
        path_prefix: matches.get_one::<String>("user-profile").cloned(),
    };

    if let Some(sub_matches) = matches.subcommand_matches("keys") {
        let keys_command = KeysCommand::new(global_args.key_dir);
        keys_command.handle_command(sub_matches)?;
    } else if matches.subcommand_matches("get-operator-address").is_some() {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_get_operator_address().await;
    } else if matches.subcommand_matches("get-operator-utxos").is_some() {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_get_operator_utxos().await;
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
    } else if let Some(sub_matches) = matches.subcommand_matches("create-peg-out") {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command
            .handle_create_peg_out_graph_command(sub_matches)
            .await;
    } else if let Some(sub_matches) = matches.subcommand_matches("push-nonces") {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command.handle_push_nonces_command(sub_matches).await;
    } else if let Some(sub_matches) = matches.subcommand_matches("push-signatures") {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command
            .handle_push_signature_command(sub_matches)
            .await;
    } else if let Some(sub_matches) = matches.subcommand_matches("mock-l2-pegout-event") {
        let mut client_command = ClientCommand::new(global_args).await;
        let _ = client_command
            .handle_mock_l2_pegout_event_command(sub_matches)
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
