use bitvm::bridge::client::cli::client_command::ClientCommand;
use bitvm::bridge::client::cli::key_command::KeysCommand;
use clap::command;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let command = command!() // requires `cargo` feature
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(KeysCommand::get_command())
        .subcommand(ClientCommand::get_status_command())
        .subcommand(ClientCommand::get_broadcast_command())
        .subcommand(ClientCommand::get_automatic_command())
        .subcommand(ClientCommand::get_interactive_command());

    let matches = command.clone().get_matches();

    if let Some(sub_matches) = matches.subcommand_matches("keys") {
        let keys_command = KeysCommand::new();
        keys_command.handle_command(sub_matches)?;
    } else if let Some(sub_matches) = matches.subcommand_matches("status") {
        let mut client_command = ClientCommand::new(sub_matches).await;
        let _ = client_command.handle_status_command().await;
    } else if let Some(sub_matches) = matches.subcommand_matches("broadcast") {
        let mut client_command = ClientCommand::new(sub_matches).await;
        let _ = client_command.handle_broadcast_command(sub_matches).await;
    } else if let Some(sub_matches) = matches.subcommand_matches("automatic") {
        let mut client_command = ClientCommand::new(sub_matches).await;
        let _ = client_command.handle_automatic_command().await;
    } else if let Some(sub_matches) = matches.subcommand_matches("interactive") {
        let mut client_command = ClientCommand::new(sub_matches).await;
        let _ = client_command.handle_interactive_command(&command).await;
    }

    Ok(())
}
