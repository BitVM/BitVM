use super::key_command::KeysCommand;
use crate::bridge::client::client::BitVMClient;
use crate::bridge::constants::DestinationNetwork;
use crate::bridge::contexts::base::generate_keys_from_secret;
use crate::bridge::graphs::base::{BaseGraph, VERIFIER_0_SECRET, VERIFIER_1_SECRET};
use crate::bridge::graphs::peg_in::PegInDepositorStatus;
use crate::bridge::graphs::peg_out::PegOutOperatorStatus;
use crate::bridge::superblock::{find_superblock, get_superblock_message};
use bitcoin::Network;
use bitcoin::PublicKey;
use clap::{arg, ArgMatches, Command};
use colored::Colorize;
use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, BufReader};

pub struct ClientCommand {
    client: BitVMClient,
}

impl ClientCommand {
    pub async fn new(sub_matches: &ArgMatches) -> Self {
        let (source_network, destination_network) = match sub_matches
            .get_one::<String>("environment")
            .unwrap()
            .as_str()
        {
            "mainnet" => (Network::Bitcoin, DestinationNetwork::Ethereum),
            "testnet" => (Network::Testnet, DestinationNetwork::EthereumSepolia),
            _ => {
                eprintln!("Invalid environment. Use mainnet, testnet.");
                std::process::exit(1);
            }
        };

        let keys_command = KeysCommand::new();
        let config = keys_command.read_config().expect("Failed to read config");

        let (_, _, verifier_0_public_key) =
            generate_keys_from_secret(Network::Bitcoin, VERIFIER_0_SECRET);
        let (_, _, verifier_1_public_key) =
            generate_keys_from_secret(Network::Bitcoin, VERIFIER_1_SECRET);

        let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
        n_of_n_public_keys.push(verifier_0_public_key);
        n_of_n_public_keys.push(verifier_1_public_key);

        let bitvm_client = BitVMClient::new(
            source_network,
            destination_network,
            &n_of_n_public_keys,
            config.keys.depositor.as_deref(),
            config.keys.operator.as_deref(),
            config.keys.verifier.as_deref(),
            config.keys.withdrawer.as_deref(),
            None,
        )
        .await;

        Self {
            client: bitvm_client,
        }
    }

    pub fn get_automatic_command() -> Command {
        Command::new("automatic")
            .short_flag('a')
            .about("Automatic mode: Poll for status updates and sign or broadcast transactions")
            .arg(arg!(-e --environment <ENVIRONMENT> "Specify the Bitcoin network environment (mainnet, testnet )").required(false)
        .default_value("mainnet"))
    }

    pub async fn handle_automatic_command(&mut self) -> io::Result<()> {
        loop {
            self.client.sync().await;

            let peg_in_graphs = self.client.get_data().peg_in_graphs.clone();

            for peg_in_graph in peg_in_graphs.iter() {
                let status = peg_in_graph.depositor_status(&self.client.esplora).await;

                self.client.pre_sign_peg_in(peg_in_graph.id());
                match status {
                    PegInDepositorStatus::PegInDepositWait => {
                        self.client
                            .broadcast_peg_in_deposit(peg_in_graph.id())
                            .await
                    }
                    PegInDepositorStatus::PegInConfirmWait => {
                        self.client
                            .broadcast_peg_in_confirm(peg_in_graph.id())
                            .await
                    }
                    _ => {
                        println!(
                            "Peg-in graph {} is in status: {}",
                            peg_in_graph.id(),
                            status
                        );
                    }
                }
            }

            let peg_out_graphs = self.client.get_data().peg_out_graphs.clone();
            for peg_out_graph in peg_out_graphs.iter() {
                let status = peg_out_graph.operator_status(&self.client.esplora).await;
                match status {
                    PegOutOperatorStatus::PegOutStartTimeAvailable => {
                        self.client.broadcast_start_time(peg_out_graph.id()).await
                    }
                    PegOutOperatorStatus::PegOutPegOutConfirmAvailable => {
                        self.client
                            .broadcast_peg_out_confirm(peg_out_graph.id())
                            .await
                    }
                    PegOutOperatorStatus::PegOutKickOff1Available => {
                        self.client.broadcast_kick_off_1(peg_out_graph.id()).await
                    }
                    PegOutOperatorStatus::PegOutKickOff2Available => {
                        let (sb, sb_hash) = find_superblock();
                        self.client
                            .broadcast_kick_off_2(
                                peg_out_graph.id(),
                                &get_superblock_message(&sb, &sb_hash),
                            )
                            .await
                    }
                    PegOutOperatorStatus::PegOutAssertAvailable => {
                        self.client.broadcast_assert(peg_out_graph.id()).await
                    }
                    PegOutOperatorStatus::PegOutTake1Available => {
                        self.client.broadcast_take_1(peg_out_graph.id()).await
                    }
                    PegOutOperatorStatus::PegOutTake2Available => {
                        self.client.broadcast_take_2(peg_out_graph.id()).await
                    }
                    _ => {
                        println!(
                            "Peg-out graph {} is in status: {}",
                            peg_out_graph.id(),
                            status
                        );
                    }
                }
            }
            self.client.sync().await;
            self.client.flush().await;
        }
    }

    pub fn get_broadcast_command() -> Command {
        Command::new("broadcast")
            .short_flag('b')
            .about("Broadcast transactions")
            .arg(arg!(-e --environment <ENVIRONMENT> "Specify the Bitcoin network environment (mainnet, testnet)")
                .required(false).default_value("mainnet"))
            .after_help("Broadcast transactions. The environment flag is optional and defaults to mainnet if not specified.")
            .subcommand(
                Command::new("pegin")
                    .about("Broadcast peg-in transactions")
                    .arg(arg!(-g --graph_id <GRAPH_ID> "Peg-in graph ID").required(true))
                    .subcommand(Command::new("deposit").about("Broadcast peg-in deposit"))
                    .subcommand(Command::new("refund").about("Broadcast peg-in refund"))
                    .subcommand(Command::new("confirm").about("Broadcast peg-in confirm"))
                    .subcommand_required(true)
            )
            .subcommand(
                Command::new("tx")
                    .about("Broadcast transactions")
                    .arg(arg!(-g --graph_id <GRAPH_ID> "Peg-out graph ID").required(true))
                    .subcommand(Command::new("peg_out_confirm").about("Broadcast peg-out confirm"))
                    .subcommand(Command::new("kick_off_1").about("Broadcast kick off 1"))
                    .subcommand(Command::new("kick_off_2").about("Broadcast kick off 2"))
                    .subcommand(Command::new("start_time").about("Broadcast start time"))
                    .subcommand(Command::new("assert").about("Broadcast assert"))
                    .subcommand(Command::new("take_1").about("Broadcast take 1"))
                    .subcommand(Command::new("take_2").about("Broadcast take 2"))
                    .subcommand_required(true)
            )
            .subcommand_required(true)
    }

    pub async fn handle_broadcast_command(&mut self, sub_matches: &ArgMatches) -> io::Result<()> {
        let subcommand = sub_matches.subcommand();
        let graph_id = subcommand.unwrap().1.get_one::<String>("graph_id").unwrap();

        match subcommand.unwrap().1.subcommand() {
            Some(("deposit", _)) => self.client.broadcast_peg_in_deposit(graph_id).await,
            Some(("refund", _)) => self.client.broadcast_peg_in_refund(graph_id).await,
            Some(("confirm", _)) => self.client.broadcast_peg_in_confirm(graph_id).await,
            Some(("peg_out_confirm", _)) => self.client.broadcast_peg_out_confirm(graph_id).await,
            Some(("kick_off_1", _)) => self.client.broadcast_kick_off_1(graph_id).await,
            Some(("kick_off_2", _)) => {
                let (sb, sb_hash) = find_superblock();
                self.client
                    .broadcast_kick_off_2(graph_id, &get_superblock_message(&sb, &sb_hash))
                    .await
            }
            Some(("start_time", _)) => self.client.broadcast_start_time(graph_id).await,
            Some(("assert", _)) => self.client.broadcast_assert(graph_id).await,
            Some(("take_1", _)) => self.client.broadcast_take_1(graph_id).await,
            Some(("take_2", _)) => self.client.broadcast_take_2(graph_id).await,
            _ => unreachable!(),
        };

        Ok(())
    }

    pub fn get_status_command() -> Command {
        Command::new("status")
        .short_flag('s')
        .about("Show the status of the BitVM client")
        .after_help("Get the status of the BitVM client. The environment flag is optional and defaults to mainnet if not specified.")
        .arg(arg!(-e --environment <ENVIRONMENT> "Specify the Bitcoin network environment (mainnet, testnet)")
        .required(false).default_value("mainnet"))
    }

    pub async fn handle_status_command(&mut self) -> io::Result<()> {
        self.client.sync().await;
        self.client.status().await;
        Ok(())
    }

    pub fn get_interactive_command() -> Command {
        Command::new("interactive")
            .short_flag('i')
            .about("Interactive mode for manually issuing commands")
            .arg(arg!(-e --environment <ENVIRONMENT> "Specify the Bitcoin network environment (mainnet, testnet)").required(false).default_value("mainnet"))
    }

    pub async fn handle_interactive_command(&mut self, main_command: &Command) -> io::Result<()> {
        println!(
            "{}",
            "Entering interactive mode. Type 'help' for a list of commands and 'exit' to quit."
                .green()
        );

        let mut stdin_reader = BufReader::new(tokio::io::stdin());
        loop {
            print!("{}", "bitvm >> ".bold());
            io::stdout().flush().unwrap(); // Ensure the prompt is printed out immediately

            let mut line = String::new();
            stdin_reader.read_line(&mut line).await.unwrap();
            let input = line.trim();

            if input == "exit" {
                break;
            }

            let mut args = vec!["bitvm"];
            args.extend(input.split_whitespace());

            let matches = match main_command.clone().try_get_matches_from(args) {
                Ok(matches) => matches,
                Err(e) => {
                    if !e.to_string().to_lowercase().contains("error") {
                        println!("{}", format!("{}", e).green());
                    } else {
                        println!("{}", format!("{}", e).red());
                    }
                    continue;
                }
            };

            if let Some(sub_matches) = matches.subcommand_matches("keys") {
                let keys_command = KeysCommand::new();
                keys_command.handle_command(sub_matches)?;
            } else if let Some(_sub_matches) = matches.subcommand_matches("status") {
                self.handle_status_command().await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("broadcast") {
                self.handle_broadcast_command(sub_matches).await?;
            } else if let Some(_sub_matches) = matches.subcommand_matches("automatic") {
                self.handle_automatic_command().await?;
            } else if let Some(_sub_matches) = matches.subcommand_matches("interactive") {
                println!("{}", "Already in interactive mode.".yellow());
            } else {
                println!(
                    "{}",
                    "Unknown command. Type 'help' for a list of commands.".red()
                );
            }
        }

        println!("{}", "Exiting interactive mode.".green());
        Ok(())
    }
}
