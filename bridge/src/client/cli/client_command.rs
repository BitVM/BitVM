use super::key_command::{Config, KeysCommand};
use super::utils::get_mock_chain_service;
use crate::client::chain::chain_adaptor::get_chain_adaptor;
use crate::client::client::BitVMClient;
use crate::client::esplora::get_esplora_url;
use crate::commitments::CommitmentMessageId;
use crate::common::ZkProofVerifyingKey;
use crate::constants::DestinationNetwork;
use crate::contexts::base::generate_keys_from_secret;
use crate::proof::{get_proof, invalidate_proof};
use crate::transactions::base::Input;
use ark_serialize::CanonicalDeserialize;

use bitcoin::{Address, PublicKey};
use bitcoin::{Network, OutPoint};
use clap::{arg, ArgMatches, Command};
use colored::Colorize;
use std::io::{self, Write};
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::sleep;

pub struct CommonArgs {
    pub key_dir: Option<String>,
    pub verifiers: Option<Vec<PublicKey>>,
    pub environment: Option<String>,
    pub path_prefix: Option<String>,
}

pub struct ClientCommand {
    client: BitVMClient,
    config: Config,
}

impl ClientCommand {
    pub async fn new(common_args: CommonArgs) -> Self {
        let (source_network, destination_network) = match common_args.environment.as_deref() {
            Some("mainnet") => (Network::Bitcoin, DestinationNetwork::Ethereum),
            Some("testnet") => (Network::Testnet, DestinationNetwork::EthereumSepolia),
            Some("regtest") => (Network::Regtest, DestinationNetwork::Local),
            _ => {
                eprintln!("Invalid environment. Use mainnet, testnet or regtest.");
                std::process::exit(1);
            }
        };

        let keys_command = KeysCommand::new(common_args.key_dir);
        let config = keys_command
            .read_config()
            .expect("Failed to read config file");

        let n_of_n_public_keys = common_args.verifiers.expect("Error: Verifier public keys must be specified either in command line or environment variable.");

        let mut verifying_key = None;
        if let Some(vk) = config.keys.verifying_key.clone() {
            let bytes = hex::decode(vk).unwrap();
            verifying_key = Some(ZkProofVerifyingKey::deserialize_compressed(&*bytes).unwrap());
        }

        let bitvm_client = BitVMClient::new(
            Some(get_esplora_url(source_network)),
            source_network,
            destination_network,
            Some(get_chain_adaptor(DestinationNetwork::Local, None, None)), // TODO: Will be replaced with a destination network specific adaptor once Ethereum support is added.
            &n_of_n_public_keys,
            config.keys.depositor.as_deref(),
            config.keys.operator.as_deref(),
            config.keys.verifier.as_deref(),
            config.keys.withdrawer.as_deref(),
            common_args.path_prefix.as_deref(),
            verifying_key,
        )
        .await;

        Self {
            client: bitvm_client,
            config,
        }
    }

    async fn get_funding_utxo_input(&self, utxo_arg: Option<&String>) -> io::Result<Input> {
        let utxo = utxo_arg.expect("Missing UTXO argument, please see help.");
        let outpoint = OutPoint::from_str(utxo).expect(
            "Could not parse the provided UTXO, please see help for the correct format.",
        );
        let tx = self
            .client
            .esplora
            .get_tx(&outpoint.txid)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Esplora failed to retrieve tx: {e}"),
                )
            })?;
        let tx = tx.expect(&format!("Esplora did not find a txid {}", outpoint.txid));

        Ok(Input {
            outpoint,
            amount: tx.output[outpoint.vout as usize].value,
        })
    }

    pub fn get_operator_address_command() -> Command {
        Command::new("get-operator-address")
            .short_flag('o')
            .about("Get an address spendable by the configured operator private key")
            .after_help("Get an address spendable by the configured operator private key")
    }

    pub async fn handle_get_operator_address(&mut self) -> io::Result<()> {
        println!(
            "Operator address: {}",
            self.client.get_operator_address().to_string().green()
        );
        Ok(())
    }

    pub fn get_operator_utxos_command() -> Command {
        Command::new("get-operator-utxos")
            .short_flag('r')
            .about("Get a list of the operator's utxos")
            .after_help("Get a list of the operator's utxos")
    }

    pub async fn handle_get_operator_utxos(&mut self) -> io::Result<()> {
        let utxos = self.client.get_operator_utxos().await;
        match utxos.len() {
            0 => println!("No operator UTXOs found."),
            utxo_count => {
                println!(
                    "{} operator UTXO{} found (<TXID>:<VOUT> <AMOUNT> <CONFIRMED>):",
                    utxo_count,
                    if utxo_count == 1 { "" } else { "s" }
                );
                for utxo in utxos {
                    println!(
                        "{}:{} {} {}",
                        utxo.txid, utxo.vout, utxo.value, utxo.status.confirmed
                    );
                }
            }
        }

        Ok(())
    }

    pub fn get_depositor_address_command() -> Command {
        Command::new("get-depositor-address")
            .short_flag('d')
            .about("Get an address spendable by the configured depositor private key")
            .after_help("Get an address spendable by the configured depositor private key")
    }

    pub async fn handle_get_depositor_address(&mut self) -> io::Result<()> {
        println!(
            "Depositor address: {}",
            self.client.get_depositor_address().to_string().green()
        );
        Ok(())
    }

    pub fn get_depositor_utxos_command() -> Command {
        Command::new("get-depositor-utxos")
            .short_flag('u')
            .about("Get a list of the depositor's utxos")
            .after_help("Get a list of the depositor's utxos")
    }

    pub async fn handle_get_depositor_utxos(&mut self) -> io::Result<()> {
        let utxos = self.client.get_depositor_utxos().await;
        match utxos.len() {
            0 => println!("No depositor UTXOs found."),
            utxo_count => {
                println!(
                    "{} operator UTXO{} found (<TXID>:<VOUT> <AMOUNT> <CONFIRMED>):",
                    utxo_count,
                    if utxo_count == 1 { "" } else { "s" }
                );
                for utxo in utxos {
                    println!(
                        "{}:{} {} {}",
                        utxo.txid, utxo.vout, utxo.value, utxo.status.confirmed
                    );
                }
            }
        }

        Ok(())
    }

    pub fn get_initiate_peg_in_command() -> Command {
        Command::new("initiate-peg-in")
        .short_flag('n')
        .about("Initiate a peg-in")
        .after_help("Initiate a peg-in by creating a peg-in graph")
        .arg(arg!(-u --utxo <UTXO> "Specify the utxo to spend from. Format: <TXID>:<VOUT>")
        .required(true))
        .arg(arg!(-d --destination_address <EVM_ADDRESS> "The evm-address to send the wrapped bitcoin to")
        .required(true))
    }

    pub async fn handle_initiate_peg_in_command(
        &mut self,
        sub_matches: &ArgMatches,
    ) -> io::Result<()> {
        self.client.sync().await;

        let evm_address = sub_matches
            .get_one::<String>("destination_address")
            .unwrap();
        let input = self
            .get_funding_utxo_input(sub_matches.get_one::<String>("utxo"))
            .await?;
        let peg_in_id = self.client.create_peg_in_graph(input, evm_address).await;

        self.client.flush().await;

        println!("Created peg-in graph with ID: {peg_in_id}");
        println!("Broadcasting deposit...");

        if let Err(e) = self.client.broadcast_peg_in_deposit(&peg_in_id).await {
            eprintln!("Failed to broadcast peg-in deposit: {e}");
        }

        Ok(())
    }

    pub fn get_create_peg_out_graph_command() -> Command {
        Command::new("create-peg-out")
            .short_flag('t')
            .about("Create peg-out graph for specified peg-in graph")
            .after_help("")
            .arg(
                arg!(-u --utxo <UTXO> "Specify the utxo to spend from. Format: <TXID>:<VOUT>")
                    .required(true),
            )
            .arg(
                arg!(-i --peg_in_id <PEG_IN_GRAPH_ID> "Specify the peg-in graph ID").required(true),
            )
    }

    pub async fn handle_create_peg_out_graph_command(
        &mut self,
        sub_matches: &ArgMatches,
    ) -> io::Result<()> {
        self.client.sync().await;

        let peg_in_id = sub_matches.get_one::<String>("peg_in_id").unwrap();
        let input = self
            .get_funding_utxo_input(sub_matches.get_one::<String>("utxo"))
            .await?;

        let peg_out_id = self.client.create_peg_out_graph(
            peg_in_id,
            input,
            CommitmentMessageId::generate_commitment_secrets(),
        );

        self.client.flush().await;

        println!("Created peg-out with ID: {peg_out_id}");
        Ok(())
    }

    pub fn get_push_nonces_command() -> Command {
        Command::new("push-nonces")
            .short_flag('c')
            .about("Push nonces for peg-out or peg-in graph")
            .after_help("")
            .arg(arg!(-i --id <GRAPH_ID> "Specify the peg-in or peg-out graph ID").required(true))
    }

    pub async fn handle_push_nonces_command(&mut self, sub_matches: &ArgMatches) -> io::Result<()> {
        let graph_id = sub_matches.get_one::<String>("id").unwrap();

        self.client.sync().await;
        self.client.push_verifier_nonces(graph_id);
        self.client.flush().await;

        Ok(())
    }

    pub fn get_push_signature_command() -> Command {
        Command::new("push-signatures")
            .short_flag('g')
            .about("Push signatures for peg-out or peg-in graph")
            .after_help("")
            .arg(arg!(-i --id <GRAPH_ID> "Specify the peg-in or peg-out graph ID").required(true))
    }

    pub async fn handle_push_signature_command(
        &mut self,
        sub_matches: &ArgMatches,
    ) -> io::Result<()> {
        let graph_id = sub_matches.get_one::<String>("id").unwrap();

        self.client.sync().await;
        self.client.push_verifier_signature(graph_id);
        self.client.flush().await;

        Ok(())
    }

    pub fn get_mock_l2_pegout_event_command() -> Command {
        Command::new("mock-l2-pegout-event")
            .short_flag('x')
            .about("FOR TEST PURPOSES ONLY! Use mock L2 chain service with specified peg-in-confirm txid")
            .after_help("")
            .arg(
                arg!(-u --utxo <UTXO> "Specify the peg-in confirm utxo. Format: <TXID>:<VOUT>")
                    .required(true),
            )
    }

    pub async fn handle_mock_l2_pegout_event_command(
        &mut self,
        sub_matches: &ArgMatches,
    ) -> io::Result<()> {
        let utxo = sub_matches.get_one::<String>("utxo").unwrap();
        let outpoint = OutPoint::from_str(utxo).expect(
            "Could not parse the provided UTXO, please see help for the correct format: {e}.",
        );

        if let Some(operator_secret) = &self.config.keys.operator {
            let (_, operator_public_key) =
                generate_keys_from_secret(self.client.source_network, operator_secret);

            self.client.sync().await;
            let mock_chain_service = get_mock_chain_service(outpoint, operator_public_key);
            self.client.set_chain_service(mock_chain_service);
            self.client.sync_l2().await;
            self.client.flush().await;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to set chain service, missing operator configuration",
            ));
        }

        Ok(())
    }

    pub fn get_automatic_command() -> Command {
        Command::new("automatic")
            .short_flag('a')
            .about("Automatic mode: Poll for status updates and sign or broadcast transactions")
    }

    pub async fn handle_automatic_command(&mut self) -> io::Result<()> {
        loop {
            self.client.sync().await;

            let old_data = self.client.data().clone();

            self.client.process_peg_ins().await;
            self.client.process_peg_outs().await;

            // A bit inefficient, but fine for now: only flush if data changed
            if self.client.data() != &old_data {
                self.client.flush().await;
            } else {
                sleep(Duration::from_millis(250)).await;
            }
        }
    }

    // TODO: there are verifier's commands missing here
    pub fn get_broadcast_command() -> Command {
        Command::new("broadcast")
            .short_flag('b')
            .about("Broadcast transactions")
            .after_help("Broadcast transactions.")
            .subcommand(
                Command::new("pegin")
                    .about("Broadcast peg-in transactions")
                    .arg(arg!(-g --graph_id <GRAPH_ID> "Peg-in graph ID").required(true))
                    .subcommand(Command::new("deposit").about("Broadcast peg-in deposit"))
                    .subcommand(Command::new("refund").about("Broadcast peg-in refund"))
                    .subcommand(Command::new("confirm").about("Broadcast peg-in confirm"))
                    .subcommand_required(true),
            )
            .subcommand(
                Command::new("tx")
                    .about("Broadcast transactions")
                    .arg(arg!(-g --graph_id <GRAPH_ID> "Peg-out graph ID").required(true))
                    .arg(arg!(-u --utxo <UTXO> "Specify the utxo to spend from. Format: <TXID>:<VOUT>").required(false))
                    .arg(arg!(-a --address <ADDRESS> "Specify the reward address to receive BTC reward").required(false))
                    .subcommand(Command::new("peg_out").about("Broadcast peg-out"))
                    .subcommand(Command::new("peg_out_confirm").about("Broadcast peg-out confirm"))
                    .subcommand(Command::new("kick_off_1").about("Broadcast kick off 1"))
                    .subcommand(Command::new("kick_off_2").about("Broadcast kick off 2"))
                    .subcommand(Command::new("start_time").about("Broadcast start time"))
                    .subcommand(Command::new("assert_initial").about("Broadcast assert initial"))
                    .subcommand(
                        Command::new("assert_commits").about("Broadcast assert commitments"),
                    )
                    .subcommand(
                        Command::new("assert_commit_1").about("Broadcast assert commit 1"),
                    )
                    .subcommand(
                        Command::new("assert_commit_2").about("Broadcast assert commit 2"),
                    )
                    .subcommand(
                      Command::new("assert_commit_1_invalid").about("FOR TEST PURPOSES ONLY! Broadcast assert commit 1 with invalid proof"),
                    )
                    .subcommand(
                      Command::new("assert_commit_2_invalid").about("FOR TEST PURPOSES ONLY! Broadcast assert commit 2 with invalid proof"),
                    )
                    .subcommand(Command::new("assert_final").about("Broadcast assert final"))
                    .subcommand(Command::new("take_1").about("Broadcast take 1"))
                    .subcommand(Command::new("take_2").about("Broadcast take 2"))
                    .subcommand(Command::new("disprove").about("Broadcast disprove"))
                    .subcommand_required(true),
            )
            .subcommand_required(true)
    }

    pub async fn handle_broadcast_command(&mut self, sub_matches: &ArgMatches) -> io::Result<()> {
        self.client.sync().await;

        let subcommand = sub_matches.subcommand();
        let graph_id = subcommand.unwrap().1.get_one::<String>("graph_id").unwrap();

        match subcommand.unwrap().1.subcommand() {
            Some(("assert_commits", _)) => {
                let result = self
                    .client
                    .broadcast_assert_commits(graph_id, &get_proof())
                    .await;
                if let Err(e) = result {
                    println!("Failed to broadcast transaction: {e}");
                }
            }
            Some((others, _)) => {
                let result = match others {
                    "deposit" => self.client.broadcast_peg_in_deposit(graph_id).await,
                    "refund" => self.client.broadcast_peg_in_refund(graph_id).await,
                    "confirm" => self.client.broadcast_peg_in_confirm(graph_id).await,
                    "peg_out" => {
                        let input = self
                            .get_funding_utxo_input(subcommand.unwrap().1.get_one::<String>("utxo"))
                            .await?;
                        let result = self.client.broadcast_peg_out(graph_id, input).await;
                        self.client.flush().await;
                        result
                    }
                    "peg_out_confirm" => self.client.broadcast_peg_out_confirm(graph_id).await,
                    "kick_off_1" => self.client.broadcast_kick_off_1(graph_id).await,
                    "kick_off_2" => self.client.broadcast_kick_off_2(graph_id).await,
                    "start_time" => self.client.broadcast_start_time(graph_id).await,
                    "assert_initial" => self.client.broadcast_assert_initial(graph_id).await,
                    "assert_commit_1_invalid" => {
                        self.client
                            .broadcast_assert_commit_1(graph_id, &invalidate_proof(&get_proof()))
                            .await
                    }
                    "assert_commit_2_invalid" => {
                        self.client
                            .broadcast_assert_commit_2(graph_id, &invalidate_proof(&get_proof()))
                            .await
                    }
                    "assert_final" => self.client.broadcast_assert_final(graph_id).await,
                    "take_1" => self.client.broadcast_take_1(graph_id).await,
                    "take_2" => self.client.broadcast_take_2(graph_id).await,
                    "disprove" => {
                        let address = subcommand.unwrap().1.get_one::<String>("address").unwrap();
                        let reward_address = Address::from_str(address).unwrap();
                        let reward_script = reward_address.assume_checked().script_pubkey(); // TODO: verify checked/unchecked address

                        self.client
                            .broadcast_disprove(graph_id, reward_script)
                            .await
                    }
                    &_ => unreachable!(),
                };
                if let Err(e) = result {
                    println!("Failed to broadcast transaction: {e}");
                }
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    pub fn get_status_command() -> Command {
        Command::new("status")
            .short_flag('s')
            .about("Show the status of the BitVM client")
            .after_help("Get the status of the BitVM client.")
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
                let key_dir = matches.get_one::<String>("key-dir").cloned();
                let keys_command = KeysCommand::new(key_dir);
                keys_command.handle_command(sub_matches)?;
            } else if matches.subcommand_matches("get-operator-address").is_some() {
                self.handle_get_operator_address().await?;
            } else if matches.subcommand_matches("get-operator-utxos").is_some() {
                self.handle_get_operator_utxos().await?;
            } else if matches
                .subcommand_matches("get-depositor-address")
                .is_some()
            {
                self.handle_get_depositor_address().await?;
            } else if matches.subcommand_matches("get-depositor-utxos").is_some() {
                self.handle_get_depositor_utxos().await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("initiate-peg-in") {
                self.handle_initiate_peg_in_command(sub_matches).await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("create-peg-out") {
                self.handle_create_peg_out_graph_command(sub_matches)
                    .await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("push-nonces") {
                self.handle_push_nonces_command(sub_matches).await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("push-signatures") {
                self.handle_push_signature_command(sub_matches).await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("mock-l2-pegout-event") {
                self.handle_mock_l2_pegout_event_command(sub_matches)
                    .await?;
            } else if matches.subcommand_matches("status").is_some() {
                self.handle_status_command().await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("broadcast") {
                self.handle_broadcast_command(sub_matches).await?;
            } else if matches.subcommand_matches("automatic").is_some() {
                self.handle_automatic_command().await?;
            } else if matches.subcommand_matches("interactive").is_some() {
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
