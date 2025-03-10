use bitcoin::{
    absolute::Height,
    consensus::encode::serialize_hex,
    hashes::{hash160, Hash},
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Transaction, Txid, XOnlyPublicKey,
};
use colored::Colorize;
use esplora_client::{AsyncClient, Builder, TxStatus, Utxo};
use futures::future::join_all;
use human_bytes::human_bytes;
use musig2::SecNonce;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use crate::{
    client::{
        chain::ethereum_adaptor::EthereumAdaptor, esplora::get_esplora_url,
        files::DEFAULT_PATH_PREFIX,
    },
    commitments::CommitmentMessageId,
    common::ZkProofVerifyingKey,
    connectors::{base::TaprootConnector, connector_0::Connector0, connector_z::ConnectorZ},
    constants::DestinationNetwork,
    contexts::base::generate_n_of_n_public_key,
    error::{ClientError, Error},
    graphs::{
        base::{
            broadcast_and_verify, get_tx_statuses, GraphId, PEG_OUT_FEE, REWARD_MULTIPLIER,
            REWARD_PRECISION,
        },
        peg_in::{PegInDepositorStatus, PegInVerifierStatus},
        peg_out::PegOutOperatorStatus,
    },
    proof::get_proof,
    scripts::generate_pay_to_pubkey_script_address,
    serialization::{serialize, try_deserialize_slice},
    transactions::{
        peg_in_confirm::PegInConfirmTransaction, peg_in_deposit::PegInDepositTransaction,
        peg_in_refund::PegInRefundTransaction, pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use bitvm::{
    // chunker::disprove_execution::RawProof,
    chunk::api::type_conversion_utils::RawProof,
    signatures::signing_winternitz::WinternitzSecret,
};

use super::{
    super::{
        contexts::{
            depositor::DepositorContext, operator::OperatorContext, verifier::VerifierContext,
            withdrawer::WithdrawerContext,
        },
        graphs::{
            base::BaseGraph,
            peg_in::{generate_id as peg_in_generate_id, PegInGraph},
            peg_out::{generate_id as peg_out_generate_id, PegOutGraph},
        },
        transactions::{
            base::{Input, InputWithScript},
            pre_signed::PreSignedTransaction,
        },
    },
    chain::{chain::Chain, chain_adaptor::ChainAdaptor},
    data_store::data_store::DataStore,
    files::{
        get_private_data_file_path, get_private_data_from_file, save_local_private_file,
        save_local_public_file, BRIDGE_DATA_DIRECTORY_NAME,
    },
    memory_cache::PUBLIC_DATA_VALIDATION_CACHE,
    sdk::{
        query::{ClientCliQuery, GraphCliQuery},
        query_contexts::depositor_signatures::DepositorSignatures,
    },
};

const TEN_MINUTES: u64 = 10 * 60;

pub type UtxoSet = HashMap<OutPoint, Height>;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct BitVMClientPublicData {
    pub version: u32,
    pub peg_in_graphs: Vec<PegInGraph>,
    pub peg_out_graphs: Vec<PegOutGraph>,
}

impl BitVMClientPublicData {
    pub fn graph_mut(&mut self, graph_id: &GraphId) -> &mut dyn BaseGraph {
        if let Some(peg_in) = self.peg_in_graphs.iter_mut().find(|x| x.id() == graph_id) {
            return peg_in;
        }
        if let Some(peg_out) = self.peg_out_graphs.iter_mut().find(|x| x.id() == graph_id) {
            return peg_out;
        }
        panic!("Graph ID not found");
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct BitVMClientPrivateData {
    // Peg in and peg out nonces all go into the same file for now
    // Verifier public key -> Graph ID -> Tx ID -> Input index -> Secret nonce
    #[allow(clippy::type_complexity)]
    pub secret_nonces: HashMap<PublicKey, HashMap<String, HashMap<Txid, HashMap<usize, SecNonce>>>>,
    // Operator Winternitz secrets for all the graphs.
    // Operator public key -> Graph ID -> Message ID -> Winternitz secret
    pub commitment_secrets:
        HashMap<PublicKey, HashMap<String, HashMap<CommitmentMessageId, WinternitzSecret>>>,
}

pub struct BitVMClient {
    pub esplora: AsyncClient,
    pub source_network: Network,

    depositor_context: Option<DepositorContext>,
    operator_context: Option<OperatorContext>,
    verifier_context: Option<VerifierContext>,
    withdrawer_context: Option<WithdrawerContext>,

    data_store: DataStore,
    data: BitVMClientPublicData,
    latest_processed_file_name: Option<String>,
    remote_file_path: String,
    local_file_path: PathBuf,

    private_data: BitVMClientPrivateData,

    chain_service: Chain,

    zkproof_verifying_key: Option<ZkProofVerifyingKey>,
}

impl BitVMClient {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        esplora_url: Option<&str>,
        source_network: Network,
        destination_network: DestinationNetwork,
        chain_adaptor: Option<Box<dyn ChainAdaptor>>,
        n_of_n_public_keys: &[PublicKey],
        depositor_secret: Option<&str>,
        operator_secret: Option<&str>,
        verifier_secret: Option<&str>,
        withdrawer_secret: Option<&str>,
        file_path_prefix: Option<&str>,
        zkproof_verifying_key: Option<ZkProofVerifyingKey>,
    ) -> Self {
        let depositor_context = depositor_secret
            .map(|secret| DepositorContext::new(source_network, secret, n_of_n_public_keys));

        let operator_context = operator_secret
            .map(|secret| OperatorContext::new(source_network, secret, n_of_n_public_keys));

        let verifier_context = verifier_secret
            .map(|secret| VerifierContext::new(source_network, secret, n_of_n_public_keys));

        let withdrawer_context = withdrawer_secret
            .map(|secret| WithdrawerContext::new(source_network, secret, n_of_n_public_keys));

        let (n_of_n_public_key, _) = generate_n_of_n_public_key(n_of_n_public_keys);

        // NOTE: This path is used to save files in the remote data store (currently AWS S3).
        // Although S3 implements a flat object storage model without true directories, it uses '/'
        // as a delimiter to simulate a hierarchical directory structure. For this reason we use it
        // explicitly in the format string below.
        let remote_file_path = format! {"{BRIDGE_DATA_DIRECTORY_NAME}/{source_network}/{destination_network}/{n_of_n_public_key}"};
        // The local file path, on the other hand, must use the platform specific path separator.
        // Additionally, it includes the provided file path prefix to create a user namespace.
        let local_file_path = Path::new(BRIDGE_DATA_DIRECTORY_NAME)
            .join(file_path_prefix.unwrap_or(DEFAULT_PATH_PREFIX)) // TODO: Refactor to require a prefix and remove the const, as the client already has a default and will always pass it. Also rename to 'user_profile' to match the client implementation.
            .join(source_network.to_string())
            .join(destination_network.to_string())
            .join(n_of_n_public_key.to_string());
        println!("Using data file path: {}", local_file_path.display());

        let data = BitVMClientPublicData {
            version: 1,
            peg_in_graphs: vec![],
            peg_out_graphs: vec![],
        };

        let data_store = DataStore::new().await;

        let private_data =
            get_private_data_from_file(&get_private_data_file_path(&local_file_path));

        Self {
            esplora: Builder::new(esplora_url.unwrap_or(get_esplora_url(source_network)))
                .build_async()
                .expect("Could not build esplora client"),
            source_network,

            depositor_context,
            operator_context,
            verifier_context,
            withdrawer_context,

            data_store,
            data,
            latest_processed_file_name: None,
            remote_file_path,
            local_file_path,

            private_data,

            chain_service: Chain::new(
                chain_adaptor.unwrap_or_else(|| Box::new(EthereumAdaptor::new(None))),
            ),

            zkproof_verifying_key,
        }
    }

    pub fn data(&self) -> &BitVMClientPublicData { &self.data }

    pub fn data_mut(&mut self) -> &mut BitVMClientPublicData { &mut self.data }

    // TODO: This should be private. Currently used in the fees test. See if it can be refactored.
    pub fn private_data(&self) -> &BitVMClientPrivateData { &self.private_data }

    // TODO: This fn is only used in tests. Consider refactoring, so it can be removed.
    pub fn set_chain_service(&mut self, chain_service: Chain) {
        self.chain_service = chain_service;
    }

    fn save_private_data(&self) {
        save_local_private_file(&self.local_file_path, &serialize(&self.private_data));
    }

    pub async fn sync(&mut self) { self.read_from_data_store().await; }

    pub async fn sync_l2(&mut self) { self.read_from_l2().await; }

    pub async fn flush(&mut self) { self.save_to_data_store().await; }

    /*
    Expected file syncing flow with data store:
     1. Fetch the latest file                               ⎫
     2. Fetch all files within 10 minutes (use timestamp)   ⎬ BitVMClient::sync()
     3. Merge files                                         ⎭
     4. Client modifies file and clicks save                } BitVMClient::<mutating operation>
     5. Fetch files that were created after fetching 1-2.   ⎫
     6. Merge with your file                                ⎬ BitVMClient::flush()
     7. Push the file to the server                         ⎭
    */

    async fn read_from_data_store(&mut self) {
        let latest_file_names_result = Self::get_latest_file_names(
            &self.data_store,
            Some(&self.remote_file_path),
            self.latest_processed_file_name.clone(),
        )
        .await;

        if latest_file_names_result.is_ok() {
            let mut latest_file_names = latest_file_names_result.unwrap();
            if !latest_file_names.is_empty() {
                // fetch latest valid file
                let (latest_file, latest_file_name) =
                    self.fetch_latest_valid_file(&mut latest_file_names).await;
                if latest_file.is_some() && latest_file_name.is_some() {
                    save_local_public_file(
                        &self.local_file_path,
                        latest_file_name.as_ref().unwrap(),
                        &serialize(&latest_file.as_ref().unwrap()),
                    );
                    self.latest_processed_file_name = latest_file_name;

                    // fetch and process all the previous files if latest valid file exists
                    let result =
                        Self::process_files_by_timestamp(self, latest_file_names, TEN_MINUTES)
                            .await;
                    match result {
                        Ok(_) => (), // println!("Ok"),
                        Err(err) => println!("Error: {}", err),
                    }

                    self.merge_data(latest_file.unwrap()); // merge the latest data at the end
                }
            }
        } else {
            println!("Error: {}", latest_file_names_result.unwrap_err());
        }
    }

    async fn read_from_l2(&mut self) {
        let peg_out_result = self.chain_service.get_peg_out_init().await;
        if peg_out_result.is_ok() {
            let mut events = peg_out_result.unwrap();
            for peg_out_graph in self.data.peg_out_graphs.iter_mut() {
                if !peg_out_graph.is_peg_out_initiated() {
                    match peg_out_graph.match_and_set_peg_out_event(&mut events).await {
                        Ok(_) => {
                            if peg_out_graph.peg_out_chain_event.is_some() {
                                println!(
                                    "Peg-out graph ID: {} Event Matched, Event: {:?}",
                                    peg_out_graph.id(),
                                    peg_out_graph.peg_out_chain_event
                                )
                            }
                        }
                        Err(err) => println!("Error: {}", err),
                    }
                }
            }
        } else {
            panic!("Get event failed from L2 chain: {:?}", peg_out_result.err());
        }
    }

    async fn get_latest_file_names(
        data_store: &DataStore,
        file_path: Option<&str>,
        fetched_file_name: Option<String>,
    ) -> Result<Vec<String>, String> {
        let all_file_names_result = data_store.get_file_names(file_path).await;
        if all_file_names_result.is_ok() {
            let mut all_file_names = all_file_names_result.unwrap();

            if fetched_file_name.is_some() {
                let fetched_file_position = all_file_names
                    .iter()
                    .position(|file_name| file_name.eq(fetched_file_name.as_ref().unwrap()));
                if fetched_file_position.is_some() {
                    let unfetched_file_position = fetched_file_position.unwrap() + 1;
                    if all_file_names.len() > unfetched_file_position {
                        all_file_names = all_file_names.split_off(unfetched_file_position);
                    } else {
                        all_file_names.clear(); // no files to process
                    }
                }
            }

            Ok(all_file_names)
        } else {
            Err(all_file_names_result.err().unwrap())
        }
    }

    async fn filter_files_names_by_timestamp(
        &self,
        latest_file_names: Vec<String>,
        period: u64,
    ) -> Result<Vec<String>, String> {
        if self.latest_processed_file_name.is_some() {
            let latest_timestamp = self
                .data_store
                .get_file_timestamp(self.latest_processed_file_name.as_ref().unwrap())?;

            let past_max_file_name = self
                .data_store
                .get_past_max_file_name_by_timestamp(latest_timestamp, period);

            let mut previous_max_position = latest_file_names
                .iter()
                .position(|file_name| file_name >= &past_max_file_name);
            if previous_max_position.is_none() {
                previous_max_position = Some(latest_file_names.len());
            }

            let file_names_to_process = latest_file_names
                .clone()
                .split_off(previous_max_position.unwrap());

            Ok(file_names_to_process)
        } else {
            Err(String::from(
                "No latest file data. Must fetch the latest file first.",
            ))
        }
    }

    async fn process_files_by_timestamp(
        &mut self,
        latest_file_names: Vec<String>,
        period: u64,
    ) -> Result<String, String> {
        let file_names_to_process = self
            .filter_files_names_by_timestamp(latest_file_names, period)
            .await?;

        Self::process_files(self, file_names_to_process).await;

        Ok(String::from("Files processed"))
    }

    async fn process_files(&mut self, file_names: Vec<String>) -> Option<String> {
        let mut latest_valid_file_name: Option<String> = None;
        if file_names.is_empty() {
            // println!("No additional files to process")
        } else {
            // TODO: can be optimized to fetch all data at once?
            for file_name in file_names.iter() {
                let (latest_data, _, _) = self.validate_data_with_cache_by_key(&file_name).await;

                if latest_data.is_some() {
                    // merge the file if the data is valid
                    println!("Merging {} data...", { file_name });
                    self.merge_data(latest_data.unwrap());
                    if latest_valid_file_name.is_none() {
                        latest_valid_file_name = Some(file_name.clone());
                    }
                } else {
                    // skip the file if the data is invalid
                    println!("Invalid file {}, Skipping...", file_name);
                }
            }
        }

        latest_valid_file_name
    }

    async fn fetch_latest_valid_file(
        &self,
        file_names: &mut Vec<String>,
    ) -> (Option<BitVMClientPublicData>, Option<String>) {
        let mut latest_valid_file: Option<BitVMClientPublicData> = None;
        let mut latest_valid_file_name: Option<String> = None;

        while !file_names.is_empty() {
            let file_name_result = file_names.pop();
            if file_name_result.is_some() {
                let file_name = file_name_result.unwrap();
                let (latest_data, latest_data_len, encoded_size) =
                    self.validate_data_with_cache_by_key(&file_name).await;
                if latest_data.is_some() {
                    // data is valid
                    println!(
                        "Fetched valid file: {} (size: {}, compressed: {})",
                        file_name,
                        human_bytes(latest_data_len as f64),
                        human_bytes(encoded_size as f64)
                    );
                    latest_valid_file = latest_data;
                    latest_valid_file_name = Some(file_name);
                    break;
                } else {
                    println!("Invalid file: {}", file_name); // TODO: can be removed
                }
                // for invalid data try another file
            }
        }

        (latest_valid_file, latest_valid_file_name)
    }

    async fn save_to_data_store(&mut self) {
        // read newly created data before pushing
        let latest_file_names_result = Self::get_latest_file_names(
            &self.data_store,
            Some(&self.remote_file_path),
            self.latest_processed_file_name.clone(),
        )
        .await;

        if latest_file_names_result.is_ok() {
            let mut latest_file_names = latest_file_names_result.unwrap();
            latest_file_names.reverse();
            let latest_valid_file_name = Self::process_files(self, latest_file_names).await;
            self.latest_processed_file_name = latest_valid_file_name;
        }

        // push data
        self.data.version += 1;

        let contents = serialize(&self.data);
        let result = self
            .data_store
            .write_compressed_data(&contents.as_bytes().to_vec(), Some(&self.remote_file_path))
            .await;
        match result {
            Ok((file_name, size)) => {
                println!(
                    "Pushed new file: {} (size: {}, compressed: {})",
                    file_name,
                    human_bytes(contents.len() as f64),
                    human_bytes(size as f64)
                );
                save_local_public_file(&self.local_file_path, &file_name, &contents);
                self.latest_processed_file_name = Some(file_name);
            }
            Err(err) => println!("Failed to push: {}", err),
        }
    }

    pub async fn validate_data_with_cache_by_key(
        &self,
        file_name: &str,
    ) -> (Option<BitVMClientPublicData>, usize, usize) {
        let result = self
            .data_store
            .fetch_compressed_data_by_key(file_name, Some(&self.remote_file_path))
            .await;
        if result.is_ok() {
            if let (Some(content), encoded_size) = result.unwrap() {
                let data = try_deserialize_slice(&content);
                if let Ok(data) = data {
                    let hash = hex::encode(hash160::Hash::hash(&content));
                    if match PUBLIC_DATA_VALIDATION_CACHE
                        .write()
                        .unwrap()
                        .try_get_or_insert(file_name.to_string(), || {
                            match Self::validate_data(&data) {
                                true => Ok(hash.clone()),
                                false => Err(()),
                            }
                        }) {
                        Ok(cached_hash) => cached_hash == &hash,
                        Err(_) => false,
                    } {
                        return (Some(data), content.len(), encoded_size);
                    }
                } else {
                    eprintln!("{}", data.err().unwrap());
                }
            }
        }

        (None, 0, 0)
    }

    pub fn validate_data(data: &BitVMClientPublicData) -> bool {
        println!(
            "Validating {} PEG-IN graphs and {} PEG-OUT graphs...",
            data.peg_in_graphs.len(),
            data.peg_out_graphs.len()
        );
        for peg_in_graph in data.peg_in_graphs.iter() {
            if !peg_in_graph.validate() {
                println!(
                    "Encountered invalid peg-in graph (graph ID: {})",
                    peg_in_graph.id()
                );
                return false;
            }
        }
        for peg_out_graph in data.peg_out_graphs.iter() {
            if !peg_out_graph.validate() {
                println!(
                    "Encountered invalid peg-out graph (graph ID: {})",
                    peg_out_graph.id()
                );
                return false;
            }
        }

        // println!("All graph data is valid");
        true
    }

    /// Merges `data` into `self.data`.
    ///
    /// # Arguments
    ///
    /// * `data` - Must be valid data verified via `BitVMClient::validate_data()` function
    pub fn merge_data(&mut self, data: BitVMClientPublicData) {
        // peg-in graphs
        let mut peg_in_graphs_by_id: HashMap<String, &mut PegInGraph> = HashMap::new();
        for peg_in_graph in self.data.peg_in_graphs.iter_mut() {
            peg_in_graphs_by_id.insert(peg_in_graph.id().clone(), peg_in_graph);
        }

        let mut peg_in_graphs_to_add: Vec<&PegInGraph> = Vec::new();
        for peg_in_graph in data.peg_in_graphs.iter() {
            let graph = peg_in_graphs_by_id.get_mut(peg_in_graph.id());
            if let Some(graph) = graph {
                graph.merge(peg_in_graph);
            } else {
                peg_in_graphs_to_add.push(peg_in_graph);
            }
        }

        for graph in peg_in_graphs_to_add.into_iter() {
            self.data.peg_in_graphs.push(graph.clone());
        }

        // peg-out graphs
        let mut peg_out_graphs_by_id: HashMap<String, &mut PegOutGraph> = HashMap::new();
        for peg_out_graph in self.data.peg_out_graphs.iter_mut() {
            let id = peg_out_graph.id().clone();
            peg_out_graphs_by_id.insert(id, peg_out_graph);
        }

        let mut peg_out_graphs_to_add: Vec<&PegOutGraph> = Vec::new();
        for peg_out_graph in data.peg_out_graphs.iter() {
            let graph = peg_out_graphs_by_id.get_mut(peg_out_graph.id());
            if let Some(graph) = graph {
                graph.merge(peg_out_graph);
            } else {
                peg_out_graphs_to_add.push(peg_out_graph);
            }
        }

        for graph in peg_out_graphs_to_add.into_iter() {
            self.data.peg_out_graphs.push(graph.clone());
        }
    }

    // fn process(&self) {
    //     for peg_in_graph in self.data.peg_in_graphs.iter() {
    //         // match graph.get(outpoint) {
    //         //     Some(subsequent_txs) => {
    //         //         for bridge_transaction in subsequent_txs {
    //         //             // TODO: Check whether the transaction is executable
    //         //             let tx = bridge_transaction.finalize();
    //         //             match self.esplora.broadcast(&tx).await {
    //         //                 Ok(_) => {
    //         //                     println!(
    //         //                         "Succesfully broadcast next transaction with id: {}",
    //         //                         tx.compute_txid()
    //         //                     );
    //         //                     remove_utxo = Some(*outpoint);
    //         //                     break;
    //         //                 }
    //         //                 Err(err) => panic!("Tx Broadcast Error: {}", err),
    //         //             }
    //         //         }
    //         //     }
    //         //     None => continue,
    //         // }
    //     }
    // }

    pub async fn status(&self) {
        if self.depositor_context.is_some() {
            self.depositor_status().await;
        }
        if self.operator_context.is_some() {
            self.operator_status().await;
        }
        if self.verifier_context.is_some() {
            self.verifier_status().await;
        }
    }

    async fn depositor_status(&self) {
        if self.depositor_context.is_none() {
            panic!("Depositor context must be initialized");
        }

        let depositor_public_key = &self
            .depositor_context
            .as_ref()
            .unwrap()
            .depositor_public_key;
        for peg_in_graph in self.data.peg_in_graphs.iter() {
            if peg_in_graph.depositor_public_key.eq(depositor_public_key) {
                let status = peg_in_graph.depositor_status(&self.esplora).await;
                println!(
                    "[DEPOSITOR]: Peg-in graph ID: {} status: {}\n",
                    peg_in_graph.id(),
                    status
                );
            }
        }
    }

    async fn operator_status(&self) {
        if self.operator_context.is_none() {
            panic!("Operator context must be initialized");
        }

        let mut peg_out_graphs_by_id: HashMap<&String, &PegOutGraph> = HashMap::new();
        for peg_out_graph in self.data.peg_out_graphs.iter() {
            peg_out_graphs_by_id.insert(peg_out_graph.id(), peg_out_graph);
        }

        let operator_public_key = &self.operator_context.as_ref().unwrap().operator_public_key;
        for peg_in_graph in self.data.peg_in_graphs.iter() {
            let peg_out_graph_id = peg_out_generate_id(peg_in_graph, operator_public_key);
            if !peg_out_graphs_by_id.contains_key(&peg_out_graph_id) {
                println!(
                    "[OPERATOR]: Peg-in graph ID: {} status: Missing peg out graph.\n",
                    peg_in_graph.id() // TODO update this to ask the operator to create a new peg out graph
                );
            } else {
                let peg_out_graph = peg_out_graphs_by_id.get(&peg_out_graph_id).unwrap();
                let status = peg_out_graph.operator_status(&self.esplora).await;
                println!(
                    "[OPERATOR]: Peg-out graph ID: {} status: {}\n",
                    peg_out_graph.id(),
                    status
                );
            }
        }
    }

    // TODO: refactor, see note on self.process_peg_in_as_verifier
    pub async fn process_peg_in_as_depositor(&mut self, peg_in_graph_id: &GraphId) {
        if self.depositor_context.is_some() {
            if let Ok(peg_in_graph) = self.get_peg_in_graph(peg_in_graph_id) {
                let status = peg_in_graph.depositor_status(&self.esplora).await;
                match status {
                    PegInDepositorStatus::PegInDepositWait => {
                        let _ = self.broadcast_peg_in_deposit(peg_in_graph_id).await;
                    }
                    PegInDepositorStatus::PegInConfirmWait => {
                        let _ = self.broadcast_peg_in_confirm(peg_in_graph_id).await;
                    }
                    _ => {
                        println!("Peg-in graph {} is in status: {}", peg_in_graph_id, status);
                    }
                }
            }
        }
    }

    // TODO: refactor series of method e.g. process_*_as_* to return Result in order to properly handle internal errors
    pub async fn process_peg_in_as_verifier(&mut self, peg_in_graph_id: &GraphId) {
        if let Some(ref context) = self.verifier_context {
            if let Ok(peg_in_graph) = self.get_peg_in_graph(peg_in_graph_id) {
                let peg_outs_for_this_peg_in = self
                    .data
                    .peg_out_graphs
                    .iter()
                    .filter(|peg_out| peg_in_graph.peg_out_graphs.contains(peg_out.id()))
                    .collect::<Vec<_>>();
                let status = peg_in_graph
                    .verifier_status(&self.esplora, context, &peg_outs_for_this_peg_in)
                    .await;
                match status {
                    PegInVerifierStatus::PendingOurNonces(graph_ids) => {
                        println!("Pushing nonces for graphs {graph_ids:?}");
                        for graph_id in graph_ids {
                            self.push_verifier_nonces(&graph_id);
                        }
                    }
                    PegInVerifierStatus::PendingOurSignature(graph_ids) => {
                        println!("Pushing signature for graphs {graph_ids:?}");
                        for graph_id in graph_ids {
                            self.push_verifier_signature(&graph_id);
                        }
                    }
                    PegInVerifierStatus::ReadyToSubmit => {
                        println!("Broadcasting peg-in confirm");
                        let _ = self.broadcast_peg_in_confirm(peg_in_graph_id).await;
                    }
                    _ => {
                        // nothing to do
                    }
                }
            }
        }
    }

    // TODO: refactor, see note on self.process_peg_in_as_verifier
    pub async fn process_peg_in_as_operator(&mut self, peg_in_graph_id: &GraphId) {
        if let Some(ref context) = self.operator_context {
            if let Ok(peg_in_graph) = self.get_peg_in_graph(peg_in_graph_id) {
                let peg_out_graph_id =
                    peg_out_generate_id(peg_in_graph, &context.operator_public_key);
                if !peg_in_graph
                    .peg_out_graphs
                    .iter()
                    .any(|x| x == &peg_out_graph_id)
                {
                    let deposit_amount =
                        peg_in_graph.peg_in_deposit_transaction.tx().output[0].value;
                    let reward_amount = deposit_amount * REWARD_MULTIPLIER / REWARD_PRECISION;
                    let expected_peg_out_confirm_amount = reward_amount.to_sat() + PEG_OUT_FEE;
                    let input = {
                        // todo: don't use a random address
                        let address = generate_pay_to_pubkey_script_address(
                            context.network,
                            &context.operator_public_key,
                        );
                        let utxos = self
                            .esplora
                            .get_address_utxo(address.clone())
                            .await
                            .unwrap();
                        let utxo = utxos
                            .into_iter()
                            .find(|x| x.value.to_sat() >= expected_peg_out_confirm_amount)
                            .unwrap_or_else(|| {
                                panic!("No utxo found with at least {expected_peg_out_confirm_amount} sats for address {address}")
                            });
                        Input {
                            amount: utxo.value,
                            outpoint: OutPoint {
                                txid: utxo.txid,
                                vout: utxo.vout,
                            },
                        }
                    };
                    self.create_peg_out_graph(
                        peg_in_graph_id,
                        input,
                        CommitmentMessageId::generate_commitment_secrets(),
                    );
                }
            }
        }
    }

    pub async fn process_peg_ins(&mut self) {
        for peg_in_graph in self.data.peg_in_graphs.clone() {
            self.process_peg_in_as_depositor(peg_in_graph.id()).await;
            self.process_peg_in_as_verifier(peg_in_graph.id()).await;
            self.process_peg_in_as_operator(peg_in_graph.id()).await;
        }
    }

    // TODO: handle internal errors
    pub async fn process_peg_outs(&mut self) {
        let peg_out_graphs = self.data().peg_out_graphs.clone();
        for peg_out_graph in peg_out_graphs.iter() {
            let status = peg_out_graph.operator_status(&self.esplora).await;
            match status {
                PegOutOperatorStatus::PegOutStartTimeAvailable => {
                    let _ = self.broadcast_start_time(peg_out_graph.id()).await;
                }
                PegOutOperatorStatus::PegOutPegOutConfirmAvailable => {
                    let _ = self.broadcast_peg_out_confirm(peg_out_graph.id()).await;
                }
                PegOutOperatorStatus::PegOutKickOff1Available => {
                    let _ = self.broadcast_kick_off_1(peg_out_graph.id()).await;
                }
                PegOutOperatorStatus::PegOutKickOff2Available => {
                    let _ = self.broadcast_kick_off_2(peg_out_graph.id()).await;
                }
                PegOutOperatorStatus::PegOutAssertInitialAvailable => {
                    let _ = self.broadcast_assert_initial(peg_out_graph.id()).await;
                }
                PegOutOperatorStatus::PegOutAssertCommit1Available => {
                    let _ = self
                        .broadcast_assert_commit_1(peg_out_graph.id(), &get_proof())
                        .await;
                }
                PegOutOperatorStatus::PegOutAssertCommit2Available => {
                    let _ = self
                        .broadcast_assert_commit_2(peg_out_graph.id(), &get_proof())
                        .await;
                }
                PegOutOperatorStatus::PegOutAssertFinalAvailable => {
                    let _ = self.broadcast_assert_final(peg_out_graph.id()).await;
                }
                PegOutOperatorStatus::PegOutTake1Available => {
                    let _ = self.broadcast_take_1(peg_out_graph.id()).await;
                }
                PegOutOperatorStatus::PegOutTake2Available => {
                    let _ = self.broadcast_take_2(peg_out_graph.id()).await;
                }
                _ => {}
            }
        }
    }

    async fn verifier_status(&self) {
        if self.verifier_context.is_none() {
            panic!("Verifier context must be initialized");
        }

        for peg_in_graph in self.data.peg_in_graphs.iter() {
            let peg_outs = peg_in_graph
                .peg_out_graphs
                .iter()
                .map(|peg_out_id| {
                    self.data
                        .peg_out_graphs
                        .iter()
                        .find(|x| x.id() == peg_out_id)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let peg_in_status = peg_in_graph
                .verifier_status(
                    &self.esplora,
                    self.verifier_context.as_ref().unwrap(),
                    &peg_outs,
                )
                .await;

            if peg_in_status == PegInVerifierStatus::Complete {
                for peg_out_graph in peg_outs {
                    let peg_out_status = peg_out_graph
                        .verifier_status(&self.esplora, self.verifier_context.as_ref().unwrap())
                        .await;
                    println!(
                        "[VERIFIER]: Peg-out graph ID: {} status: {}\n",
                        peg_out_graph.id(),
                        peg_out_status
                    );
                }
            }
            println!(
                "[VERIFIER]: Peg-in graph ID: {} status: {}\n",
                peg_in_graph.id(),
                peg_in_status
            );
        }
    }

    pub async fn create_peg_in_graph(&mut self, input: Input, evm_address: &str) -> String {
        if self.depositor_context.is_none() {
            panic!("Depositor context must be initialized");
        }

        let peg_in_graph =
            PegInGraph::new(self.depositor_context.as_ref().unwrap(), input, evm_address);

        let peg_in_graph_id = peg_in_generate_id(&peg_in_graph.peg_in_deposit_transaction);

        let graph = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_out_graph| peg_out_graph.id().eq(&peg_in_graph_id));
        if graph.is_some() {
            panic!("Peg in graph already exists");
        }

        self.data.peg_in_graphs.push(peg_in_graph);

        peg_in_graph_id
    }

    pub async fn broadcast_peg_in_deposit(
        &mut self,
        peg_in_graph_id: &String,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_in_or_fail(&mut self.data, peg_in_graph_id)?;
        let tx = graph.deposit(&self.esplora).await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_peg_in_refund(
        &mut self,
        peg_in_graph_id: &String,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_in_or_fail(&mut self.data, peg_in_graph_id)?;
        let tx = graph.refund(&self.esplora).await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_peg_in_confirm(
        &mut self,
        peg_in_graph_id: &String,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_in_or_fail(&mut self.data, peg_in_graph_id)?;
        let tx = graph.confirm(&self.esplora).await?;
        self.broadcast_tx(&tx).await
    }

    pub fn create_peg_out_graph(
        &mut self,
        peg_in_graph_id: &str,
        peg_out_confirm_input: Input,
        commitment_secrets: HashMap<CommitmentMessageId, WinternitzSecret>,
    ) -> String {
        if self.operator_context.is_none() {
            panic!("Operator context must be initialized");
        }
        let operator_public_key = &self.operator_context.as_ref().unwrap().operator_public_key;

        let peg_in_graph = self
            .data
            .peg_in_graphs
            .iter_mut()
            .find(|peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id))
            .unwrap_or_else(|| panic!("Invalid graph ID"));

        let peg_out_graph_id = peg_out_generate_id(peg_in_graph, operator_public_key);
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter()
            .find(|&peg_out_graph| peg_out_graph.id().eq(&peg_out_graph_id));
        if peg_out_graph.is_some() {
            panic!("Peg out graph already exists");
        }

        let peg_out_graph = PegOutGraph::new(
            self.operator_context.as_ref().unwrap(),
            peg_in_graph,
            peg_out_confirm_input,
            &commitment_secrets,
        );

        self.data.peg_out_graphs.push(peg_out_graph);
        peg_in_graph.peg_out_graphs.push(peg_out_graph_id.clone());

        self.private_data.commitment_secrets = HashMap::from([(
            *operator_public_key,
            HashMap::from([(peg_out_graph_id.to_string(), commitment_secrets)]),
        )]);
        self.save_private_data();

        peg_out_graph_id
    }

    pub async fn broadcast_peg_out(
        &mut self,
        peg_out_graph_id: &String,
        input: Input,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        if self.operator_context.is_some() {
            let tx = graph
                .peg_out(
                    &self.esplora,
                    self.operator_context.as_ref().unwrap(),
                    input,
                )
                .await?;
            self.broadcast_tx(&tx).await
        } else {
            Err(Error::Client(ClientError::OperatorContextNotDefined))
        }
    }

    pub async fn broadcast_peg_out_confirm(
        &mut self,
        peg_out_graph_id: &String,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph.peg_out_confirm(&self.esplora).await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_kick_off_1(&mut self, peg_out_graph_id: &String) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;

        if self.operator_context.is_some() {
            let tx = graph
                .kick_off_1(
                    &self.esplora,
                    self.operator_context.as_ref().unwrap(),
                    &self.private_data.commitment_secrets
                        [&self.operator_context.as_ref().unwrap().operator_public_key]
                        [peg_out_graph_id][&CommitmentMessageId::PegOutTxIdSourceNetwork],
                    &self.private_data.commitment_secrets
                        [&self.operator_context.as_ref().unwrap().operator_public_key]
                        [peg_out_graph_id][&CommitmentMessageId::PegOutTxIdDestinationNetwork],
                )
                .await?;
            self.broadcast_tx(&tx).await
        } else {
            Err(Error::Client(ClientError::OperatorContextNotDefined))
        }
    }

    pub async fn broadcast_start_time(&mut self, peg_out_graph_id: &String) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;

        if self.operator_context.is_some() {
            let tx = graph
                .start_time(
                    &self.esplora,
                    self.operator_context.as_ref().unwrap(),
                    &self.private_data.commitment_secrets
                        [&self.operator_context.as_ref().unwrap().operator_public_key]
                        [peg_out_graph_id][&CommitmentMessageId::StartTime],
                )
                .await?;
            self.broadcast_tx(&tx).await
        } else {
            Err(Error::Client(ClientError::OperatorContextNotDefined))
        }
    }

    pub async fn broadcast_start_time_timeout(
        &mut self,
        peg_out_graph_id: &String,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph
            .start_time_timeout(&self.esplora, output_script_pubkey)
            .await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_kick_off_2(&mut self, peg_out_graph_id: &String) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph
            .kick_off_2(
                &self.esplora,
                self.operator_context.as_ref().unwrap(),
                &self.private_data.commitment_secrets
                    [&self.operator_context.as_ref().unwrap().operator_public_key]
                    [peg_out_graph_id][&CommitmentMessageId::Superblock],
                &self.private_data.commitment_secrets
                    [&self.operator_context.as_ref().unwrap().operator_public_key]
                    [peg_out_graph_id][&CommitmentMessageId::SuperblockHash],
            )
            .await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_kick_off_timeout(
        &mut self,
        peg_out_graph_id: &String,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph
            .kick_off_timeout(&self.esplora, output_script_pubkey)
            .await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_challenge(
        &mut self,
        peg_out_graph_id: &String,
        crowdfundng_inputs: &Vec<InputWithScript<'_>>,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;

        if self.depositor_context.is_some() {
            let tx = graph
                .challenge(
                    &self.esplora,
                    crowdfundng_inputs,
                    &self.depositor_context.as_ref().unwrap().depositor_keypair,
                    output_script_pubkey,
                )
                .await?;
            self.broadcast_tx(&tx).await
        } else if self.operator_context.is_some() {
            let tx = graph
                .challenge(
                    &self.esplora,
                    crowdfundng_inputs,
                    &self.operator_context.as_ref().unwrap().operator_keypair,
                    output_script_pubkey,
                )
                .await?;
            self.broadcast_tx(&tx).await
        } else if self.verifier_context.is_some() {
            let tx = graph
                .challenge(
                    &self.esplora,
                    crowdfundng_inputs,
                    &self.verifier_context.as_ref().unwrap().verifier_keypair,
                    output_script_pubkey,
                )
                .await?;
            self.broadcast_tx(&tx).await
        } else if self.withdrawer_context.is_some() {
            let tx = graph
                .challenge(
                    &self.esplora,
                    crowdfundng_inputs,
                    &self.withdrawer_context.as_ref().unwrap().withdrawer_keypair,
                    output_script_pubkey,
                )
                .await?;
            self.broadcast_tx(&tx).await
        } else {
            Err(Error::Client(ClientError::NoUserContextDefined))
        }
    }

    pub async fn broadcast_assert_initial(
        &mut self,
        peg_out_graph_id: &String,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph.assert_initial(&self.esplora).await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_assert_commit_1(
        &mut self,
        peg_out_graph_id: &String,
        proof: &RawProof,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph
            .assert_commit_1(
                &self.esplora,
                &self.private_data.commitment_secrets
                    [&self.operator_context.as_ref().unwrap().operator_public_key]
                    [peg_out_graph_id],
                proof,
            )
            .await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_assert_commit_2(
        &mut self,
        peg_out_graph_id: &String,
        proof: &RawProof,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph
            .assert_commit_2(
                &self.esplora,
                &self.private_data.commitment_secrets
                    [&self.operator_context.as_ref().unwrap().operator_public_key]
                    [peg_out_graph_id],
                proof,
            )
            .await?;
        self.broadcast_tx(&tx).await
    }

    // use this when possible
    // broadcast assert commits together to save groth16 verifying time
    pub async fn broadcast_assert_commits(
        &mut self,
        peg_out_graph_id: &String,
        proof: &RawProof,
    ) -> Result<(Txid, Txid), Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let (commit1_tx, commit2_tx) = graph
            .assert_commits(
                &self.esplora,
                &self.private_data.commitment_secrets
                    [&self.operator_context.as_ref().unwrap().operator_public_key]
                    [peg_out_graph_id],
                proof,
            )
            .await?;
        Ok((
            self.broadcast_tx(&commit1_tx).await?,
            self.broadcast_tx(&commit2_tx).await?,
        ))
    }

    pub async fn broadcast_assert_final(
        &mut self,
        peg_out_graph_id: &String,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph.assert_final(&self.esplora).await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_disprove(
        &mut self,
        peg_out_graph_id: &String,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph
            .disprove(
                &self.esplora,
                output_script_pubkey,
                self.zkproof_verifying_key
                    .as_ref()
                    .ok_or(Error::Client(ClientError::ZkProofVerifyingKeyNotDefined))?,
            )
            .await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_disprove_chain(
        &mut self,
        peg_out_graph_id: &String,
        output_script_pubkey: ScriptBuf,
    ) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph
            .disprove_chain(&self.esplora, output_script_pubkey)
            .await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_take_1(&mut self, peg_out_graph_id: &String) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph.take_1(&self.esplora).await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn broadcast_take_2(&mut self, peg_out_graph_id: &String) -> Result<Txid, Error> {
        let graph = Self::find_peg_out_or_fail(&mut self.data, peg_out_graph_id)?;
        let tx = graph
            .take_2(&self.esplora, self.operator_context.as_ref().unwrap())
            .await?;
        self.broadcast_tx(&tx).await
    }

    pub async fn get_initial_utxo(&self, address: Address, amount: Amount) -> Option<Utxo> {
        let utxos = self.esplora.get_address_utxo(address).await.unwrap();

        let possible_utxos = utxos
            .into_iter()
            .filter(|utxo| utxo.value == amount)
            .collect::<Vec<_>>();
        if !possible_utxos.is_empty() {
            Some(possible_utxos[0].clone())
        } else {
            None
        }
    }

    pub async fn get_initial_utxos(&self, address: Address, amount: Amount) -> Option<Vec<Utxo>> {
        let utxos: Vec<Utxo> = self.esplora.get_address_utxo(address).await.unwrap();
        let possible_utxos = utxos
            .into_iter()
            .filter(|utxo| utxo.value == amount)
            .collect::<Vec<_>>();
        if !possible_utxos.is_empty() {
            Some(possible_utxos)
        } else {
            None
        }
    }

    pub fn get_operator_address(&self) -> Address {
        if let Some(ref context) = self.operator_context {
            generate_pay_to_pubkey_script_address(context.network, &context.operator_public_key)
        } else {
            panic!("Operator private key not provided in configuration.");
        }
    }

    pub async fn get_operator_utxos(&self) -> Vec<Utxo> {
        self.esplora
            .get_address_utxo(self.get_operator_address())
            .await
            .unwrap()
    }

    pub fn get_depositor_address(&self) -> Address {
        if let Some(ref context) = self.depositor_context {
            generate_pay_to_pubkey_script_address(context.network, &context.depositor_public_key)
        } else {
            panic!("Depositor private key not provided in configuration.");
        }
    }

    pub async fn get_depositor_utxos(&self) -> Vec<Utxo> {
        self.esplora
            .get_address_utxo(self.get_depositor_address())
            .await
            .unwrap()
    }

    pub fn push_verifier_nonces(&mut self, graph_id: &GraphId) {
        if self.verifier_context.is_none() {
            panic!("Can only be called by a verifier!");
        }

        let graph = self.data.graph_mut(graph_id);
        let secret_nonces = graph.push_verifier_nonces(self.verifier_context.as_ref().unwrap());
        self.merge_secret_nonces(graph_id, secret_nonces);
        self.save_private_data();
    }

    fn get_peg_in_graph(&self, peg_in_graph_id: &String) -> Result<&PegInGraph, Error> {
        self.data
            .peg_in_graphs
            .iter()
            .find(|peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id))
            .ok_or(Error::Client(ClientError::PegInGraphNotFound(
                peg_in_graph_id.clone(),
            )))
    }

    // TODO: consider refactor client as static, and use it in graph struct directly
    //       so we can have this method instead of find_peg_in_or_fail
    // fn get_peg_in_graph_mut(&mut self, peg_in_graph_id: &String) -> Result<&mut PegInGraph, Error> {
    //     self.data_mut_ref()
    //         .peg_in_graphs
    //         .iter_mut()
    //         .find(|peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id))
    //         .ok_or(Error::Client(ClientError::PegInGraphNotFound(
    //             peg_in_graph_id.clone(),
    //         )))
    // }

    fn find_peg_in_or_fail<'a>(
        data: &'a mut BitVMClientPublicData,
        peg_in_graph_id: &'a String,
    ) -> Result<&'a mut PegInGraph, Error> {
        if let Some(graph) = data
            .peg_in_graphs
            .iter_mut()
            .find(|peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id))
        {
            Ok(graph)
        } else {
            Err(Error::Client(ClientError::PegInGraphNotFound(
                peg_in_graph_id.clone(),
            )))
        }
    }

    fn find_peg_out_or_fail<'a>(
        data: &'a mut BitVMClientPublicData,
        peg_out_graph_id: &'a String,
    ) -> Result<&'a mut PegOutGraph, Error> {
        if let Some(graph) = data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id))
        {
            Ok(graph)
        } else {
            Err(Error::Client(ClientError::PegOutGraphNotFound(
                peg_out_graph_id.clone(),
            )))
        }
    }

    async fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid, Error> {
        let status_message = broadcast_and_verify(&self.esplora, tx).await?;

        let txid = tx.compute_txid();
        println!("{} Txid: {}", status_message, txid.to_string().green());

        Ok(txid)
    }

    fn merge_secret_nonces(
        &mut self,
        graph_id: &str,
        secret_nonces: HashMap<Txid, HashMap<usize, SecNonce>>,
    ) {
        self.private_data
            .secret_nonces
            .entry(self.verifier_context.as_ref().unwrap().verifier_public_key)
            .or_default();

        if !self.private_data.secret_nonces
            [&self.verifier_context.as_ref().unwrap().verifier_public_key]
            .contains_key(graph_id)
        {
            self.private_data
                .secret_nonces
                .get_mut(&self.verifier_context.as_ref().unwrap().verifier_public_key)
                .unwrap()
                .insert(graph_id.to_string(), HashMap::new());
        }

        self.private_data
            .secret_nonces
            .get_mut(&self.verifier_context.as_ref().unwrap().verifier_public_key)
            .unwrap()
            .get_mut(graph_id)
            .unwrap()
            .extend(secret_nonces);
    }

    pub fn generate_connector_z_taproot_address(
        &self,
        source_network: Network,
        recipient_address: &str,
        depositor_taproot_key: &XOnlyPublicKey,
    ) -> Address {
        let connector_z = ConnectorZ::new(
            source_network,
            recipient_address,
            depositor_taproot_key,
            &self
                .operator_context
                .as_ref()
                .unwrap()
                .n_of_n_taproot_public_key,
        );
        connector_z.generate_taproot_address()
    }

    pub fn generate_presign_pegin_confirm_tx(
        &self,
        source_network: Network,
        recipient_address: &str,
        amount: Amount,
        depositor_taproot_key: &XOnlyPublicKey,
        outpoint: OutPoint,
    ) -> String {
        let connector_z = ConnectorZ::new(
            source_network,
            recipient_address,
            depositor_taproot_key,
            &self
                .operator_context
                .as_ref()
                .unwrap()
                .n_of_n_taproot_public_key,
        );
        let connector_0 = Connector0::new(
            source_network,
            &self
                .operator_context
                .as_ref()
                .unwrap()
                .n_of_n_taproot_public_key,
        );
        let mut peg_in_confirm_tx = PegInConfirmTransaction::new_for_validation(
            &connector_0,
            &connector_z,
            Input { outpoint, amount },
            self.operator_context
                .as_ref()
                .unwrap()
                .n_of_n_public_keys
                .clone(),
        );
        let secret_nonces_0 =
            peg_in_confirm_tx.push_nonces(self.verifier_context.as_ref().unwrap());

        peg_in_confirm_tx.pre_sign(
            self.verifier_context.as_ref().unwrap(),
            &connector_z,
            &secret_nonces_0,
        );
        serialize_hex(&(peg_in_confirm_tx.tx_mut()))
    }

    pub fn generate_presign_pegin_deposit_tx(
        &self,
        source_network: Network,
        amount: Amount,
        recipient_address: &str,
        depositor_public_key: &PublicKey,
        outpoint: OutPoint,
    ) -> String {
        let depositor_taproot_key = XOnlyPublicKey::from(*depositor_public_key);
        let connector_z = ConnectorZ::new(
            source_network,
            recipient_address,
            &depositor_taproot_key,
            &self
                .operator_context
                .as_ref()
                .unwrap()
                .n_of_n_taproot_public_key,
        );
        let mut peg_in_deposit_tx = PegInDepositTransaction::new_for_validation(
            source_network,
            depositor_public_key,
            &connector_z,
            Input { outpoint, amount },
        );
        serialize_hex(&(peg_in_deposit_tx.tx_mut()))
    }

    pub fn generate_presign_pegin_refund_tx(
        &self,
        source_network: Network,
        amount: Amount,
        recipient_address: &str,
        depositor_public_key: &PublicKey,
        outpoint: OutPoint,
    ) -> String {
        let depositor_taproot_key: XOnlyPublicKey = XOnlyPublicKey::from(*depositor_public_key);
        let connector_z = ConnectorZ::new(
            source_network,
            recipient_address,
            &depositor_taproot_key,
            &self
                .operator_context
                .as_ref()
                .unwrap()
                .n_of_n_taproot_public_key,
        );
        let mut peg_in_refund_tx = PegInRefundTransaction::new_for_validation(
            source_network,
            depositor_public_key,
            &connector_z,
            Input { outpoint, amount },
        );
        serialize_hex(&(peg_in_refund_tx.tx_mut()))
    }

    pub fn push_verifier_signature(&mut self, graph_id: &GraphId) {
        let verifier = self
            .verifier_context
            .as_ref()
            .expect("Can only be called by a verifier!");

        let graph = self.data.graph_mut(graph_id);
        graph.verifier_sign(
            verifier,
            &self.private_data.secret_nonces
                [&self.verifier_context.as_ref().unwrap().verifier_public_key][graph_id],
        );
    }

    // pub async fn execute_possible_txs(
    //     &mut self,
    //     context: &dyn BaseContext,
    //     graph: &mut CompiledBitVMGraph,
    // ) {
    //     // Iterate through our UTXO set and execute an executable TX
    //     // TODO: May have to respect an order here.
    //     let mut remove_utxo = None;
    //     for (outpoint, _) in self.utxo_set.iter() {
    //         match graph.get(outpoint) {
    //             Some(subsequent_txs) => {
    //                 for bridge_transaction in subsequent_txs {
    //                     // TODO: Check whether the transaction is executable
    //                     let tx = bridge_transaction.finalize();
    //                     match self.esplora.broadcast(&tx).await {
    //                         Ok(_) => {
    //                             println!(
    //                                 "Succesfully broadcast next transaction with id: {}",
    //                                 tx.compute_txid()
    //                             );
    //                             remove_utxo = Some(*outpoint);
    //                             break;
    //                         }
    //                         Err(err) => panic!("Tx Broadcast Error: {}", err),
    //                     }
    //                 }
    //             }
    //             None => continue,
    //         }
    //     }

    //     if let Some(remove_utxo) = remove_utxo {
    //         self.utxo_set.remove(&remove_utxo);
    //         graph.remove(&remove_utxo);
    //     }
    // }

    // pub async fn listen(
    //     &mut self,
    //     context: &dyn BaseContext,
    //     initial_outpoint: OutPoint,
    //     graph: &mut CompiledBitVMGraph,
    // ) {
    //     let builder = Builder::new(ESPLORA_URL);
    //     let esplora = builder.build_async().unwrap();
    //     let mut latest_hash =
    //         BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
    //             .unwrap();
    //     self.utxo_set.insert(initial_outpoint, Height::ZERO);

    //     while !graph.is_empty() {
    //         if let Ok(block_hash) = esplora.get_tip_hash().await {
    //             if block_hash == latest_hash {
    //                 sleep(Duration::from_secs(10));
    //                 continue;
    //             }
    //             latest_hash = block_hash;
    //             // TODO: This assumes that the tip did not increase. There should be a
    //             // better API endpoint like /block-height/{block_hash}
    //             let block_height = esplora.get_height().await.unwrap();
    //             let block = esplora
    //                 .get_block_by_hash(&block_hash)
    //                 .await
    //                 .unwrap()
    //                 .unwrap();

    //             // Handle new block received logic
    //             println!("Received block {}", block_hash);

    //             for tx in block.txdata {
    //                 for (vout, _) in tx.output.iter().enumerate() {
    //                     let outpoint = OutPoint {
    //                         txid: tx.compute_txid(),
    //                         vout: vout as u32,
    //                     };
    //                     if graph.contains_key(&outpoint) {
    //                         // Update our UTXO set
    //                         self.utxo_set
    //                             .insert(outpoint, Height::from_consensus(block_height).unwrap());
    //                     }
    //                 }
    //             }
    //             self.execute_possible_txs(context, graph).await;
    //         }
    //     }
    // }
}

impl ClientCliQuery for BitVMClient {
    async fn get_unused_peg_in_graphs(&self) -> Vec<Value> {
        join_all(self.data.peg_in_graphs.iter().filter_map(|peg_in| {
            Some(async move {
                match peg_in.depositor_status(&self.esplora).await {
                    PegInDepositorStatus::PegInConfirmComplete => match self.data.peg_out_graphs.iter().find(|peg_out| peg_out.peg_in_graph_id == *peg_in.id()) {
                        Some(peg_out) => match peg_out.operator_status(&self.esplora).await {
                            PegOutOperatorStatus::PegOutWait => Some(json!({
                                "graph_id": peg_in.id(),
                                "amount": peg_in.peg_in_confirm_transaction.prev_outs()[0].value.to_sat(),
                                "source_outpoint": {
                                    "txid": peg_in.peg_in_confirm_transaction.tx().compute_txid(),
                                    "vout": 0
                                },
                            })),
                            _ => None,
                        },
                        None => None,
                    },
                    _ => None,
                }
            })
        }))
        .await
        .iter()
        .filter_map(|v| {
            v.clone()
        })
        .collect()
    }

    async fn get_depositor_status(&self, depositor_public_key: &PublicKey) -> Vec<Value> {
        join_all(
            self.data
                .peg_in_graphs
                .iter()
                .filter(|&graph| graph.depositor_public_key.eq(depositor_public_key))
                .map(|graph| async {
                    let tx_ids = vec![
                        graph.peg_in_deposit_transaction.tx().compute_txid(),
                        graph.peg_in_confirm_transaction.tx().compute_txid(),
                        graph.peg_in_refund_transaction.tx().compute_txid(),
                    ];
                    let tx_statuses_results = get_tx_statuses(&self.esplora, &tx_ids).await;
                    let blockchain_height = self.esplora.get_height().await;
                    let status = graph.interpret_depositor_status(
                        &tx_statuses_results[0],
                        &tx_statuses_results[1],
                        &tx_statuses_results[2],
                        blockchain_height,
                    );

                    let tx_statuses = tx_statuses_results
                        .iter()
                        .map(|tx_status| {
                            tx_status.as_ref().unwrap_or(&TxStatus {
                                confirmed: false,
                                block_height: None,
                                block_hash: None,
                                block_time: None,
                            })
                        })
                        .collect::<Vec<_>>();
                    let tx_json_values = tx_statuses
                        .iter()
                        .enumerate()
                        .map(|(i, tx_status)| {
                            json!({
                            "type": match i {
                                0 => "peg_in_deposit",
                                1 => "peg_in_confirm",
                                2 => "peg_in_refund",
                                _ => unreachable!(),
                            },
                            "txid": tx_ids[i],
                            "status": {
                                "confirmed": tx_status.confirmed,
                                "block_height": tx_status.block_height.unwrap_or(0),
                                "block_hash": tx_status.block_hash.or(None),
                                "block_time": tx_status.block_time.unwrap_or(0),
                            }})
                        })
                        .collect::<Vec<_>>();

                    json!({
                        "type": "peg_in",
                        "graph_id": graph.id(),
                        "status": status.to_string(),
                        "amount": graph.peg_in_deposit_transaction.prev_outs()[0].value.to_sat(),
                        "destination_address": graph.depositor_evm_address,
                        "txs" : tx_json_values,
                    })
                }),
        )
        .await
    }

    async fn get_withdrawer_status(&self, withdrawer_chain_address: &str) -> Vec<Value> {
        join_all(
            self.data
                .peg_out_graphs
                .iter()
                .filter(|&graph| {
                    if graph.peg_out_chain_event.is_some() {
                        return graph
                            .peg_out_chain_event
                            .as_ref()
                            .unwrap()
                            .withdrawer_chain_address
                            .eq(withdrawer_chain_address);
                    }
                    false
                })
                .map(|graph| async {
                    let (tx_json_value, tx_status_result) = match &graph.peg_out_transaction {
                        Some(tx) => {
                            let txid = tx.tx().compute_txid();
                            let tx_status_result = self.esplora.get_tx_status(&txid).await;
                            let tx_status = tx_status_result.as_ref().unwrap_or(&TxStatus {
                                confirmed: false,
                                block_height: None,
                                block_hash: None,
                                block_time: None,
                            });
                            let tx_json_value = json!({
                                "type": "peg_out",
                                "txid": txid,
                                "status": {
                                    "confirmed": tx_status.confirmed,
                                    "block_height": tx_status.block_height.unwrap_or(0),
                                    "block_hash": tx_status.block_hash.or(None),
                                    "block_time": tx_status.block_time.unwrap_or(0),
                                }
                            });

                            (Some(tx_json_value), Some(tx_status_result))
                        }
                        None => (Some(json!([])), None),
                    };
                    let (peg_out_amount, destination_address) = match &graph.peg_out_chain_event {
                        Some(peg_out_chain_event) => (
                            peg_out_chain_event.amount.to_sat(),
                            peg_out_chain_event.withdrawer_destination_address.clone(),
                        ),
                        None => (0, "".to_string()),
                    };

                    let status = graph.interpret_withdrawer_status(tx_status_result.as_ref());
                    json!({
                        "type": "peg_out",
                        "graph_id": graph.id(),
                        "status": status.to_string(),
                        "amount": peg_out_amount,
                        "destination_address": destination_address,
                        "txs": tx_json_value,
                    })
                }),
        )
        .await
    }

    async fn get_depositor_transactions(
        &self,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        deposit_input: Input,
        depositor_evm_address: &str,
    ) -> Result<Value, String> {
        // depositor context should contain pub key of n_of_n
        if self.depositor_context.is_none() {
            return Err("Depositor context must be initialized".into());
        }

        let n_of_n_public_key = &self.depositor_context.as_ref().unwrap().n_of_n_public_key;
        let n_of_n_taproot_public_key = &self
            .depositor_context
            .as_ref()
            .unwrap()
            .n_of_n_taproot_public_key;
        let n_of_n_public_keys = &self.depositor_context.as_ref().unwrap().n_of_n_public_keys;
        let peg_in_graph = PegInGraph::new_for_query(
            self.depositor_context.as_ref().unwrap().network,
            depositor_public_key,
            depositor_taproot_public_key,
            n_of_n_public_key,
            n_of_n_public_keys,
            n_of_n_taproot_public_key,
            depositor_evm_address,
            deposit_input,
        );

        Ok(json!({
            "deposit": serialize_hex(peg_in_graph.peg_in_deposit_transaction.tx()),
            "confirm": serialize_hex(peg_in_graph.peg_in_confirm_transaction.tx()),
            "refund": serialize_hex(peg_in_graph.peg_in_refund_transaction.tx()),
        }))
    }

    async fn create_peg_in_graph_with_depositor_signatures(
        &mut self,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        deposit_input: Input,
        depositor_evm_address: &str,
        signatures: &DepositorSignatures,
    ) -> Result<Value, String> {
        // depositor context should contain pub key of n_of_n
        if self.depositor_context.is_none() {
            return Err("Depositor context must be initialized".into());
        }

        let n_of_n_public_key = &self.depositor_context.as_ref().unwrap().n_of_n_public_key;
        let n_of_n_public_keys = &self.depositor_context.as_ref().unwrap().n_of_n_public_keys;
        let n_of_n_taproot_public_key = &self
            .depositor_context
            .as_ref()
            .unwrap()
            .n_of_n_taproot_public_key;
        let peg_in_graph = PegInGraph::new_with_depositor_signatures(
            self.depositor_context.as_ref().unwrap().network,
            depositor_public_key,
            depositor_taproot_public_key,
            n_of_n_public_key,
            n_of_n_public_keys,
            n_of_n_taproot_public_key,
            depositor_evm_address,
            deposit_input,
            signatures,
        );

        let peg_in_graph_id = peg_in_generate_id(&peg_in_graph.peg_in_deposit_transaction);

        let graph = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_out_graph| peg_out_graph.id().eq(&peg_in_graph_id));
        if graph.is_some() {
            return Err("Peg in graph already exists".into());
        }

        self.data.peg_in_graphs.push(peg_in_graph.clone());

        match peg_in_graph.broadcast_deposit(&self.esplora).await {
            Ok(_) => Ok(json!({"graph_id": peg_in_graph_id})),
            Err(e) => Err(e),
        }
    }

    async fn retry_broadcast_peg_in_deposit(&self, peg_in_graph_id: &str) -> Result<Value, String> {
        let Some(peg_in_graph) = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id))
        else {
            return Err("Peg in graph not found".into());
        };

        match peg_in_graph.broadcast_deposit(&self.esplora).await {
            Ok(_) => Ok(json!({"graph_id": peg_in_graph_id})),
            Err(e) => Err(e),
        }
    }
}
