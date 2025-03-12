use super::commitments::CommitmentMessageId;
use super::graphs::base::GraphId;
use super::transactions::{base::BaseTransaction, pre_signed::PreSignedTransaction};
use bitcoin::{PublicKey, Txid};
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum ClientError {
    NoUserContextDefined,
    OperatorContextNotDefined,
    ZkProofVerifyingKeyNotDefined,
    PegInGraphNotFound(GraphId),
    PegOutGraphNotFound(GraphId),
}

#[derive(Debug)]
pub struct NamedTx {
    pub txid: Txid,
    pub name: &'static str,
    pub confirmed: bool,
}

impl NamedTx {
    pub fn for_tx(tx: &(impl BaseTransaction + PreSignedTransaction), confirmed: bool) -> Self {
        Self {
            txid: tx.tx().compute_txid(),
            name: tx.name(),
            confirmed,
        }
    }
}

#[derive(Debug)]
pub enum GraphError {
    PrecedingTxNotCreated(&'static str),
    PrecedingTxNotConfirmed(Vec<NamedTx>),
    PrecedingTxTimelockNotMet(NamedTx),
    WitnessNotGenerated(CommitmentMessageId),
}

#[derive(Debug)]
pub enum TransactionError {
    AlreadyMined(Txid),
}

#[derive(Debug)]
pub enum L2Error {
    PegOutNotInitiated,
}

#[derive(Debug)]
pub enum ValidationError {
    WitnessMismatch(&'static str, Txid, usize), // str: tx name, txid: the transaction id, usize: tx input index
    TxValidationFailed(&'static str, Txid, usize), // str: tx name, txid: the transaction id, usize: tx input index
    NoncesValidationFailed(&'static str, PublicKey, Txid, usize), // str: tx name, pubkey: the public key, txid: the transaction id, usize: tx input index
}

#[derive(Debug)]
pub enum ChunkerError {
    ValidProof,
}

#[derive(Debug)]
pub enum Error {
    Esplora(esplora_client::Error),
    Client(ClientError),
    Graph(GraphError),
    Transaction(TransactionError),
    L2(L2Error),
    Chunker(ChunkerError),
    Validation(ValidationError),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self) }
}

pub fn err_to_string(err: impl Display) -> String { err.to_string() }
