use bitcoin::Txid;
use std::fmt;

#[derive(Debug)]
pub struct NamedTx {
    pub txid: Txid,
    pub name: &'static str,
}

#[derive(Debug)]
pub enum GraphError {
    PrecedingTxNotCreated(&'static str),
    PrecedingTxNotConfirmed(Vec<NamedTx>),
    PrecedingTxTimelockNotMet(NamedTx),
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
pub enum ChunkerError {
    NotWrongProof,
    InvalidProof,
}

#[derive(Debug)]
pub enum Error {
    Esplora(esplora_client::Error),
    Graph(GraphError),
    Transaction(TransactionError),
    L2(L2Error),
    Chunker(ChunkerError),
    Other(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self) }
}
