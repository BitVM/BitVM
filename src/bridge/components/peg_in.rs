use crate::treepp::*;
use bitcoin::{
    absolute,
    Address, Amount, Network, OutPoint, Sequence,
    Transaction, TxIn, TxOut, Witness,
    ScriptBuf, XOnlyPublicKey,
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT, N_OF_N_SECRET};

use super::bridge::*;
use super::connector_a::*;
use super::connector_b::*;
use super::helper::*;

pub struct PegInTransaction {
  tx: Transaction,
  prev_outs: Vec<TxOut>,
}