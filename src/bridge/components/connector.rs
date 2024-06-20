use crate::treepp::*;
use bitcoin::{
  Sequence, TxIn, Witness
};

use super::helper::Input;

pub fn generate_default_tx_in(input: &Input) -> TxIn {
  TxIn {
    previous_output: input.outpoint,
    script_sig: Script::new(),
    sequence: Sequence::MAX,
    witness: Witness::default(),
  }
}