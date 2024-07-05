use bitcoin::{taproot::TaprootSpendInfo, Address, ScriptBuf, Sequence, TxIn, Witness};

use super::super::transactions::base::Input;

pub fn generate_default_tx_in(input: &Input) -> TxIn {
    TxIn {
        previous_output: input.outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    }
}

pub trait P2wshConnector {
    fn generate_script(&self) -> ScriptBuf;

    fn generate_address(&self) -> Address;

    fn generate_tx_in(&self, input: &Input) -> TxIn;
}

pub trait TaprootConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf;

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn;

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo;

    fn generate_taproot_address(&self) -> Address;
}
