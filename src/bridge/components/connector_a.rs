use crate::treepp::*;
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, XOnlyPublicKey,
};

use super::helper::*;

// leaf[0]: spendable by operator
pub fn generate_leaf0(operator_pubkey: &XOnlyPublicKey) -> Script {
    generate_pay_to_pubkey_script(operator_pubkey)
}

// leaf[1]: spendable by operator with sighash flag=“Single|AnyoneCanPay”, spendable along with any other inputs such that the output value exceeds V*1%
pub fn generate_leaf1(operator_pubkey: &XOnlyPublicKey) -> Script {
    generate_pay_to_pubkey_script(operator_pubkey)
}

pub fn generate_spend_info(
    operator_pubkey: &XOnlyPublicKey,
    n_of_n_pubkey: &XOnlyPublicKey,
) -> TaprootSpendInfo {
    TaprootBuilder::new()
        .add_leaf(0, generate_leaf0(operator_pubkey))
        .expect("Unable to add leaf0")
        .add_leaf(1, generate_leaf1(operator_pubkey))
        .expect("Unable to add leaf1")
        .finalize(&Secp256k1::new(), *n_of_n_pubkey)
        .expect("Unable to finalize taproot")
}

pub fn generate_address(
    operator_pubkey: &XOnlyPublicKey,
    n_of_n_pubkey: &XOnlyPublicKey,
) -> Address {
    Address::p2tr_tweaked(
        generate_spend_info(operator_pubkey, n_of_n_pubkey).output_key(),
        Network::Testnet,
    )
}
