use crate::treepp::*;
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, XOnlyPublicKey,
};

use super::helper::*;

// leaf[0]: spendable by operator
pub fn generate_taproot_leaf0(operator_public_key: &XOnlyPublicKey) -> Script {
    generate_pay_to_pubkey_taproot_script(operator_public_key)
}

// leaf[1]: spendable by operator with sighash flag=“Single|AnyoneCanPay”, spendable along with any other inputs such that the output value exceeds V*1%
pub fn generate_taproot_leaf1(operator_public_key: &XOnlyPublicKey) -> Script {
    generate_pay_to_pubkey_taproot_script(operator_public_key)
}

pub fn generate_taproot_spend_info(
    operator_public_key: &XOnlyPublicKey,
    n_of_n_public_key: &XOnlyPublicKey,
) -> TaprootSpendInfo {
    TaprootBuilder::new()
        .add_leaf(1, generate_taproot_leaf0(operator_public_key))
        .expect("Unable to add leaf0")
        .add_leaf(1, generate_taproot_leaf1(operator_public_key))
        .expect("Unable to add leaf1")
        .finalize(&Secp256k1::new(), *n_of_n_public_key)
        .expect("Unable to finalize taproot")
}

pub fn generate_taproot_address(
    operator_public_key: &XOnlyPublicKey,
    n_of_n_public_key: &XOnlyPublicKey,
) -> Address {
    Address::p2tr_tweaked(
        generate_taproot_spend_info(operator_public_key, n_of_n_public_key).output_key(),
        Network::Testnet,
    )
}
