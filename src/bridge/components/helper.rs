use crate::treepp::*;
use bitcoin::{
  Address, Amount, Network, OutPoint, XOnlyPublicKey
};

pub fn generate_burn_script() -> Script {
  script! {
      OP_RETURN
  }
}

pub fn generate_burn_script_address() -> Address {
  Address::p2wsh(&generate_burn_script(), Network::Testnet)
}

pub fn generate_timelock_script(n_of_n_pubkey: &XOnlyPublicKey, weeks: i64) -> Script {
  script! {
    { NUM_BLOCKS_PER_WEEK * weeks }
    OP_CSV
    OP_DROP
    { n_of_n_pubkey.clone() }
    OP_CHECKSIG
  }
}

pub fn generate_timelock_script_address(n_of_n_pubkey: &XOnlyPublicKey, weeks: i64) -> Address {
  Address::p2wsh(&generate_timelock_script(n_of_n_pubkey, weeks), Network::Testnet)
}

pub fn generate_pay_to_pubkey_script(pubkey: &XOnlyPublicKey) -> Script {
  script! {
      { pubkey.clone() }
      OP_CHECKSIG
  }
}

pub fn generate_pay_to_pubkey_script_address(pubkey: &XOnlyPublicKey) -> Address {
  Address::p2wsh(
    &generate_pay_to_pubkey_script(pubkey),
    Network::Testnet
  )
}

pub type Input = (OutPoint, Amount);

pub const NUM_BLOCKS_PER_WEEK: i64 = 1008;
