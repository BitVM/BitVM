use crate::treepp::*;
use bitcoin::{
    hashes::{ripemd160, Hash},
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network,
    XOnlyPublicKey,
};

use super::helper::*;

// Specialized for assert leaves currently.a
// TODO: Attach the pubkeys after constructing leaf scripts
pub type LockScript = fn(u32) -> Script;

pub type UnlockWitness = fn(u32) -> Vec<Vec<u8>>;

pub struct AssertLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

pub fn assert_leaf(operator_pubkey: XOnlyPublicKey) -> AssertLeaf {
  AssertLeaf {
      lock: |index| {
          script! {
              { operator_pubkey }
              OP_CHECKSIGVERIFY
              OP_RIPEMD160
              { ripemd160::Hash::hash(format!("SECRET_{}", index).as_bytes()).as_byte_array().to_vec() }
              OP_EQUALVERIFY
              { index }
              OP_DROP
              OP_TRUE
          }
      },
      unlock: |index| vec![format!("SECRET_{}", index).as_bytes().to_vec()],
  }
}

pub fn generate_assert_leaves(operator_pubkey: XOnlyPublicKey) -> Vec<Script> {
  // TODO: Scripts with n_of_n_pubkey and one of the commitments disprove leaves in each leaf (Winternitz signatures)
  let mut leaves = Vec::with_capacity(1000);
  let locking_template = assert_leaf(operator_pubkey).lock;
  for i in 0..1000 {
      leaves.push(locking_template(i));
  }
  leaves
}

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_c_alt_spend_info(
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey,
) -> TaprootSpendInfo {
  let secp = Secp256k1::new();

  // Leaf[0]: spendable by multisig of OPK and VPK[1…N]
  let leaf0 = script! {
    { operator_pubkey }
    OP_CHECKSIGVERIFY
    { n_of_n_pubkey }
    OP_CHECKSIGVERIFY
  };

  // Leaf[i] for some i in 1,2,…1000: spendable by multisig of OPK and VPK[1…N]? (How do we do this?) plus the condition that f_{i}(z_{i-1})!=z_i
  let mut scripts = generate_assert_leaves();

  scripts.insert(0, leaf0);

  let script_weights = scripts.iter().map(|script| (1, script.clone()));
  return TaprootBuilder::with_huffman_tree(script_weights)
      .expect("Unable to add assert leaves")
      // Finalizing with n_of_n_pubkey allows the key-path spend with the
      // n_of_n
      .finalize(&secp, n_of_n_pubkey)
      .expect("Unable to finalize assert transaction connector c taproot");
}

pub fn connector_c_alt_address(operator_pubkey: XOnlyPublicKey, n_of_n_pubkey: XOnlyPublicKey) -> Address {
  Address::p2tr_tweaked(
      connector_c_alt_spend_info(operator_pubkey, n_of_n_pubkey).output_key(),
      Network::Testnet,
  )
}
