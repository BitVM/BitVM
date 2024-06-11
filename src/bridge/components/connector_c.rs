use crate::treepp::*;
use bitcoin::{
    hashes::{ripemd160, Hash}, key::Secp256k1, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

// Specialized for assert leaves currently.
pub type LockScript = fn(index: u32) -> Script;

pub type UnlockWitness = fn(index: u32) -> Vec<Vec<u8>>;

pub struct AssertLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

pub fn assert_leaf() -> AssertLeaf {
  AssertLeaf {
      lock: |index| {
          script! {
              OP_RIPEMD160
              { ripemd160::Hash::hash(format!("SECRET_{}", index).as_bytes()).as_byte_array().to_vec() }
              OP_EQUALVERIFY
              { index }
              OP_DROP
          }
      },
      unlock: |index| vec![format!("SECRET_{}", index).as_bytes().to_vec()],
  }
}

pub fn generate_assert_leaves() -> Vec<Script> {
  // TODO: Scripts with n_of_n_pubkey and one of the commitments disprove leaves in each leaf (Winternitz signatures)
  let mut leaves = Vec::with_capacity(1000);
  let locking_template = assert_leaf().lock;
  for i in 0..1000 {
      leaves.push(locking_template(i));
  }
  leaves
}

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_c_spend_info(
  n_of_n_pubkey: XOnlyPublicKey
) -> (TaprootSpendInfo, TaprootSpendInfo) {

  // Leaf[0]: spendable by multisig of OPK and VPK[1…N]
  let take2_script = script! {
    { n_of_n_pubkey }
    OP_CHECKSIG
  };

  let secp = Secp256k1::new();

  let leaf0 = TaprootBuilder::new()
    .add_leaf(0, take2_script)
    .expect("Unable to add leaf0")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize taproot");

  // Leaf[i] for some i in 1,2,…1000: spendable by multisig of OPK and VPK[1…N] plus the condition that f_{i}(z_{i-1})!=z_i
  let disprove_scripts = generate_assert_leaves();
  let script_weights = disprove_scripts.iter().map(|script| (1, script.clone()));

  let leaf1 = TaprootBuilder::with_huffman_tree(script_weights)
      .expect("Unable to add assert leaves")
      // Finalizing with n_of_n_pubkey allows the key-path spend with the
      // n_of_n
      .finalize(&secp, n_of_n_pubkey)
      .expect("Unable to finalize assert transaction connector c taproot");

  (leaf0, leaf1)
}

pub fn connector_c_address(n_of_n_pubkey: XOnlyPublicKey) -> Address {
  Address::p2tr_tweaked(
      connector_c_spend_info(n_of_n_pubkey).1.output_key(),
      Network::Testnet,
  )
}

pub fn connector_c_pre_sign_address(n_of_n_pubkey: XOnlyPublicKey) -> Address {
  Address::p2tr_tweaked(
      connector_c_spend_info(n_of_n_pubkey).0.output_key(),
      Network::Testnet,
  )
}