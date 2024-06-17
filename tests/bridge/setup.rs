use bitcoin::{
  consensus::encode::serialize_hex, key::{Keypair, Secp256k1}, Amount, OutPoint, TxOut, PublicKey, PrivateKey, Network
};

use bitvm::{
  self, 
  bridge::{client::BitVMClient, 
    components::{
      bridge::BridgeTransaction, 
      helper::Input, 
    }, 
    context::BridgeContext, 
    graph::{DEPOSITOR_SECRET, FEE_AMOUNT, INITIAL_AMOUNT, N_OF_N_SECRET, OPERATOR_SECRET, UNSPENDABLE_PUBKEY}
  }
};

pub fn setup_test() -> (BitVMClient, BridgeContext) {
  let secp = Secp256k1::new();

  let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
  let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
  let n_of_n_pubkey = n_of_n_key.x_only_public_key().0;
  let depositor_key = Keypair::from_seckey_str(&secp, DEPOSITOR_SECRET).unwrap();
  let depositor_pubkey = depositor_key.x_only_public_key().0;
  let depositor_private_key = PrivateKey::new(depositor_key.secret_key(), Network::Testnet);
  let depositor_pubkey_normal = PublicKey::from_private_key(&secp, &depositor_private_key);

  let mut context = BridgeContext::new();
  context.set_operator_key(operator_key);
  context.set_n_of_n_pubkey(n_of_n_pubkey);
  context.set_depositor_pubkey(depositor_pubkey);
  context.set_depositor_pubkey_normal(depositor_pubkey_normal);
  context.set_unspendable_pubkey(*UNSPENDABLE_PUBKEY);

  let client = BitVMClient::new();

  return (client, context)
}