

use bitcoin::key::Secp256k1;
use bitvm::{
  self, 
  bridge::{client::BitVMClient, 
    context::BridgeContext, 
    graph::{DEPOSITOR_SECRET, EVM_ADDRESS, N_OF_N_SECRET, OPERATOR_SECRET, WITHDRAWER_SECRET }
  }
};
use musig2::secp256k1::All;

pub fn setup_test() -> (BitVMClient, BridgeContext, Secp256k1<All>) {
  let mut context = BridgeContext::new();
  context.initialize_evm_address(EVM_ADDRESS);
  context.initialize_operator(OPERATOR_SECRET);
  context.initialize_n_of_n(N_OF_N_SECRET);
  context.initialize_depositor(DEPOSITOR_SECRET);
  context.initialize_withdrawer(WITHDRAWER_SECRET);

  let client = BitVMClient::new();

  let secp = Secp256k1::new();

  return (client, context, secp)
}