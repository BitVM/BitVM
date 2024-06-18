use bitvm::{
  self, 
  bridge::{client::BitVMClient, 
    context::BridgeContext, 
    graph::{DEPOSITOR_SECRET, EVM_ADDRESS, N_OF_N_SECRET, OPERATOR_SECRET, WITHDRAWER_SECRET }
  }
};

pub fn setup_test() -> (BitVMClient, BridgeContext) {
  let mut context = BridgeContext::new();
  context.initialize_evm_address(EVM_ADDRESS);
  context.initialize_operator(OPERATOR_SECRET);
  context.initialize_n_of_n(N_OF_N_SECRET);
  context.initialize_depositor(DEPOSITOR_SECRET);
  context.initialize_withdrawer(WITHDRAWER_SECRET);

  let client = BitVMClient::new();

  return (client, context)
}