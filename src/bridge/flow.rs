use bitcoin::{
  key::Keypair,
  Amount, Network, PublicKey, TxOut, XOnlyPublicKey
};

use super::{
  graph::CompiledBitVMGraph,
  components::{
  peg_in_confirm::PegInConfirmTransaction,
  peg_in_refund::PegInRefundTransaction,
  helper::*
}
};

pub struct Flow {
  network: Network,
  amount: Amount,
  evm_address: String
}

impl Flow {

  // pub fn peg_in_deposit(depositor_keypair: &Keypair, n_of_n_public_key: &PublicKey, n_of_n_taproot_public_key: &XOnlyPublicKey) -> (PegInConfirmTransaction, PegInRefundTransaction) {
  //   todo!()
  // }
  // pub fn peg_in_refund(peg_in_refund_transaction: &PegInRefundTransaction, depositor_keypair: &Keypair) {
  //   todo!()
  // }

  // pub fn peg_in_confirm_pre_sign(peg_in_confirm_transaction: &PegInConfirmTransaction, operator_keypair: &Keypair, n_of_n_public_key: &PublicKey, n_of_n_taproot_public_key: &XOnlyPublicKey) -> (CompiledBitVMGraph) {
  //   todo!()
  // }

  // pub fn peg_in_confirm_pre_sign(peg_in_confirm_transaction: &PegInConfirmTransaction, graph: &CompiledBitVMGraph, n_of_n_keypair: &Keypair) -> (CompiledBitVMGraph) {
  //   todo!()
  // }

  // pub fn peg_in_confirm_finalize(peg_in_confirm_transaction: &PegInConfirmTransaction) {
  //   todo!()
  // }

  // pub fn peg_out_and_kickoff(graph: &CompiledBitVMGraph, commit: &str, withdrawer_public_key: &PublicKey, operator_keypair: &Keypair) {
  //   todo!()
  // }

  // pub fn take1(graph: &CompiledBitVMGraph) {
  //   todo!()
  // }

  // pub fn challenge(graph: &CompiledBitVMGrap, additional_inputs: Vec<Input>, additional_outputs: Vec<TxOut>) {
  //   todo!()
  // }

  // pub fn take2(graph: &CompiledBitVMGraph) {
  //   todo!()
  // }

  // pub fn assert(graph: &CompiledBitVMGraph, commit: &str) {
  //   todo!()
  // }

  // pub fn disprove(graph: &CompiledBitVMGraph, disprove: &str) {
  //   todo!()
  // }

  // pub fn burn(graph: &CompiledBitVMGraph, additional_outputs: Vec<TxOut>) {
  //   todo!()
  // }
}
