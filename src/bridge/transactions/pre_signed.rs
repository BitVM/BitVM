use bitcoin::{
  key::Keypair,
  sighash::Prevouts,
  taproot::TaprootSpendInfo,
  EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType,
  Transaction, TxOut,
};

use super::{
  signing::{
    populate_p2wsh_witness,
    populate_p2wpkh_witness,
    populate_taproot_input_witness,
  },
  super::contexts::base::BaseContext,
};

pub trait PreSignedTransaction {
  fn tx(&mut self) -> &mut Transaction;
  fn prev_outs(&self) -> &Vec<TxOut>;
  fn prev_scripts(&self) -> Vec<ScriptBuf>;
}

pub fn pre_sign_p2wsh_input<T: PreSignedTransaction>(
  tx: &mut T,
  context: &dyn BaseContext,
  input_index: usize,
  sighash_type: EcdsaSighashType,
  keypairs: &Vec<&Keypair>,
) {
  let script = &tx.prev_scripts()[input_index];
  let value = tx.prev_outs()[input_index].value;

  populate_p2wsh_witness(
      context,
      tx.tx(),
      input_index,
      sighash_type,
      script,
      value,
      keypairs,
  );
}

pub fn pre_sign_p2wpkh_input<T: PreSignedTransaction>(
  tx: &mut T,
  context: &dyn BaseContext,
  input_index: usize,
  sighash_type: EcdsaSighashType,
  public_key: &PublicKey,
  keypair: &Keypair,
) {
  let value = tx.prev_outs()[input_index].value;

  populate_p2wpkh_witness(
      context,
      tx.tx(),
      input_index,
      sighash_type,
      value,
      public_key,
      keypair,
  );
}

pub fn pre_sign_taproot_input<T: PreSignedTransaction>(
  tx: &mut T,
  context: &dyn BaseContext,
  input_index: usize,
  sighash_type: TapSighashType,
  taproot_spend_info: TaprootSpendInfo,
  keypairs: &Vec<&Keypair>,
) {
  let script = &tx.prev_scripts()[input_index];

  let prevouts_copy = tx.prev_outs().clone(); // To avoid immutable borrows, since we have to mutably borrow tx in this function.

  if sighash_type == TapSighashType::Single
      || sighash_type == TapSighashType::SinglePlusAnyoneCanPay
  {
      populate_taproot_input_witness(
          context,
          tx.tx(),
          &Prevouts::One(input_index, &prevouts_copy[input_index]),
          input_index,
          sighash_type,
          &taproot_spend_info,
          script,
          keypairs,
      );
  } else {
      populate_taproot_input_witness(
          context,
          tx.tx(),
          &Prevouts::All(&prevouts_copy),
          input_index,
          sighash_type,
          &taproot_spend_info,
          script,
          keypairs,
      );
  }
}
