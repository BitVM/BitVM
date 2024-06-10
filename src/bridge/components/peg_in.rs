use bitcoin::{
    Transaction, TxOut,
};



pub struct PegInTransaction {
  tx: Transaction,
  prev_outs: Vec<TxOut>,
}