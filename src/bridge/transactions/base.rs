use bitcoin::{Amount, OutPoint, Transaction};
use serde::{Deserialize, Serialize};

pub struct Input {
    pub outpoint: OutPoint,
    pub amount: Amount,
}
pub trait BaseTransaction {
    // fn initialize(&mut self, context: &dyn BaseContext);

    // TODO: Use musig2 to aggregate signatures
    // fn pre_sign(&mut self, context: &dyn BaseContext);

    // TODO: Implement default that goes through all leaves and checks if one of them is executable
    // TODO: Return a Result with an Error in case the witness can't be created
    fn finalize(&self) -> Transaction;
}

pub fn serialize(object: &impl Serialize) -> String { serde_json::to_string(object).unwrap() }

pub fn deserialize<'a, T>(data: &'a str) -> T
where
    T: Deserialize<'a>,
{
    serde_json::from_str::<T>(data).unwrap()
}
