use bitcoin::{Amount, OutPoint, Script, Transaction};

pub struct Input {
    pub outpoint: OutPoint,
    pub amount: Amount,
}

pub struct InputWithScript<'a> {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub script: &'a Script,
}

pub trait BaseTransaction {
    // fn initialize(&mut self, context: &dyn BaseContext);

    // TODO: Use musig2 to aggregate signatures
    // fn pre_sign(&mut self, context: &dyn BaseContext);

    // TODO: Implement default that goes through all leaves and checks if one of them is executable
    // TODO: Return a Result with an Error in case the witness can't be created
    fn finalize(&self) -> Transaction;
}
