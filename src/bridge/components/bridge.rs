use super::super::context::BridgeContext;
use bitcoin::Transaction;

pub trait BridgeTransaction {
    // TODO: Use musig2 to aggregate signatures
    fn pre_sign(&mut self, context: &BridgeContext);

    // TODO: Implement default that goes through all leaves and checks if one of them is executable
    // TODO: Return a Result with an Error in case the witness can't be created
    fn finalize(&self, context: &BridgeContext) -> Transaction;
}
