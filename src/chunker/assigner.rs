use super::common::*;
use crate::treepp::*;

pub struct BitCommitment {}

pub trait BCAssigner {
    /// check hash
    fn create_hash(&mut self, id: &str);
    fn locking_script(&self, id: &str) -> Script;
    fn get_witness(&mut self, id: &str, hash: BLAKE3HASH) -> Witness;
}
