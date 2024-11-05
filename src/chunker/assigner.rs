use super::{common::*, elements::ElementTrait};
use crate::treepp::*;

/// Implement `BCAssinger` to adapt with bridge.
pub trait BCAssigner {
    /// check hash
    fn create_hash(&mut self, id: &str);
    fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script;
    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Witness;
}

pub struct DummyAssinger {}

impl BCAssigner for DummyAssinger {
    fn create_hash(&mut self, _: &str) {}

    fn locking_script<T: ElementTrait + ?Sized>(&self, _: &Box<T>) -> Script {
        script! {}
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Witness {
        element.to_hash_witness().unwrap()
    }
}
