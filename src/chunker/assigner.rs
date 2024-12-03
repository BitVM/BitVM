use super::{common::*, elements::ElementTrait};
use crate::treepp::*;
use std::{collections::BTreeMap, rc::Rc};

/// Implement `BCAssinger` to adapt with bridge.
pub trait BCAssigner: Default {
    /// check hash
    fn create_hash(&mut self, id: &str);
    /// return a element of
    fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script;
    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness;
    /// output sciprt for all elements, used by assert transaction
    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>>;
    /// output witness for all elements, used by assert transaction
    fn all_intermeidate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>>;
    /// recover hashes from witnesses
    fn recover_from_witness(&self, witnesses: Vec<Vec<RawWitness>>)
        -> BTreeMap<String, BLAKE3HASH>;
}

#[derive(Default)]
pub struct DummyAssinger {
    bc_map: BTreeMap<String, String>,
}

impl BCAssigner for DummyAssinger {
    fn create_hash(&mut self, id: &str) {
        self.bc_map.insert(id.to_string(), id.to_string());
    }

    fn locking_script<T: ElementTrait + ?Sized>(&self, _: &Box<T>) -> Script {
        script! {}
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        element.to_hash_witness().unwrap()
    }

    fn recover_from_witness(
        &self,
        witnesses: Vec<Vec<RawWitness>>,
    ) -> BTreeMap<String, BLAKE3HASH> {
        let mut btree_map: BTreeMap<String, BLAKE3HASH> = Default::default();
        // flat the witnesses and recover to btreemap
        let flat_witnesses: Vec<RawWitness> = witnesses.into_iter().fold(vec![], |mut w, x| {
            w.extend(x);
            w
        });
        assert_eq!(flat_witnesses.len(), self.bc_map.len());
        for ((id, _), idx) in self.bc_map.iter().zip(0..flat_witnesses.len()) {
            btree_map.insert(id.to_owned(), witness_to_array(flat_witnesses[idx].clone()));
        }
        btree_map
    }

    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>> {
        vec![self.bc_map.iter().map(|(_, _)| script! {}).collect()]
    }

    fn all_intermeidate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>> {
        assert_eq!(elements.len(), self.bc_map.len());
        vec![elements
            .iter()
            .map(|(_, element)| self.get_witness(element))
            .collect()]
    }
}
