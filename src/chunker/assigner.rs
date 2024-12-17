use super::{
    chunk_groth16_verifier::groth16_verify_to_segments,
    common::*,
    disprove_execution::RawProof,
    elements::{ElementTrait, G2PointType},
};
use crate::treepp::*;
use std::{collections::BTreeMap, rc::Rc};

/// Implement `BCAssinger` to adapt with bridge.
#[allow(clippy::borrowed_box)]
pub trait BCAssigner: Default {
    /// check hash
    fn create_hash(&mut self, id: &str);
    /// return a element of
    fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script;
    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness;
    /// output sciprt for all elements, used by assert transaction
    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>>;
    /// output witness for all elements, used by assert transaction
    fn all_intermediate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>>;
    /// recover hashes from witnesses
    fn recover_from_witness(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
    ) -> BTreeMap<String, BLAKE3HASH>;
}

#[derive(Default)]
pub struct DummyAssigner {
    bc_map: BTreeMap<String, String>,
}

impl BCAssigner for DummyAssigner {
    fn create_hash(&mut self, id: &str) {
        if self.bc_map.contains_key(id) {
            panic!("variable name is repeated, check {}", id);
        }
        self.bc_map.insert(id.to_string(), id.to_string());
    }

    fn locking_script<T: ElementTrait + ?Sized>(&self, _: &Box<T>) -> Script {
        script! {}
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        element.to_hash_witness().unwrap()
    }

    fn recover_from_witness(
        &mut self,
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

    fn all_intermediate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>> {
        for (key, _) in self.bc_map.iter() {
            if !elements.contains_key(key) {
                println!("unconsistent key: {}", key)
            }
        }
        assert_eq!(elements.len(), self.bc_map.len());
        vec![elements
            .values()
            .map(|element| self.get_witness(element))
            .collect()]
    }
}

/// This assigner records all intermediate values messages.
/// It run the entire chunker with a default proof. A git-commit-related cache may reduce the time.
#[derive(Default)]
pub struct BCRecorder {
    bc_map: BTreeMap<String, String>,
}

impl BCRecorder {
    fn all_intermediate_variable(&mut self) -> Vec<String> {
        let proof = RawProof::default();
        let _ = groth16_verify_to_segments(self, &proof.public, &proof.proof, &proof.vk);
        self.bc_map.clone().into_keys().collect()
    }
}

impl BCAssigner for BCRecorder {
    fn create_hash(&mut self, id: &str) {
        if self.bc_map.contains_key(id) {
            panic!("variable name is repeated, check {}", id);
        }
        self.bc_map.insert(id.to_string(), id.to_string());
    }

    fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script {
        todo!()
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        todo!()
    }

    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>> {
        todo!()
    }

    fn all_intermediate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>> {
        todo!()
    }

    fn recover_from_witness(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
    ) -> BTreeMap<String, BLAKE3HASH> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::DummyAssigner;
    use crate::chunker::common::witness_size;
    use crate::execute_script_with_inputs;
    use crate::treepp::{script, Script};
    use crate::{
        bridge::transactions::signing_winternitz::{
            generate_winternitz_witness, winternitz_message_checksig, WinternitzPublicKey,
            WinternitzSecret, WinternitzSigningInputs, LOG_D,
        },
        chunker::{
            assigner::BCRecorder,
            disprove_execution::RawProof,
            elements::{ElementTrait as _, G2PointType},
        },
        signatures::utils::digits_to_number,
    };

    #[test]
    fn test_variable_names() {
        let variable_names = BCRecorder::default().all_intermediate_variable();
        println!("variable_name: {}", variable_names.len());
    }

    #[test]
    fn test_commit_g2_point() {
        let mut dummy_assigner = DummyAssigner::default();
        let proof = RawProof::default();
        let q4 = proof.proof.b;

        let mut q4_input = G2PointType::new(&mut dummy_assigner, "q4");
        q4_input.fill_with_data(crate::chunker::elements::DataType::G2PointData(q4));

        let witness = q4_input.to_witness().unwrap();

        println!(
            "{:?}, total_length: {}",
            witness.iter().map(|x| x.len()).collect::<Vec<usize>>(),
            witness.len()
        );

        let bc_secret = WinternitzSecret::new(20);
        let public_key = WinternitzPublicKey::from(&bc_secret);

        let times = 10;
        let witness = (0..times)
            .map(|_| {
                generate_winternitz_witness(&WinternitzSigningInputs {
                    message: &vec![0; 20],
                    signing_key: &bc_secret,
                })
                .to_vec()
            })
            .collect::<Vec<_>>()
            .concat();
        let script = script! {
            for _ in 0..times {
                { winternitz_message_checksig(&public_key) }
                for _ in 0..40 {
                    OP_DROP
                }
            }
        };

        println!(
            "witness size: {}, script size: {}",
            witness_size(&witness),
            script.len()
        );
        // witness size: 8830, script size: 30120

        let res = execute_script_with_inputs(script, witness);
        println!("res.max_stack {}", res.stats.max_nb_stack_items);
        // res.max_stack 889
    }
}
