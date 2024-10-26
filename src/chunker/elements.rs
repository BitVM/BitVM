use std::any::Any;

use super::common::*;
use crate::bn254::utils::fq6_push_not_montgomery;
use crate::treepp::*;
use crate::{chunker::assigner::BCAssigner, execute_script_with_inputs};

/// FqElements are used in the chunker, representing muliple Fq.
#[derive(Debug, Clone)]
pub struct FqElement {
    pub identity: String,
    pub size: usize,
    pub witness_data: Option<Witness>,
}

/// Achieve fq size by using `FqElement::SIZE`
impl FqElement {
    fn witness_size(&self) -> usize {
        self.size * 9
    }
}

// (x: Fq, y: Fq)
pub struct G1Point(FqElement);
// (x: Fq2, y: Fq2)
pub struct G2Point(FqElement);
// (Fq6)
pub struct Fq6(FqElement);
// (Fq12)
pub struct Fq12(FqElement);

/// data type
pub enum DataType {
    Fq6Data(ark_bn254::Fq6),
    Fq12Data(ark_bn254::Fq12),
}

/// This trait defines the intermediate values
pub trait ElementTrait {
    /// Fill data by a specific value
    fn fill_with_data(&mut self, x: DataType);
    /// Convert the intermediate values to witness
    fn to_witness(&self) -> Option<Witness>;
    /// Convert the intermediate values from witness.
    /// If witness is none, return none.
    fn from_witness(&self) -> Option<DataType>;
    /// Hash witness by blake3
    fn to_hash(&self) -> Option<BLAKE3HASH>;
    /// Size of element by Fq
    fn size(&self) -> usize;
    /// Witness size of element by u32
    fn witness_size(&self) -> usize;
    /// Return the name of identity.
    fn id(&self) -> &str;
}

impl Fq6 {
    /// Create a new element by using bitcommitment assigner
    fn new<F: BCAssigner>(id: &str, size: usize, assigner: &mut F) -> Self {
        assigner.create_hash(id);
        Self {
            0: FqElement {
                identity: id.to_owned(),
                size: size,
                witness_data: None,
            },
        }
    }
}

/// impl element for Fq6
impl ElementTrait for Fq6 {
    fn fill_with_data(&mut self, x: DataType) {
        // TODO: need to be optimized and verify

        match x {
            DataType::Fq6Data(fq6_data) => {
                let res = execute_script(script! {
                    {fq6_push_not_montgomery(fq6_data)}
                });
                let witness = extract_witness_from_stack(res);
                assert_eq!(witness.len(), self.0.size);

                self.0.witness_data = Some(witness);
            }
            _ => panic!("fill wrong data {:?}", x.type_id()),
        }
    }

    fn to_witness(&self) -> Option<Witness> {
        self.0.witness_data.clone()
    }

    fn from_witness(&self) -> Option<DataType> {
        // TODO:
        todo!()
    }

    fn to_hash(&self) -> Option<BLAKE3HASH> {
        // TODO: need to be optimized and verify
        match self.0.witness_data.clone() {
            None => None,
            Some(witness) => {
                let res = execute_script_with_inputs(
                    script! {
                        {blake3_var_length(self.0.witness_size())}
                    },
                    witness,
                );
                let hash = witness_to_array(extract_witness_from_stack(res));
                Some(hash)
            }
        }
    }

    fn size(&self) -> usize {
        self.0.size
    }

    fn witness_size(&self) -> usize {
        self.0.witness_size()
    }

    fn id(&self) -> &str {
        &self.0.identity
    }
}

// TODO: impl element for G1point, G2point using macro!...
