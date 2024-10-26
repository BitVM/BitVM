use super::assigner::BCAssigner;
use super::common;
use super::common::*;
use super::elements::ElementTrait;
use crate::bn254::utils::Hint;
use crate::execute_script;
use crate::treepp::*;
use std::rc::Rc;

pub struct Segment {
    pub script: Script,
    pub parameter_list: Vec<Rc<Box<dyn ElementTrait>>>,
    pub result_list: Vec<Rc<Box<dyn ElementTrait>>>,
    pub hints: Vec<Hint>,
}

impl Segment {
    fn hinted_to_witness(&self) -> Vec<Vec<u8>> {
        // TODO: optimize these code
        let res = execute_script(script! {
            for hint in self.hints.iter() {
                { hint.push() }
            }
        });
        res.final_stack.0.iter_str().fold(vec![], |mut vector, x| {
            vector.push(x);
            vector
        })
    }

    pub fn new(
        script: Script,
        parameter_list: Vec<Rc<Box<dyn ElementTrait>>>,
        result_list: Vec<Rc<Box<dyn ElementTrait>>>,
        hints: Vec<Hint>,
    ) -> Self {
        Self {
            script,
            parameter_list,
            result_list,
            hints,
        }
    }

    /// [hinted, input0, input1, input1_bc_witness, input0_bc_witness, output1_bc_witness, outpu0_bc_witness]
    pub fn script<T: BCAssigner>(&self, assigner: &mut T) -> Script {
        let mut base: usize = 0;
        let mut script = script! {

            // 1. unlock all bitcommitment
            for result in self.result_list.iter() {
                {assigner.locking_script(result.as_ref().id())}
                for _ in 0..32 {
                    OP_TOALTSTACK
                }
            }
            for parameter in self.parameter_list.iter() {
                {assigner.locking_script(parameter.as_ref().id())} // verify bit commitment
                for _ in 0..32 {
                    OP_TOALTSTACK
                }
            }
        };

        for parameter in self.parameter_list.iter().rev() {
            let parameter_length = parameter.as_ref().witness_size();
            script = script.push_script(
                script! {
                // 2. push parameters onto altstack
                    for _ in 0..parameter_length {
                        {base + parameter_length} OP_PICK
                    }
                    {blake3_var_length(parameter_length)}
                    for _ in 0..32 {
                        OP_FROMALTSTACK
                    }
                    {equalverify(32)}
                }
                .compile(),
            );
            base += parameter_length;
        }

        script = script.push_script(
            script! {

                // 3. run inner script
                {self.script.clone()}

                // 4. result of blake3
                for result in self.result_list.iter().rev() {
                    {blake3_var_length(result.as_ref().witness_size())}
                    for _ in 0..32 {
                        OP_TOALTSTACK
                    }
                }

                for _ in 0..32 * self.result_list.len() * 2 {
                    OP_FROMALTSTACK
                }

                // 5. compare the result with assigned value
                {common::not_equal(32 * self.result_list.len())}
            }
            .compile(),
        );
        script
    }

    /// try to challenge this
    pub fn witness<T: BCAssigner>(&self, assigner: &mut T) -> Witness {
        // [hinted, input0, input1, input1_bc_witness, input0_bc_witness, output1_bc_witness, outpu0_bc_witness]
        let mut witness = vec![];

        witness.append(&mut self.hinted_to_witness());

        // TODO: use error to avoid unwrap
        for parameter in self.parameter_list.iter() {
            witness.append(&mut parameter.as_ref().to_witness().unwrap());
        }

        // TODO: use error to avoid unwrap
        for parameter in self.parameter_list.iter().rev() {
            witness.append(&mut assigner.get_witness(
                parameter.as_ref().id(),
                parameter.as_ref().to_hash().unwrap(),
            ));
        }

        for result in self.result_list.iter().rev() {
            witness.append(
                &mut assigner.get_witness(result.as_ref().id(), result.as_ref().to_hash().unwrap()),
            )
        }

        witness
    }
}
