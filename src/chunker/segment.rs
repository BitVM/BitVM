use super::assigner::BCAssigner;
use super::common;
use super::common::*;
use super::elements::ElementTrait;
use crate::bn254::utils::Hint;
use crate::execute_script;
use crate::treepp::*;
use std::rc::Rc;

pub struct Segment {
    pub name: String,
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

    pub fn new(script: Script) -> Self {
        Self::new_with_name(String::new(), script)
    }

    pub fn new_with_name(name: String, script: Script) -> Self {
        Self {
            name,
            script,
            parameter_list: vec![],
            result_list: vec![],
            hints: vec![],
        }
    }

    pub fn add_parameter<T: ElementTrait + 'static + Clone>(mut self, x: &T) -> Self {
        self.parameter_list.push(Rc::new(Box::new(x.clone())));
        self
    }

    pub fn add_result<T: ElementTrait + 'static + Clone>(mut self, x: &T) -> Self {
        self.result_list.push(Rc::new(Box::new(x.clone())));
        self
    }

    pub fn add_hint(mut self, hints: Vec<Hint>) -> Self {
        self.hints = hints;
        self
    }

    /// [hinted, input0, input1, input1_bc_witness, input0_bc_witness, outpu0_bc_witness, output1_bc_witness]
    pub fn script<T: BCAssigner>(&self, assigner: &T) -> Script {
        let mut base: usize = 0;
        let mut script = script! {

            // 1. unlock all bitcommitment
            for result in self.result_list.iter().rev() {
                {assigner.locking_script(&result)}
                for _ in 0..BLAKE3_HASH_LENGTH {
                    OP_TOALTSTACK
                }
            }
            for parameter in self.parameter_list.iter() {
                {assigner.locking_script(&parameter)} // verify bit commitment
                for _ in 0..BLAKE3_HASH_LENGTH {
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
                        {base + parameter_length - 1} OP_PICK
                    }
                    {blake3_var_length(parameter_length)}
                    for _ in 0..BLAKE3_HASH_LENGTH {
                        OP_FROMALTSTACK
                    }
                    {equalverify(BLAKE3_HASH_LENGTH)}
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
                    for _ in 0..BLAKE3_HASH_LENGTH {
                        OP_TOALTSTACK
                    }
                }

                for _ in 0..BLAKE3_HASH_LENGTH * self.result_list.len() * 2 {
                    OP_FROMALTSTACK
                }

                // 5. compare the result with assigned value
                {common::not_equal(BLAKE3_HASH_LENGTH * self.result_list.len())}
            }
            .compile(),
        );
        script
    }

    /// try to challenge this
    pub fn witness<T: BCAssigner>(&self, assigner: &T) -> Witness {
        // [hinted, input0, input1, input1_bc_witness, input0_bc_witness, output1_bc_witness, outpu0_bc_witness]
        let mut witness = vec![];

        witness.append(&mut self.hinted_to_witness());

        for parameter in self.parameter_list.iter() {
            match parameter.as_ref().to_witness() {
                Some(mut w) => {
                    witness.append(&mut w);
                }
                None => {
                    panic!("extract witness {} fail in {}", parameter.id(), self.name)
                }
            }
        }

        for parameter in self.parameter_list.iter().rev() {
            witness.append(&mut assigner.get_witness(&parameter));
        }

        for result in self.result_list.iter() {
            witness.append(&mut assigner.get_witness(&result))
        }

        witness
    }
}

#[cfg(test)]
mod tests {
    use super::Segment;
    use crate::chunker::elements::ElementTrait;
    use crate::chunker::{assigner::DummyAssinger, elements::DataType::Fq6Data, elements::Fq6Type};
    use crate::{execute_script_with_inputs, treepp::*};

    #[test]
    fn test_segment_by_simple_case() {
        let mut assigner = DummyAssinger {};

        let mut a0 = Fq6Type::new(&mut assigner, "a0");
        a0.fill_with_data(Fq6Data(ark_bn254::Fq6::from(1)));

        let segment = Segment::new(script! {}).add_parameter(&a0).add_result(&a0);

        let script = segment.script(&assigner);
        let witness = segment.witness(&assigner);

        println!("witnesss needs stack {}", witness.len());
        println!(
            "element witnesss needs stack {}",
            a0.to_hash_witness().unwrap().len()
        );

        let res = execute_script_with_inputs(script, witness);
        println!("res.successs {}", res.success);
        println!("res.stack len {}", res.final_stack.len());
        println!("rse.remaining: {}", res.remaining_script);
        println!("res: {:1000}", res);
    }
}
