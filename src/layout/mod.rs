use bitcoin::{taproot::TaprootSpendInfo, ScriptBuf, Witness};
use bitcoin_script::Script;
use std::cell::RefCell;
use std::rc::Rc;

use crate::signatures::winternitz::PublicKey;

pub mod cache;
pub mod example;
pub mod groth16;
pub mod serialization;

pub struct Commitment {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hint {
    Fr(ark_bn254::Fr),
    Fq(ark_bn254::Fq),
    //...
}

impl Hint {
    pub fn into_witness(self) -> Witness {
        todo!()
    }
}

// This serves as an arc between chunks.
#[derive(Clone)]
pub struct HashedInput {
    // The destination chunk.
    outputting_chunk: Rc<RefCell<Chunk>>,

    // The index of output in the outputs.
    output_index: usize,
}

impl HashedInput {
    pub fn new(outputting_chunk: Rc<RefCell<Chunk>>, output_index: usize) -> Self {
        assert!(
            output_index <= outputting_chunk.borrow().outputs.len(),
            "Referenced output_index does not exist."
        );
        HashedInput {
            outputting_chunk,
            output_index,
        }
    }

    pub fn size(&self) -> usize {
        self.outputting_chunk.borrow().outputs[self.output_index]
    }
}

#[derive(Clone)]
pub struct Chunk {
    inputs: Vec<HashedInput>,
    outputs: Vec<usize>,
    hints: Vec<Hint>,
    execution_script: Script,
    name: String,
}

impl Chunk {
    pub fn new(
        inputs: Vec<HashedInput>,
        outputs: Vec<usize>,
        hints: Vec<Hint>,
        execution_script: Script,
        name: &str,
    ) -> Self {
        Chunk {
            inputs,
            outputs,
            hints,
            execution_script,
            name: name.to_string(),
        }
    }

    // Extends the script with the required input and output hashing and compiles it.
    pub fn scriptbuf(&self, commitments: Vec<PublicKey>) -> ScriptBuf {
        todo!();
    }

    // Uses inputs, revealed witnernitz signatures and hints to generate the script witness at runtime.
    pub fn witness(&self, signatures: /* TODO: Use a better type*/ Vec<Vec<u8>>) -> Witness {
        todo!();
    }

    pub fn commitments(&self, secret: &str) -> Vec<PublicKey> {
        todo!();
    }
}

pub struct Layout {
    pub chunks: Vec<Rc<RefCell<Chunk>>>,
    pub name: String,
    //TODO: Proof data that is commited and revealed in assert tx. Can handle it as a chunk with no
    //script and only outputs but it should be stored in its own field in this struct.
}

impl Layout {
    pub fn new(name: &str) -> Self {
        Layout { chunks: vec![], name: name.to_string() }
    }

    pub fn push(&mut self, chunk: Chunk) -> Rc<RefCell<Chunk>> {
        let rc_chunk = Rc::new(RefCell::new(chunk));
        self.chunks.push(rc_chunk.clone());
        rc_chunk
    }

    pub fn append(&mut self, mut chunks: Vec<Rc<RefCell<Chunk>>>) -> Rc<RefCell<Chunk>> {
        self.chunks.append(&mut chunks);
        self.chunks
            .last()
            .expect("Appending an empty Vec of chunks to an empty layout.")
            .clone()
    }

    // Create a new chunk, set its inputs to the previous chunk's outputs and push it to the
    // layout.
    // Returns the newly created chunk.
    pub fn push_serial_chunk(
        &mut self,
        outputs: Vec<usize>,
        hints: Vec<Hint>,
        execution_script: Script,
        name: &str,
    ) -> Rc<RefCell<Chunk>> {
        let inputs = match self.chunks.last() {
            Some(chunk) => {
                assert!(
                    chunk.borrow().outputs.len() == 1,
                    "Pushing a chunk in series, but the previous chunk has more than one output."
                );
                vec![HashedInput::new(chunk.clone(), 0)]
            }
            None => vec![],
        };
        self.push(Chunk::new(inputs, outputs, hints, execution_script, name))
    }

    pub fn push_partial_parallel_layout(
        &mut self,
        partial_parallel_layout: Layout,
        connection_points: Vec<(Rc<RefCell<Chunk>>, usize)>,
    ) -> Rc<RefCell<Chunk>> {
        assert!(
            !partial_parallel_layout.chunks.is_empty(),
            "Pushing an empty partial parallel layout to the parent layout."
        );
        for connection_point in connection_points {
            partial_parallel_layout.chunks[0]
                .borrow_mut()
                .inputs
                .push(HashedInput::new(connection_point.0, connection_point.1));
        }
        self.append(partial_parallel_layout.chunks)
    }

    pub fn taproot_spend_info(&self) -> TaprootSpendInfo {
        todo!();
    }

    pub fn commitments(&self) -> Vec<PublicKey> {
        todo!()
    }

}
