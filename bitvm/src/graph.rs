use std::collections::HashMap;
use scripts::transaction::TxType;
use crate::{instructions::commit_instruction, model::{Vicky, Paul}, trace::{trace_challenge, kick_off}};

pub struct BitVmModel {
    // pub vicky : &'a dyn Vicky,
    // pub paul : &'a dyn Paul,
}

type BitVmTx = TxType<BitVmModel>;
type BitVMGraph = HashMap<BitVmTx, Vec<BitVmTx>>;


pub fn define_bitvm_graph() -> BitVMGraph {
    let mut graph = BitVMGraph::new();
    graph.insert(
        kick_off,
        vec![trace_challenge::<1>, trace_challenge::<2>, trace_challenge::<3>],
    );
    graph.insert(
        trace_challenge::<1>,
        vec![trace_challenge::<2>, trace_challenge::<3>],
    );
    graph.insert(trace_challenge::<2>, vec![]);
    graph.insert(trace_challenge::<3>, vec![commit_instruction]);
    graph.insert(commit_instruction, vec![]);

    return graph;
}



