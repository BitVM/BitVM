use std::collections::HashMap;
use scripts::{transaction::TxType, leaf::{Leaf, Leaves}};
use crate::{instructions::commit_instruction, model::{Vicky, Paul, BitVmModel}, trace::{trace_challenge}};
use crate::trace::kick_off;


pub type BitVmLeaf = Leaf<BitVmModel>;

pub type BitVmTx = fn() -> Leaves<BitVmModel>;

pub type BitVMGraph = HashMap<BitVmTx, Vec<BitVmTx>>;


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



