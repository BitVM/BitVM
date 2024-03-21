use crate::trace::{kick_off, trace_response};
use crate::{instructions::commit_instruction, model::BitVmModel, trace::trace_challenge};
use tapscripts::leaf::Leaf;
use std::collections::HashMap;


pub type BitVmLeaf = Leaf<BitVmModel>;

pub type BitVmTx = fn() -> Vec<BitVmLeaf>;

pub type BitVMGraph = HashMap<BitVmTx, Vec<BitVmTx>>;


pub fn define_bitvm_graph() -> BitVMGraph {
    let mut graph = BitVMGraph::new();
    graph.insert(
        kick_off,
        vec![
            trace_challenge::<1>,
            trace_challenge::<2>,
            trace_challenge::<3>,
            trace_response::<1>,
        ],
    );
    graph.insert(
        trace_challenge::<1>,
        vec![trace_challenge::<2>, trace_challenge::<3>],
    );
    graph.insert(trace_challenge::<2>, vec![]);
    graph.insert(trace_challenge::<3>, vec![commit_instruction]);
    graph.insert(commit_instruction, vec![]);
    graph.insert(trace_response::<1>, vec![]);

    return graph;
}
