use std::collections::HashMap;
use bitcoin::{Txid, hashes::Hash, OutPoint};
use hex::FromHex;
use scripts::transaction::{TxType, compile_graph};
use crate::{instructions::commit_instruction, model::{Vicky, Paul}, trace::{trace_challenge, kick_off}};

pub(crate) struct BitVmModel {
    // pub vicky : &'a dyn Vicky,
    // pub paul : &'a dyn Paul,
}

type BitVmTx<'a> = TxType<'a, BitVmModel>;
type BitVMGraph<'a> = HashMap<BitVmTx<'a>, Vec<BitVmTx<'a>>>;


fn define_bitvm_graph<'a>() -> BitVMGraph<'a> {
    let mut graph = BitVMGraph::new();
    graph.insert(
        kick_off,
        vec![
            trace_challenge::<1>,
            trace_challenge::<2>,
            trace_challenge::<3>,
        ],
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





#[test]
fn test() {
    let graph = define_bitvm_graph();
    let params = BitVmModel {};
    let start = kick_off;
    let txid_hex = "2694698395179d1f3f7f862a439f0dbaca437f8e7238afbdbb7f2cc7418a82b2";
    let txid_bytes = Vec::from_hex(txid_hex).expect("Invalid hex string");
    let txid = Txid::from_slice(&txid_bytes).expect("Invalid Txid bytes");

    let outpoint = OutPoint { txid, vout: 0 };
    compile_graph(&params, &graph, start, outpoint);
}
