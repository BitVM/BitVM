use crate::leaf::Leaves;
use bitcoin::address::{NetworkValidation, NetworkUnchecked};
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Script, TxOut, Txid, Witness, Amount, Address, Network};
use bitcoin::{Transaction, TxIn};
use std::collections::HashMap;
use std::str::FromStr;





pub type TxType<'a, T> = fn(T) -> Leaves<'a>;


pub fn compile_graph<T>(
    params: &T,
    graph: &HashMap<TxType<T>, Vec<TxType<T>>>,
    start: TxType<T>,
    prev_outpoint: OutPoint,
) -> HashMap<Txid, Vec<Transaction>> {

    let result = HashMap::<Txid, Vec<Transaction>>::new();
    let children = &graph[&start];
    let transaction = compile_transaction(prev_outpoint, &children);
    let mut next_outpoint = OutPoint {
        txid: transaction.txid(),
        vout: 0,
    };
    for child in children {
        let subgraph = compile_graph(params, graph, *child, next_outpoint);
        // merge_graphs(result, subgraph); // TODO
    }

    result
}

fn compile_transaction<T>(prev_outpoint: OutPoint, children: &Vec<TxType<T>>) -> Transaction {

    // Decode the destination address
    // TODO: join all leaves of all children into a single taproot
    let address: Address = Address::from_str("1K6KoYC69NnafWJ7YgtrpwJxBLiijWqwa6").unwrap()
                .require_network(Network::Bitcoin).unwrap();

    let script_pubkey = address.script_pubkey();


    let input = TxIn {
        previous_output: prev_outpoint,
        script_sig: Script::new().into(),
        sequence: bitcoin::Sequence(0xFFFFFFFF),
        witness: Witness::new(),
    };

    let output = TxOut {
        value: Amount::from_sat(50_000), // TODO: input amount - fees? 
        script_pubkey: script_pubkey,
    };
    
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    return tx;
}
