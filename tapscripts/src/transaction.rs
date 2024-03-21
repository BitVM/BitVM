use crate::leaf::Leaves;
use bitcoin::{OutPoint, Script, TxOut, Txid, Witness, Amount, Address, Network};
use bitcoin::{Transaction, TxIn};
use std::collections::HashMap;
use std::str::FromStr;

pub type TxType<Model> = fn() -> Leaves<Model>;


pub fn compile_graph<Model>(
    model: &Model,
    graph: &HashMap<TxType<Model>, Vec<TxType<Model>>>,
    start: TxType<Model>,
    prev_outpoint: OutPoint,
) -> HashMap<Txid, Vec<Transaction>> {

    let result = HashMap::<Txid, Vec<Transaction>>::new();
    let children = &graph[&start];
    let transaction = compile_transaction(prev_outpoint, &children);
    let next_outpoint = OutPoint {
        txid: transaction.txid(),
        vout: 0,
    };
    for child in children {
        let subgraph = compile_graph(model, graph, *child, next_outpoint);
        // merge_graphs(result, subgraph); // TODO
    }

    result
}

fn compile_transaction<Model>(prev_outpoint: OutPoint, children: &Vec<TxType<Model>>) -> Transaction {

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
        script_pubkey,
    };
    
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    return tx;
}
