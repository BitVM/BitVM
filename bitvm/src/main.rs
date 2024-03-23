mod dummy_program;
use bitcoin::{OutPoint, Txid, hashes::Hash};
use bitvm::{client, vm::VM, model::{PaulOpponent, VickyPlayer, PaulPlayer, BitVmModel}, graph::CompiledBitVMGraph, trace::kick_off};
use dummy_program::{DUMMY_PROGRAM, DUMMY_DATA};
use hex::FromHex;
use tapscripts::{actor::{Actor, Player, Opponent}, transaction::compile_graph};
use std::{env, cell::RefCell, rc::Rc};
use bitvm::graph::define_bitvm_graph;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2{
        panic!("You must specify if you want to start a 'vicky' or 'paul' client");
    }
    
    let mut model = if args[1] == "vicky" {
        start_vicky()
    } else {
        start_paul()
    };
    
    let graph = define_bitvm_graph();
    let start = kick_off;

    let txid_hex = "2694698395179d1f3f7f862a439f0dbaca437f8e7238afbdbb7f2cc7418a82b2";
    let txid_bytes = Vec::from_hex(txid_hex).expect("Invalid hex string");
    let txid = Txid::from_slice(&txid_bytes).expect("Invalid Txid bytes");
    let prev_outpoint = OutPoint { txid, vout: 0 };

    let compiled_graph = compile_graph(&model, &graph, start, prev_outpoint);

    let mut client = crate::client::BitVMClient::new();
    client.listen(&mut model, &compiled_graph).await
}


fn start_vicky() -> BitVmModel {
    println!("Start Vicky");

    let secret = "d898098e09898a0980989b980809809809f09809884324874302975287524398";
    let opponent_pubkey = "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497";
    let vicky = VickyPlayer::new(secret, &DUMMY_PROGRAM, &DUMMY_DATA, opponent_pubkey);
    let paul = Rc::clone(&vicky.opponent);
    BitVmModel {
        paul: paul,
        vicky: Rc::new(vicky),
    }
}

fn start_paul() -> BitVmModel {
    println!("Start Paul");

    let secret = "d898098e09898a0980989b980809809809f09809884324874302975287524398";
    let opponent_pubkey = "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497";
    let paul = PaulPlayer::new(secret, &DUMMY_PROGRAM, &DUMMY_DATA, opponent_pubkey);
    let vicky = Rc::clone(&paul.opponent);
    BitVmModel { 
        paul: Rc::new(paul),
        vicky: vicky,
    }
}