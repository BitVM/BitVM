mod common;

use bitcoin::{Txid, hashes::Hash, OutPoint};
use hex::FromHex;
use scripts::transaction::compile_graph;
use bitvm::{model::{Vicky, Paul, PaulPlayer, VickyPlayer}, trace::kick_off, constants::ASM_ADD, vm::Instruction};
use bitvm::graph::{define_bitvm_graph, BitVmModel};
use crate::common::vicky_pubkey;


#[test]
fn test() {
    let address_a = 0;
    let value_a = 0xFFFFFFFB;
    let address_b = 1;
    let value_b = 7;
    let address_c = 2;
    let program = [Instruction {
        asm_type: ASM_ADD,
        address_a,
        address_b,
        address_c,
    }];
    let data: [u32; 2] = [value_a, value_b];


    let graph = define_bitvm_graph();
    let params = BitVmModel { 
    //         vicky: &VickyPlayer::new(
    //     "d898098e09898a0980989b980809809809f09809884324874302975287524398",
    //     &program,
    //     &data,
    //     vicky_pubkey(),
    // ), paul: &PaulPlayer::new(
    //     "d898098e09898a0980989b980809809809f09809884324874302975287524398",
    //     &program,
    //     &data,
    //     vicky_pubkey(),
    // ) 
    };
    let start = kick_off;
    let txid_hex = "2694698395179d1f3f7f862a439f0dbaca437f8e7238afbdbb7f2cc7418a82b2";
    let txid_bytes = Vec::from_hex(txid_hex).expect("Invalid hex string");
    let txid = Txid::from_slice(&txid_bytes).expect("Invalid Txid bytes");

    let outpoint = OutPoint { txid, vout: 0 };
    compile_graph(&params, &graph, start, outpoint);
}