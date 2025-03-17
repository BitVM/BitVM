use crate::treepp::*;
use bitcoin::Witness;

use bitcoin::{hashes::Hash, ScriptBuf, TapLeafHash, Transaction};
use bitcoin_scriptexec::{Exec, ExecCtx, TxTemplate};

pub fn roll_constant(d: usize) -> Script {
    script! {
        if d == 0 {

        } else if d == 1 {
            OP_SWAP
        } else if d == 2 {
            OP_ROT
        } else {
            { d } OP_ROLL
        }
    }
}

pub fn extend_witness(w: &mut Witness, add: Witness) {
    for x in &add {
        w.push(x)
    }
}

pub fn does_unlock(script: Vec<u8>, witness: Vec<Vec<u8>>) -> bool {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Default::default(),
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        ScriptBuf::from_bytes(script),
        witness,
    )
    .expect("error creating exec");
    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    exec.result().unwrap().success
}
