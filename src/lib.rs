// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use bitcoin_script::{define_pushable, script};
    pub use crate::execute_script;

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}
    
use bitcoin_scriptexec::{Exec, ExecCtx, ExecutionResult, Options, TxTemplate};
use bitcoin::{hashes::Hash, TapLeafHash, Transaction};
pub fn execute_script(script: bitcoin::ScriptBuf) -> ExecutionResult {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
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
        script,
        vec![],
    )
    .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    // if !res.success {
    //     println!(
    //         "Remaining script: {}",
    //         exec.remaining_script().to_asm_string()
    //     );
    //     // TODO: Print stack with hex values
    //     println!("Remaining stack: {:?}", exec.stack());
    //     println!("Last Opcode: {:?}", res.opcode);
    //     println!("StackSize: {:?}", exec.stack().len());
    //     println!("{:?}", res.clone().error.map(|e| format!("{:?}", e)));
    // }

    res.clone()
}

//pub mod treepp;
pub mod ubigint;
pub mod winternitz;
