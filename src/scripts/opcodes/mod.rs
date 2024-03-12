use bitcoin::{hashes::Hash, TapLeafHash, Transaction};
use bitcoin_script::define_pushable;
use bitcoin_scriptexec::{Exec, ExecCtx, ExecutionResult, Options, TxTemplate};

pub mod blake3;
pub mod pseudo;
pub mod u160_std;
pub mod u256_std;
pub mod u32_add;
pub mod u32_and;
pub mod u32_cmp;
pub mod u32_or;
pub mod u32_rrot;
pub mod u32_state;
pub mod u32_std;
pub mod u32_sub;
pub mod u32_xor;
pub mod u32_zip;

define_pushable!();

pub fn unroll<F, T>(count: u32, mut closure: F) -> Vec<T>
where
    F: FnMut(u32) -> T,
    T: pushable::Pushable,
{
    let mut result = vec![];

    for i in 0..count {
        result.push(closure(i))
    }
    result
}

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
    if !res.success {
        println!(
            "Remaining script: {}",
            exec.remaining_script().to_asm_string()
        );
        // TODO: Print stack with hex values
        println!("Remaining stack: {:?}", exec.stack());
        println!("Last Opcode: {:?}", res.opcode);
        println!("StackSize: {:?}", exec.stack().len());
        println!("{:?}", res.clone().error.map(|e| format!("{:?}", e)));
    }

    res.clone()
}
