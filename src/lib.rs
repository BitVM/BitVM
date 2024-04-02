#[allow(dead_code)]
// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use crate::execute_script;
    pub use bitcoin_script::{define_pushable, script};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

use core::fmt;

use bitcoin::{hashes::Hash, hex::DisplayHex, TapLeafHash, Transaction};
use bitcoin_scriptexec::{Exec, ExecCtx, ExecutionResult, Options, TxTemplate};

pub mod bigint;
pub mod bn254;
pub mod signatures;
// pub mod graph;

/// A wrapper for the stack types to print them better.
struct FmtStack<'a>(&'a Vec<Vec<u8>>);
impl<'a> fmt::Display for FmtStack<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter().enumerate().peekable();
        write!(f, "\n0:\t\t ")?;
        while let Some((index, item)) = iter.next() {
            write!(f, "0x{:8}", item.as_hex())?;
            if iter.peek().is_some() {
                if (index + 1) % 4 == 0 {
                    write!(f, "\n{}:\t\t", index + 1)?;
                }
                write!(f, " ")?;
            }
        }
        Ok(())
    }
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
    //if !res.success {
    //    println!(
    //        "Remaining script: {}",
    //        exec.remaining_script().to_asm_string()
    //    );
    //
    //    println!("Remaining stack: {}", FmtStack(exec.stack()));
    //    println!("Last Opcode: {:?}", res.opcode);
    //    println!("StackSize: {:?}", exec.stack().len());
    //    println!("{:?}", res.clone().error.map(|e| format!("{:?}", e)));
    //}

    res.clone()
}

#[cfg(test)]
mod test {
    use super::treepp::*;

    #[test]
    fn test_script_debug() {
        let script = script! {
            OP_TRUE
            DEBUG
            OP_TRUE
            OP_VERIFY
        };
        let exec_result = execute_script(script);
        assert!(!exec_result.success);
    }
}
