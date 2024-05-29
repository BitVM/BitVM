#[allow(dead_code)]
// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use crate::execute_script;
    pub use bitcoin_script::{define_pushable, script};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

use core::fmt;

use bitcoin::{hashes::Hash, hex::DisplayHex, Opcode, TapLeafHash, Transaction};
use bitcoin_scriptexec::{Exec, ExecCtx, ExecError, ExecStats, Options, Stack, TxTemplate};
use utils::test_exec_error_transform;
use zulu_bitcoin_scriptexec::{
    Exec as Test_Exec, ExecCtx as Test_ExecCtx, Options as Test_Options, Stack as Test_Stack,
    TxTemplate as Test_TxTemplate,
};

pub mod bigint;
pub mod bn254;
pub mod bridge;
pub mod fflonk;
pub mod hash;
pub mod pseudo;
pub mod signatures;
pub mod u32;
pub mod u4;
pub mod utils;

/// A wrapper for the stack types to print them better.
pub struct FmtStack(Stack);
impl fmt::Display for FmtStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter_str().enumerate().peekable();
        write!(f, "\n0:\t\t ")?;
        while let Some((index, item)) = iter.next() {
            write!(f, "0x{:8}", item.as_hex())?;
            if iter.peek().is_some() {
                if (index + 1) % f.width().unwrap() == 0 {
                    write!(f, "\n{}:\t\t", index + 1)?;
                }
                write!(f, " ")?;
            }
        }
        Ok(())
    }
}

impl FmtStack {
    pub fn len(&self) -> usize { self.0.len() }

    pub fn get(&self, index: usize) -> Vec<u8> { self.0.get(index) }
}

impl fmt::Debug for FmtStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)?;
        Ok(())
    }
}

impl From<Test_Stack> for FmtStack {
    fn from(test_stack: Test_Stack) -> Self {
        let entries = test_stack.iter_str().map(|item| item).collect();
        FmtStack(Stack::from_u8_vec(entries))
    }
}

#[derive(Debug)]
pub struct ExecuteInfo {
    pub success: bool,
    pub error: Option<ExecError>,
    pub final_stack: FmtStack,
    pub remaining_script: String,
    pub last_opcode: Option<Opcode>,
    pub stats: ExecStats,
}

impl fmt::Display for ExecuteInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            writeln!(f, "Script execution successful.")?;
        } else {
            writeln!(f, "Script execution failed!")?;
        }
        if let Some(ref error) = self.error {
            writeln!(f, "Error: {:?}", error)?;
        }
        if self.remaining_script.len() > 0 {
            writeln!(f, "Remaining Script: {}", self.remaining_script)?;
        }
        if self.final_stack.len() > 0 {
            match f.width() {
                None => writeln!(f, "Final Stack: {:4}", self.final_stack)?,
                Some(width) => {
                    writeln!(f, "Final Stack: {:width$}", self.final_stack, width = width)?
                }
            }
        }
        if let Some(ref opcode) = self.last_opcode {
            writeln!(f, "Last Opcode: {:?}", opcode)?;
        }
        writeln!(f, "Stats: {:?}", self.stats)?;
        Ok(())
    }
}

pub fn execute_script(script: bitcoin::ScriptBuf) -> ExecuteInfo {
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
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats: exec.stats().clone(),
    }
}

// Execute a script on stack without `MAX_STACK_SIZE` limit.
// This function is only used for script test, not for production.
//
// NOTE: It's only for test purpose.
pub fn execute_script_no_stack_limit(script: bitcoin::ScriptBuf) -> ExecuteInfo {
    let mut exec = Test_Exec::new(
        Test_ExecCtx::Tapscript,
        Test_Options::default(),
        Test_TxTemplate {
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

    // collect execute info
    let stats_json = serde_json::to_string(exec.stats());
    let stats = if let Some(stats_str) = stats_json.ok() {
        serde_json::from_str(stats_str.as_str()).unwrap_or_default()
    } else {
        ExecStats::default()
    };
    ExecuteInfo {
        success: res.success,
        error: test_exec_error_transform(res.error.clone()),
        last_opcode: res.opcode,
        final_stack: exec.stack().clone().into(),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats,
    }
}

#[cfg(test)]
mod test {
    use crate::bn254;
    use crate::bn254::fp254impl::Fp254Impl;

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

    #[test]
    fn test_script_execute() {
        let script = script! {
            for i in 0..36 {
                { 0x0babe123 + i }
            }
        };
        let exec_result = execute_script(script);
        // The width decides how many stack elements are printed per row
        println!(
            "{:width$}",
            exec_result,
            width = bn254::fq::Fq::N_LIMBS as usize
        );
        println!("{:4}", exec_result);
        println!("{}", exec_result);
        assert!(!exec_result.success);
        assert_eq!(exec_result.error, None);
    }
}
