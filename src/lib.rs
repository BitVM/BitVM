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
use bitcoin::script::Instruction;
use bitcoin_scriptexec::{Exec, ExecCtx, ExecError, ExecStats, Options, Stack, TxTemplate};

pub mod bigint;
pub mod bn254;
pub mod signatures;
// pub mod graph;
pub mod fflonk;
pub mod hash;
pub mod pseudo;
pub mod u32;

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
    check_code_optimize(&script);

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

pub fn check_code_optimize(script: &bitcoin::ScriptBuf) {
    use bitcoin::opcodes::all::*;

    let script = crate::treepp::Script::from(script.clone());
    let instructions_iter = script.instructions();

    let mut last_instruction = None;
    for instruction in instructions_iter {
        let instruction = instruction.expect("error interpreting the script");

        match instruction {
            Instruction::PushBytes(_) => {
                last_instruction = None;
            }
            Instruction::Op(opcode) => {
                let mut next_instruction = Some(opcode);
                if opcode == OP_ADD {
                    if Some(OP_PUSHNUM_1) == last_instruction {
                        eprintln!("Script can be optimized: 1 OP_ADD => OP_1ADD");
                        next_instruction = None;
                    }
                }
                if opcode == OP_SUB {
                    if Some(OP_PUSHNUM_1) == last_instruction {
                        eprintln!("Script can be optimized: 1 OP_SUB => OP_1SUB");
                        next_instruction = None;
                    }
                }
                if opcode == OP_DROP {
                    if Some(OP_DROP) == last_instruction {
                        eprintln!("Script can be optimized: OP_DROP OP_DROP => OP_2DROP");
                        next_instruction = None;
                    }
                }
                if opcode == OP_ROLL {
                    if Some(OP_PUSHBYTES_0) == last_instruction {
                        eprintln!("Script can be optimized: 0 OP_ROLL => ");
                        next_instruction = None;
                    }
                    if Some(OP_PUSHNUM_1) == last_instruction {
                        eprintln!("Script can be optimized: 1 OP_ROLL => OP_SWAP");
                        next_instruction = None;
                    }
                    if Some(OP_PUSHNUM_2) == last_instruction {
                        eprintln!("Script can be optimized: 2 OP_ROLL => OP_ROT");
                        next_instruction = None;
                    }
                }
                if opcode == OP_PICK {
                    if Some(OP_PUSHBYTES_0) == last_instruction {
                        eprintln!("Script can be optimized: 0 OP_PICK => OP_DUP");
                        next_instruction = None;
                    }
                    if Some(OP_PUSHNUM_1) == last_instruction {
                        eprintln!("Script can be optimized: 1 OP_PICK => OP_OVER");
                        next_instruction = None;
                    }
                }
                if opcode == OP_ELSE {
                    if Some(OP_IF) == last_instruction {
                        eprintln!("Script can be optimized: OP_IF OP_ELSE => OP_NOTIF");
                        next_instruction = None;
                    }
                }

                last_instruction = next_instruction;
            }
        }
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
