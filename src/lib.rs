#[allow(dead_code)]
// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use crate::execute_script;
    pub use crate::run;
    pub use bitcoin_script::{script, Script};
}

use core::fmt;
use std::{cmp::min, fs::File, io::Write};

use bitcoin::{hashes::Hash, hex::DisplayHex, Opcode, ScriptBuf, TapLeafHash, Transaction};
use bitcoin_scriptexec::{Exec, ExecCtx, ExecError, ExecStats, Options, Stack, TxTemplate};

pub mod bigint;
pub mod bn254;
pub mod bridge;
pub mod fflonk;
pub mod groth16;
pub mod hash;
pub mod pseudo;
pub mod signatures;
pub mod u32;
pub mod u4;

/// A wrapper for the stack types to print them better.
pub struct FmtStack(Stack);
impl fmt::Display for FmtStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter_str().enumerate().peekable();
        write!(f, "\n0:\t\t ")?;
        while let Some((index, mut item)) = iter.next() {
            if item.is_empty() {
                write!(f, "    []    ")?;
            } else {
            item.reverse();
            write!(f, "0x{:8}", item.as_hex())?;
            }
            if iter.peek().is_some() {
                if (index + 1) % f.width().unwrap_or(4) == 0 {
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
        if !self.remaining_script.is_empty() {
            if self.remaining_script.len() < 500 {
                writeln!(f, "Remaining Script: {}", self.remaining_script)?;
            } else {
                let mut string = self.remaining_script.clone();
                string.truncate(500);
                writeln!(f, "Remaining Script: {}...", string)?;
            }
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

pub fn execute_script(script: treepp::Script) -> ExecuteInfo {
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
        script.compile(),
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

pub fn run(script: treepp::Script) {
    let stack = script.clone().analyze_stack();
    if !stack.is_valid_final_state_without_inputs() {
        println!("Stack analysis does not end in valid state: {:?}", stack);
        assert!(false);
    }
    let exec_result = execute_script(script);
    if !exec_result.success {
        println!(
            "ERROR: {:?} <--- \n STACK: {:4} ",
            exec_result.last_opcode, exec_result.final_stack
        );
    }
    println!("Max_stack_items = {}", exec_result.stats.max_nb_stack_items);
    assert!(exec_result.success);
}

pub fn run_as_chunks(script: treepp::Script, chunk_size: usize, stack_limit: usize) {
    let exec_result = execute_script_as_chunks(script, chunk_size, stack_limit);
    if !exec_result.success {
        println!(
            "ERROR: {:?} <--- \n STACK: {:9} ",
            exec_result.last_opcode, exec_result.final_stack
        );
    }
    assert!(exec_result.success);
}

// Execute a script on stack without `MAX_STACK_SIZE` limit.
// This function is only used for script test, not for production.
//
// NOTE: Only for test purposes.
pub fn execute_script_without_stack_limit(script: treepp::Script) -> ExecuteInfo {
    // Get the default options for the script exec.
    let mut opts = Options::default();
    // Do not enforce the stack limit.
    opts.enforce_stack_limit = false;

    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        opts,
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
        script.compile(),
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

// TODO: Use signatures to copy over the stack from one chunk to the next.
pub fn execute_script_as_chunks(
    script: treepp::Script,
    target_chunk_size: usize,
    stack_limit: usize,
) -> ExecuteInfo {
    let (chunk_sizes, scripts) = script
        .clone()
        .compile_to_chunks(target_chunk_size, stack_limit);
    // TODO: Remove this when we are sure we are in script size limit for groth16
    // Get the default options for the script exec.
    let mut opts = Options::default();
    // Do not enforce the stack limit.
    opts.enforce_stack_limit = false;

    assert!(scripts.len() > 0, "No chunks to execute");
    let mut stats_file = File::create("chunk_runtime.txt").expect("Unable to create stats file");
    writeln!(stats_file, "chunk sizes: {:?}", chunk_sizes).expect("Unable to write to stats file");
    let num_chunks = scripts.len();
    let mut scripts = scripts.into_iter().peekable();
    let mut final_exec = None; // Only used to not initialize an obsolote Exec
    let mut next_stack = Stack::new();
    let mut next_altstack = Stack::new();
    let mut chunk_stacks = vec![];

    // Execute each chunk and copy over the stacks
    for i in 0..num_chunks {
        // Note: Exec::with_stack() currently overwrites the witness!
        let mut exec = Exec::with_stack(
            ExecCtx::Tapscript,
            opts.clone(),
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
            scripts.next().unwrap_or_else(|| unreachable!()),
            vec![], // Note: If you put a witness here make sure to adjust
                                    // Exec::with_stack() to not overwrite it!
            next_stack.clone(),
            next_altstack.clone(),
        )
        .expect("Failed to create Exec");
        
        // Execute the current chunk.
        while exec.exec_next().is_ok() {
        }

        if exec.result().unwrap().error.is_some() {
            let res = exec.result().unwrap();
            println!("Exec errored in chunk {}", i);
            return ExecuteInfo {
                success: res.success,
                error: res.error.clone(),
                last_opcode: res.opcode,
                final_stack: FmtStack(exec.stack().clone()),
                remaining_script: exec.remaining_script().to_asm_string(),
                stats: exec.stats().clone(),
            }
        };

        chunk_stacks.push(exec.stack().len() + exec.altstack().len());
        // Copy over the stack for next iteration.
        // TODO: Take the stack snapshot at the end of the chunk logic (before the stack is hashed and
        // then dropped) BUT AFTER THE ALSTACK IS MOVED TO STACK
        next_stack = exec.stack().clone();
        // TODO: altstack should be empty
        // TODO: Next altstack is generated from the stack entries
        next_altstack = exec.altstack().clone();
        final_exec = Some(exec);
    }
    let final_exec = final_exec.unwrap_or_else(|| unreachable!());
    let res = final_exec.result().unwrap();
    writeln!(stats_file,
        "intermediate stack transfer sizes: {:?}",
        chunk_stacks[0..chunk_stacks.len() - 1].to_vec()
    ).expect("Unable to write into stats_file");
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(final_exec.stack().clone()),
        remaining_script: final_exec.remaining_script().to_asm_string(),
        stats: final_exec.stats().clone(),
    }
}


pub fn execute_script_as_chunks_vs_normal(
    script: treepp::Script,
    target_chunk_size: usize,
    tolerance: usize,
) -> ExecuteInfo {
    let (chunk_sizes, scripts) = script
        .clone()
        .compile_to_chunks(target_chunk_size, tolerance);
    let compiled_script = script.compile();
    let mut total_script = vec![];
    for script in &scripts {
        total_script.extend(script.clone().into_bytes());
    }
    println!("chunk sizes: {:?}", chunk_sizes);
    
    for i in 0..min(compiled_script.len(), total_script.len()) {
        assert_eq!(compiled_script.as_bytes()[i], total_script[i], "Incorrect at position {}: compiled: {} total: {}", i, compiled_script.as_bytes()[i], total_script[i]);
    }
    //assert!(
    //    compiled_script.as_bytes() == total_script,
    //    "Total chunk script is not same as compiled script {:?}, {:?}", compiled_script.len(), total_script.len()
    //);

    assert!(scripts.len() > 0, "No chunks to execute");
    let num_chunks = scripts.len();
    let mut scripts = scripts.into_iter();
    let mut final_exec = None; // Only used to not initialize an obsolote Exec
    let mut next_stack = Stack::new();
    let mut next_altstack = Stack::new();
    let mut chunk_stacks = vec![];
    let mut compiled_exec = Exec::new(
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
        compiled_script,
        vec![], // Note: If you put a witness here make sure to adjust
                // Exec::with_stack() to not overwrite it!
    )
    .expect("Failed to create Exec");

    // Execute each chunk and copy over the stacks
    for i in 0..num_chunks {
        // Note: Exec::with_stack() currently overwrites the witness!
        let mut exec = Exec::with_stack(
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
            scripts.next().unwrap_or_else(|| unreachable!()),
            vec![], // Note: If you put a witness here make sure to adjust
            // Exec::with_stack() to not overwrite it!
            next_stack.clone(),
            next_altstack.clone(),
        )
        .expect("Failed to create Exec");

        // Execute the current chunk.
        while exec.exec_next().is_ok() {
            // Execute the compiled script in parallel.
            if compiled_exec.exec_next().is_err() {
                println!("compiled_exec error: {:?}", compiled_exec.result());
                panic!("Errored with compiled_exec");
            }
            assert_eq!(
                exec.stack(),
                compiled_exec.stack(),
                "Stack not equal to compiled_exec {:?}\n{:?} \n -- in chunk: {}",
                compiled_exec.stats(),
                exec.stats(),
                i
            );
            assert_eq!(
                exec.altstack(),
                compiled_exec.altstack(),
                "Altstack not equal to compiled_exec {:?}\n{:?}",
                compiled_exec.stats(),
                exec.stats()
            );
        }

        if exec.result().unwrap().error.is_some() {
            let res = exec.result().unwrap();
            println!("Exec errored in chunk {}", i);
            println!(
                "intermediate stack transfer sizes: {:?}",
                chunk_stacks[0..chunk_stacks.len() - 1].to_vec()
            );
            return ExecuteInfo {
                success: res.success,
                error: res.error.clone(),
                last_opcode: res.opcode,
                final_stack: FmtStack(exec.stack().clone()),
                remaining_script: exec.remaining_script().to_asm_string(),
                stats: exec.stats().clone(),
            }
        };

        chunk_stacks.push(exec.stack().len() + exec.altstack().len());
        // Copy over the stack for next iteration.
        next_stack = exec.stack().clone();
        next_altstack = exec.altstack().clone();
        final_exec = Some(exec);
    }
    let final_exec = final_exec.unwrap_or_else(|| unreachable!());
    let res = final_exec.result().unwrap();
    println!(
        "intermediate stack transfer sizes: {:?}",
        chunk_stacks[0..chunk_stacks.len() - 1].to_vec()
    );
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(final_exec.stack().clone()),
        remaining_script: final_exec.remaining_script().to_asm_string(),
        stats: final_exec.stats().clone(),
    }
}

#[cfg(test)]
mod test {
    use crate::bn254;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::execute_script_as_chunks;

    use super::execute_script_without_stack_limit;
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

    #[test]
    fn test_execute_script_without_stack_limit() {
        let script = script! {
            for _ in 0..1001 {
                OP_1
            }
            for _ in 0..1001 {
                OP_DROP
            }
            OP_1
        };
        let exec_result = execute_script_without_stack_limit(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_execute_script_as_chunks() {
        let sub_script = script! {
            OP_1
            OP_1
        };
        let sub_script_2 = script! {
            OP_DROP
            OP_DROP
        };

        let script = script! {
            { sub_script.clone() }
            { sub_script.clone() }
            { sub_script.clone() }
            { sub_script.clone() }
            { sub_script_2.clone() }
            { sub_script_2.clone() }
            { sub_script_2.clone() }
            { sub_script_2.clone() }
            OP_1
        };
        let exec_result = execute_script_as_chunks(script, 2, 1000);
        println!("{:?}", exec_result);
        assert!(exec_result.success);
    }
}
