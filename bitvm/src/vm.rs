use core::panic;

use crate::merkle::tree::{build_path, build_tree, verify_path};

use crate::constants::{
    ASM_ADD, ASM_ADDI, ASM_AND, ASM_ANDI, ASM_BEQ, ASM_BNE, ASM_JMP, ASM_LOAD, ASM_MUL, ASM_OR,
    ASM_ORI, ASM_RSHIFT1, ASM_SLT, ASM_SLTU, ASM_STORE, ASM_SUB, ASM_SUBI, ASM_SYSCALL, ASM_XOR,
    ASM_XORI, PATH_LEN,
};

#[derive(Copy, Clone)]
pub struct Instruction {
    pub asm_type: u8,
    pub address_a: u32,
    pub address_b: u32,
    pub address_c: u32,
}

pub struct Snapshot {
    pub pc: u32,
    pub memory: Vec<u32>,
    pub step_count: usize,
    pub instruction: Instruction,
}

pub struct MerklePath {
    pub path: Vec<[u8; 20]>,
    pub value: u32,
    pub address: u32,
}

impl MerklePath {
    fn new(snapshot: &Snapshot, address: u32) -> Self {
        Self {
            path: build_path(&snapshot.memory, address),
            value: snapshot.read(address),
            address,
        }
    }

    pub fn verify_up_to(&self, height: usize) -> [u8; 20] {
        let mut sub_path = self.path.clone();
        sub_path.shrink_to(PATH_LEN - height);
        verify_path(sub_path, self.value, self.address)
    }

    pub fn get_node(&self, index: usize) -> [u8; 20] {
        self.path[PATH_LEN - 1 - index]
    }
}

impl Snapshot {
    fn new(memory: Vec<u32>, instruction: Instruction, pc: u32) -> Self {
        Self {
            pc,
            memory,
            step_count: 0,
            instruction,
        }
    }

    pub fn read(&self, address: u32) -> u32 {
        self.memory[address as usize]
    }

    fn write(&mut self, address: u32, value: u32) {
        while address >= self.memory.len() as u32 {
            self.memory.push(0);
        }
        self.memory[address as usize] = value;
    }

    pub fn path(&self, address: u32) -> MerklePath {
        MerklePath::new(self, address)
    }

    pub fn root(&self) -> [u8; 20] {
        build_tree(&self.memory)
    }
}

fn execute_instruction(s: &mut Snapshot) {
    match s.instruction.asm_type {
        ASM_ADD => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a)
                    .wrapping_add(s.read(s.instruction.address_b)),
            );
            s.pc += 1
        }
        ASM_SUB => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a)
                    .wrapping_sub(s.read(s.instruction.address_b)),
            );
            s.pc += 1
        }
        ASM_MUL => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a)
                    .wrapping_mul(s.read(s.instruction.address_b)),
            );
            s.pc += 1
        }
        ASM_AND => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a) & s.read(s.instruction.address_b),
            );
            s.pc += 1
        }
        ASM_OR => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a) | s.read(s.instruction.address_b),
            );
            s.pc += 1
        }
        ASM_XOR => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a) ^ s.read(s.instruction.address_b),
            );
            s.pc += 1
        }
        ASM_ADDI => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a)
                    .wrapping_add(s.instruction.address_b),
            );
            s.pc += 1
        }
        ASM_SUBI => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a)
                    .wrapping_sub(s.instruction.address_b),
            );
            s.pc += 1
        }
        ASM_ANDI => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a) & s.instruction.address_b,
            );
            s.pc += 1
        }
        ASM_ORI => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a) | s.instruction.address_b,
            );
            s.pc += 1
        }
        ASM_XORI => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a) ^ s.instruction.address_b,
            );
            s.pc += 1
        }
        ASM_BEQ => {
            if s.read(s.instruction.address_a) == s.read(s.instruction.address_b) {
                s.pc = s.instruction.address_c
            } else {
                s.pc += 1
            }
        }
        ASM_BNE => {
            if s.read(s.instruction.address_a) != s.read(s.instruction.address_b) {
                s.pc = s.instruction.address_c
            } else {
                s.pc += 1
            }
        }
        ASM_JMP => s.pc = s.read(s.instruction.address_a),
        ASM_RSHIFT1 => {
            s.write(
                s.instruction.address_c,
                s.read(s.instruction.address_a) >> 1,
            );
            s.pc += 1
        }
        ASM_SLTU => {
            s.write(
                s.instruction.address_c,
                if s.read(s.instruction.address_a) < s.read(s.instruction.address_b) {
                    1
                } else {
                    0
                },
            );
            s.pc += 1
        }
        ASM_SLT => {
            s.write(
                s.instruction.address_c,
                if (s.read(s.instruction.address_a) as i32)
                    < (s.read(s.instruction.address_b) as i32)
                {
                    1
                } else {
                    0
                },
            );
            s.pc += 1
        }
        ASM_LOAD => {
            s.instruction.address_a = s.read(s.instruction.address_b);
            s.write(s.instruction.address_c, s.read(s.instruction.address_a));
            s.pc += 1
        }
        ASM_STORE => {
            s.instruction.address_c = s.read(s.instruction.address_b);
            s.write(s.instruction.address_c, s.read(s.instruction.address_a));
            s.pc += 1
        }
        ASM_SYSCALL => {
            println!("syscall called");
            s.pc += 1
        }
        _ => panic!("Unknown instuction type {}", s.instruction.asm_type),
    }
}

pub struct VM {
    program: Vec<Instruction>,
    memory_entries: Vec<u32>,
}

impl VM {
    pub fn new(program_source: &[Instruction], memory_entries: &[u32]) -> Self {
        Self {
            program: program_source.into(),
            memory_entries: memory_entries.into(),
        }
    }

    pub fn run(&self, max_steps: usize) -> Snapshot {
        let mut snapshot: Snapshot = Snapshot::new(self.memory_entries.clone(), self.program[0], 0);
        while snapshot.pc < self.program.len() as u32 && snapshot.step_count + 1 < max_steps {
            snapshot.instruction = self.program[snapshot.pc as usize];
            execute_instruction(&mut snapshot);
            snapshot.step_count += 1;
        }
        snapshot
    }
}
