use core::panic;
use std::ops::{Index, IndexMut};

use crate::utils::u160::u160;
use crate::utils::merkle::{build_path, build_tree, verify_path};

use crate::bitvm::constants::{
    ASM_ADD, ASM_ADDI, ASM_AND, ASM_ANDI, ASM_BEQ, ASM_BNE, ASM_JMP, ASM_LOAD, ASM_MUL, ASM_OR,
    ASM_ORI, ASM_RSHIFT1, ASM_SLT, ASM_SLTU, ASM_STORE, ASM_SUB, ASM_SUBI, ASM_SYSCALL, ASM_XOR,
    ASM_XORI, PATH_LEN,
};

pub type Instruction = (u8, u32, u32, u32);

pub struct Snapshot {
    pub pc: u32,
    pub memory: Vec<u32>,
    pub step_count: u32,
    pub instruction: Instruction,
}

pub struct MerklePath {
    pub path: Vec<u160>,
    pub value: u32,
    pub address: u32,
}

impl MerklePath {
    pub fn verify_up_to(&self, height: u8) -> u160 {
        let sub_path = &self.path[0..PATH_LEN - height as usize];
        verify_path(sub_path, self.value, self.address)
    }

    pub fn get_node(&self, index: u8) -> u160 {
        self.path[PATH_LEN - 1 - index as usize]
    }
}

impl Snapshot {
    fn new(memory: &[u32], instruction: Instruction, pc: u32) -> Self {
        Self {
            pc: pc + 0,
            memory: Vec::<u32>::from(memory),
            step_count: 0,
            instruction,
        }
    }

    pub fn path(&self, address: u32) -> MerklePath {
        MerklePath {
            path: build_path(&self.memory, address),
            value: self[address],
            address: address + 0
        }
    }

    pub fn root(&self) -> u160 {
        build_tree(&self.memory)
    }
}

impl Index<u32> for Snapshot {
    type Output = u32;
    fn index<'a>(&'a self, address: u32) -> &'a u32 {
        &self.memory[address as usize]
    }
}

impl IndexMut<u32> for Snapshot {
    fn index_mut<'a>(&'a mut self, address: u32) -> &'a mut u32 {
        while address >= self.memory.len() as u32 {
            self.memory.push(0);
        }
        &mut self.memory[address as usize]
    }
}

fn execute_instruction(mem: &mut Snapshot) {
    let (asm_type, address_a, address_b, address_c) = mem.instruction;
    mem.pc = match asm_type {
        ASM_ADD => { mem[address_c] = mem[address_a].wrapping_add(mem[address_b]); mem.pc + 1 }
        ASM_SUB => { mem[address_c] = mem[address_a].wrapping_sub(mem[address_b]); mem.pc + 1 }
        ASM_MUL => { mem[address_c] = mem[address_a].wrapping_mul(mem[address_b]); mem.pc + 1 }
        ASM_AND => { mem[address_c] = mem[address_a] & mem[address_b]; mem.pc + 1 }
        ASM_OR => { mem[address_c] = mem[address_a] | mem[address_b]; mem.pc + 1 }
        ASM_XOR => { mem[address_c] = mem[address_a] ^ mem[address_b]; mem.pc + 1 }
        ASM_ADDI => { mem[address_c] = mem[address_a].wrapping_add(address_b); mem.pc + 1 }
        ASM_SUBI => { mem[address_c] = mem[address_a].wrapping_sub(address_b); mem.pc + 1 }
        ASM_ANDI => { mem[address_c] = mem[address_a] & address_b; mem.pc + 1 }
        ASM_ORI => { mem[address_c] = mem[address_a] | address_b; mem.pc + 1 }
        ASM_XORI => { mem[address_c] = mem[address_a] ^ address_b; mem.pc + 1 }
        ASM_BEQ => { match mem[address_a] == mem[address_b] { true => address_c, _ => mem.pc + 1 } }
        ASM_BNE => { match mem[address_a] != mem[address_b] { true => address_c, _ => mem.pc + 1 } }
        ASM_JMP => mem[address_a],
        ASM_RSHIFT1 => { mem[address_c] = mem[address_a] >> 1; mem.pc + 1 }
        ASM_SLTU => { mem[address_c] = (mem[address_a] < mem[address_b]) as u32; mem.pc + 1 }
        ASM_SLT => { mem[address_c] = ((mem[address_a] as i32) < (mem[address_b] as i32)) as u32; mem.pc + 1 }
        ASM_LOAD => { mem.instruction.1 = mem[address_b]; mem[address_c] = mem[mem[address_a]]; mem.pc + 1 }
        ASM_STORE => { let address = mem[address_b]; mem[address] = mem[address_a]; mem.instruction.3 = address; mem.pc + 1 }
        ASM_SYSCALL => { println!("syscall called"); mem.pc + 1 }
        _ => panic!("Unknown instuction type {}", asm_type),
    }
}

pub struct VM {
    program: Vec<Instruction>,
    memory_entries: Vec<u32>,
}

impl VM {
    pub fn new<const N: usize, const M: usize>(program_source: [Instruction; N], memory_entries: [u32; M]) -> Self {
        Self {
            program: Vec::<Instruction>::from(program_source),
            memory_entries: Vec::<u32>::from(memory_entries)
        }
    }

    pub fn run(&self, max_steps: u32) -> Snapshot {
        let mut mem: Snapshot = Snapshot::new(&self.memory_entries, self.program[0], 0);
        while mem.pc < self.program.len() as u32 && mem.step_count + 1 < max_steps {
            mem.instruction = self.program[mem.pc as usize];
            execute_instruction(&mut mem);
            mem.step_count += 1;
        }
        mem
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//
#[cfg(test)]
mod tests {
    use crate::bitvm::constants::{
        ASM_ADD,
        ASM_SUB,
        ASM_AND,
        ASM_OR,
        ASM_XOR,
        ASM_ADDI,
        ASM_SUBI,
        ASM_ANDI,
        ASM_ORI,
        ASM_XORI,
        ASM_BEQ,
        ASM_BNE,
        ASM_RSHIFT1,
        ASM_SLTU,
        ASM_SLT,
        ASM_LOAD,
        ASM_STORE,
        TRACE_LEN,
    };
    use super::{Instruction, Snapshot, VM};

    // The program: Count up to some given number
    const DUMMY_PROGRAM: [Instruction; 2] = [
        ( ASM_ADD, 1, 0, 0 ), // Increment value at address 0 by value at address 1
        ( ASM_BNE, 2, 0, 0 ), // If value at address 0 and value at address 2 are not equal, jump 1 line backwards
    ];

    // The input data
    const DUMMY_DATA: [u32; 3] = [
        0,  // The initial value is 0
        1,  // The step size is 1
        10, // We count up to 10
    ];

    #[test]
    fn execute_dummy_program() {
        VM::new(DUMMY_PROGRAM, DUMMY_DATA).run(TRACE_LEN);
    }

    #[test]
    fn execute_add_instructions() {
        let program = [(ASM_ADD, 0, 1, 2)];
        let data: [u32; 2] = [0xFFFFFFFB, 7];

        let vm: VM = VM::new(program, data);
        let mem: Snapshot = vm.run(TRACE_LEN as u32);

        // Verify result
        assert_eq!(mem[2], 2);

        // Verify program counter
        assert_eq!(mem.pc, vm.run(0).pc + 1);
    }

    #[test]
    fn execute_sub_instructions() {
        let program = [(ASM_SUB, 0, 1, 2)];
        let data = [ 0xFFFFFFFD, 0xFFFFFFFB ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        assert_eq!(mem[2], 2);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // "negative" result
    fn execute_sub_instructions_2() {
        let address_c = 2;
        let program = [( ASM_SUB, 0, 1, address_c )];
        let data = [ 3, 5 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0xFFFFFFFE);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_and_instructions() {
        let address_c = 2;
        let program = [( ASM_AND, 0, 1, address_c )];
        let data = [ 0b1100, 0b0101 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);

        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0b0100); 

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_or_instructions() {
        let address_c = 2;
        let program = [( ASM_OR, 0, 1, address_c )];
        let data = [ 0b1100, 0b0101 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);

        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0b1101);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_xor_instructions() {
        let address_c = 2;
        let program = [( ASM_XOR, 0, 1, address_c )];
        let data = [ 0b1100, 0b0101 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);

        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0b1001); 

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_addi_instructions() {
        let address_c = 1;
        let program = [( ASM_ADDI, 0, 7, address_c )];
        let data = [ 0 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 2) ;

        // Verify program counter
        assert_eq!(mem.pc, vm.run(0).pc + 1);
    }

    #[test]
    fn execute_subi_instructions() {
        let address_c = 2;
        let program = [( ASM_SUBI, 0, 43, address_c )];
        let data = [ 0 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0xFFFFFFFF);

        // Verify program counter
        assert_eq!(mem.pc, vm.run(0).pc + 1);
    }

    #[test]
    fn execute_andi_instructions() {
        let address_c = 2;
        let program = [( ASM_ANDI, 0, 0b0101, address_c )];
        let data = [ 0b1100 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);

        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0b0100);

        // Verify program counter
        assert_eq!(mem.pc, vm.run(0).pc + 1);
    }

    #[test]
    fn execute_ori_instructions() {
        let address_c = 2;
        let program = [( ASM_ORI, 0, 0b0101, 2 )];
        let data = [ 0b1100 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);

        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0b1101);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_xori_instructions() {
        let address_c = 2;
        let program = [( ASM_XORI, 0, 0b0101, address_c )];
        let data = [ 0b1100 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);

        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0b1001);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Case: True
    fn execute_beq_instructions() {
        let address_c = 210;
        let program = [( ASM_BEQ, 0, 1, address_c )];
        let data = [ 42, 42 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify next program counter is address_c
        let next_pc = mem.pc;
        assert_eq!(next_pc, address_c);
    }

    #[test] // Case: False
    fn execute_beq_instructions_2() {
        let program = [( ASM_BEQ, 0, 1, 210 )];
        let data = [ 42, 43 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify next program counter is curr_pc + 1
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }


    #[test] // Case: True
    fn execute_bne_instructions() {
        let address_c = 210;
        let program = [( ASM_BNE, 0, 1, address_c )];
        let data = [ 42, 43 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify next program counter is address_c
        let next_pc = mem.pc;
        assert_eq!(next_pc, address_c);
    }


    #[test] // Case: False
    fn execute_bne_instructions_2() {
        let program = [( ASM_BNE, 0, 1, 210 )];
        let data = [ 42, 42 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify next program counter is curr_pc + 1
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_rshift1_instructions() {
        let address_c = 1;
        let program = [( ASM_RSHIFT1, 0, 0, address_c )];
        let data = [ 0b1100 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c, 0b0110);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Result: 1
    fn execute_sltu_instructions() {
        let address_c = 2;
        let program = [( ASM_SLTU, 0, 1, address_c )];
        let data = [ 0xFFFFFFFE, 0xFFFFFFFF ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c,  1 ) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Result: 0
    fn execute_sltu_instructions_2() {
        let address_c = 2;
        let program = [( ASM_SLTU, 0, 1, address_c )];
        let data = [ 0xFFFFFFFF, 0xFFFFFFFE ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c,  0);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Result: 1
    fn execute_slt_instructions() {
        let address_c = 2;
        let program = [( ASM_SLT, 0, 1, address_c )];
        let data = [ 0xFFFFFFF9, 0x00000001 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c,  1 ) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = mem.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Result: 0
    fn execute_slt_instructions_2() {
        let address_c = 2;
        let program = [( ASM_SLT, 0, 1, address_c )];
        let data = [ /* -5 */ 0xFFFFFFFB, /* -7 */ 0xFFFFFFF9 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = mem[address_c];
        assert_eq!(value_c,  0);

        // Verify program counter
        assert_eq!(mem.pc, vm.run(0).pc + 1);
    }

    #[test]
    fn execute_load_instructions() {
        // address_a is figured out at runtime from value_b -> address_a == value_b
        // value_a is loaded
        // Specifies where the address is stored
        let value_b = 17;
        let address_c = 1;
        let program = [( ASM_LOAD, 0, 0, address_c )];
        let data = [ value_b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x89ABCDEF ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify result
        assert_eq!(mem[address_c], 0x89ABCDEF);
        
        // Verify that the instruction correctly sets address_a
        assert_eq!(mem.instruction.1, value_b);

        // Verify program counter
        assert_eq!(mem.pc, vm.run(0).pc + 1);
    }
    
    #[test]
    fn execute_store_instructions() {
        // address_c is figured out at runtime from value_b -> address_c == value_b
        // value_a is stored
        // Specifies where the address is stored
        let program = [( ASM_STORE, 0, 1, 0 )];
        let data = [ 0x89ABCDEF, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);
        
        // Verify that the instruction correctly sets address_c
        let address_c = mem.instruction.3;
        assert_eq!(address_c,  17);

        // Verify result
        assert_eq!(mem[address_c],  0x89ABCDEF) ;

        // Verify program counter
        assert_eq!(mem.pc, vm.run(0).pc + 1);
    }


    #[test]
    fn merklize_its_memory() {
        let program = [(ASM_ADD, /* TODO: set this to some random address, e.g., 42 */ 1, 0, 2)];
        let data = [ 42, 43 ];

        let vm = VM::new(program, data);
        let mem = vm.run(TRACE_LEN);

        let path_root = mem.path(1).verify_up_to(0);

        assert_eq!(path_root, mem.root());
    }
}
