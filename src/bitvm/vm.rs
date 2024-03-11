
use crate::utils::merkle::{buildTree, buildPath, verifyPath};

use crate::bitvm::constants::{
    ASM_ADD,
    ASM_SUB,
    ASM_MUL,
    ASM_AND,
    ASM_OR,
    ASM_XOR,
    ASM_ADDI,
    ASM_SUBI,
    ASM_ANDI,
    ASM_ORI,
    ASM_XORI,
    ASM_JMP,
    ASM_BEQ,
    ASM_BNE,
    ASM_RSHIFT1,
    ASM_SLTU,
    ASM_SLT,
    ASM_LOAD,
    ASM_STORE,
    ASM_SYSCALL,
    PATH_LEN,
};

#[derive(Copy, Clone)]
struct Instruction {
    asm_type : u8,
    addressA : u32,
    addressB : u32,
    addressC : u32,
}

struct Snapshot {
    pc: u32,
    memory: Vec<u32>,
    step_count: usize,
    instruction: Instruction,
}

struct MerklePath {
    path: Vec<[u8; 20]>,
    value: u32,
    address: u32
}

impl MerklePath {

    fn new(snapshot: &Snapshot, address: u32) -> Self {
        if address < 0 { panic!("ERROR: address={address} is negative") }
        Self {
            path: buildPath(&snapshot.memory, address),
            value: snapshot.read(address),
            address: address
        }
    }

    fn verifyUpTo(&self, height: usize) -> [u8; 20] {
        let mut subPath = self.path.clone();
        subPath.shrink_to(PATH_LEN - height);
        verifyPath(subPath, self.value, self.address)
    }

    fn getNode(&self, index: usize) -> [u8; 20] {
        self.path[PATH_LEN - 1 - index]
    }
}

impl Snapshot {

    fn new(memory: Vec<u32>, instruction: Instruction, pc: u32) -> Self {
        Self {
            pc: pc,
            memory: memory,
            step_count: 0,
            instruction: instruction,
        }
    }

    fn read(&self, address: u32) -> u32 {
        self.memory[address as usize]
    }

    fn write(&mut self, address: u32, value: u32) {
        if address >= self.memory.len() as u32 {
            self.memory.push(0);
        }
        self.memory[address as usize] = value;
        
    }
    
    fn path(&self, address: u32) -> MerklePath {
        MerklePath::new(self, address)
    }

    fn root(&self) -> [u8; 20] {
        buildTree(&self.memory)
    }
}

fn executeInstruction (snapshot: &mut Snapshot) {
    match (snapshot.instruction.asm_type) {
        ASM_ADD => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA).wrapping_add(snapshot.read(snapshot.instruction.addressB))
            );
            snapshot.pc += 1
        }
        ASM_SUB => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA).wrapping_sub(snapshot.read(snapshot.instruction.addressB))
            );
            snapshot.pc += 1
        }
        ASM_MUL => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA).wrapping_mul(snapshot.read(snapshot.instruction.addressB))
            );
            snapshot.pc += 1
        }
        ASM_AND => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) & snapshot.read(snapshot.instruction.addressB)
            );
            snapshot.pc += 1
        }
        ASM_OR => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) | snapshot.read(snapshot.instruction.addressB)
            );
            snapshot.pc += 1
        }
        ASM_XOR => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) ^ snapshot.read(snapshot.instruction.addressB)
            );
            snapshot.pc += 1
        }
        ASM_ADDI => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA).wrapping_add(snapshot.instruction.addressB)
            );
            snapshot.pc += 1
        }
        ASM_SUBI => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA).wrapping_sub(snapshot.instruction.addressB)
            );
            snapshot.pc += 1
        }
        ASM_ANDI => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) & snapshot.instruction.addressB
            );
            snapshot.pc += 1
        }
        ASM_ORI => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) | snapshot.instruction.addressB
            );
            snapshot.pc += 1
        }
        ASM_XORI => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) ^ snapshot.instruction.addressB
            );
            snapshot.pc += 1
        }
        ASM_BEQ => {
            if (snapshot.read(snapshot.instruction.addressA) == snapshot.read(snapshot.instruction.addressB)) {
                snapshot.pc = snapshot.instruction.addressC
            } else {
                snapshot.pc += 1
            }
        }
        ASM_BNE => {
            if (snapshot.read(snapshot.instruction.addressA) != snapshot.read(snapshot.instruction.addressB)) {
                snapshot.pc = snapshot.instruction.addressC
            } else {
                snapshot.pc += 1
            }
        }
        ASM_JMP => {
            snapshot.pc = snapshot.read(snapshot.instruction.addressA)
        }
        ASM_RSHIFT1 => {
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) >> 1
            );
            snapshot.pc += 1
        }
        ASM_SLTU => {
            snapshot.write(snapshot.instruction.addressC, if snapshot.read(snapshot.instruction.addressA) < snapshot.read(snapshot.instruction.addressB) { 1 } else { 0 });
            snapshot.pc += 1
        }            
        ASM_SLT => {
            snapshot.write(snapshot.instruction.addressC, if (snapshot.read(snapshot.instruction.addressA) as i32) < (snapshot.read(snapshot.instruction.addressB) as i32) { 1 } else { 0 });
            snapshot.pc += 1
        }
        ASM_LOAD => {
            snapshot.instruction.addressA = snapshot.read(snapshot.instruction.addressB);
            snapshot.write(snapshot.instruction.addressC, snapshot.read(snapshot.instruction.addressA));
            snapshot.pc += 1
        }
        ASM_STORE => {
            snapshot.instruction.addressC = snapshot.read(snapshot.instruction.addressB);
            snapshot.write(snapshot.instruction.addressC, snapshot.read(snapshot.instruction.addressA)); 
            snapshot.pc += 1
        }
        ASM_SYSCALL => {
            println!("syscall called");
            snapshot.pc += 1
        }
        _ => {
            snapshot.pc += 1
        }
    }
}

struct VM {
    program: Vec<Instruction>,
    memory_entries: Vec<u32>
}

impl VM {
    fn new(programSource: &[Instruction], memory_entries: &[u32]) -> Self {
        Self {
            program: programSource.into(),
            memory_entries: memory_entries.into(),
        }
    }

    fn run(&mut self, maxSteps: usize) -> Snapshot {
        let mut snapshot: Snapshot = Snapshot::new(self.memory_entries.clone(), self.program[0], 0);
        while (snapshot.pc < self.program.len() as u32 && snapshot.step_count + 1 < maxSteps) {
            snapshot.instruction = self.program[snapshot.pc as usize];
            executeInstruction(&mut snapshot);
            snapshot.step_count += 1;
        }
        snapshot
    }

}


#[cfg(test)]
mod tests {
    use crate::bitvm::constants::{
        ASM_ADD,
        ASM_BNE,
        TRACE_LEN
    };
    use crate::bitvm::vm::{
        Instruction,
        Snapshot,
        VM
    };

    // The program: Count up to some given number
    const DUMMY_PROGRAM: [Instruction; 2] = [
        Instruction {asm_type: ASM_ADD, addressA: 1, addressB: 0, addressC: 0}, // Increment value at address 0 by value at address 1
        Instruction {asm_type: ASM_BNE, addressA: 2, addressB: 0, addressC: 0}, // If value at address 0 and value at address 2 are not equal, jump 1 line backwards
    ];

    // The input data
    const DUMMY_DATA: [u32; 3] = [
        0,      // The initial value is 0
        1,      // The step size is 1
        10,     // We count up to 10
    ];

    #[test]
    fn execute_dummy_program() {
        let mut vm = VM::new(&DUMMY_PROGRAM, &DUMMY_DATA);
        vm.run(TRACE_LEN);
    }

    #[test]
    fn execute_ADD_instructions() {
        let addressA: u32 = 0;
        let valueA: u32 = 0xFFFFFFFB;
        let addressB: u32 = 1;
        let valueB: u32 = 7;
        let addressC: u32 = 2;
        let program = [Instruction {asm_type: ASM_ADD, addressA: addressA, addressB: addressB, addressC: addressC}];
        let data: [u32; 2] = [valueA, valueB];

        let mut vm: VM = VM::new(&program, &data);
        let snapshot: Snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let valueC = snapshot.read(addressC);
        assert_eq!(valueC, 2); 

        // Verify program counter
        let currPc = vm.run(0).pc;
        let nextPc = snapshot.pc;
        assert_eq!(nextPc, currPc + 1);
    }
}