#[cfg(test)]
mod vm_tests {
    use bitvm::constants::{
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
    use bitvm::vm::{Instruction, Snapshot, VM};

    // The program: Count up to some given number
    const DUMMY_PROGRAM: [Instruction; 2] = [
        Instruction {
            asm_type: ASM_ADD,
            address_a: 1,
            address_b: 0,
            address_c: 0,
        }, // Increment value at address 0 by value at address 1
        Instruction {
            asm_type: ASM_BNE,
            address_a: 2,
            address_b: 0,
            address_c: 0,
        }, // If value at address 0 and value at address 2 are not equal, jump 1 line backwards
    ];

    // The input data
    const DUMMY_DATA: [u32; 3] = [
        0,  // The initial value is 0
        1,  // The step size is 1
        10, // We count up to 10
    ];

    #[test]
    fn execute_dummy_program() {
        let vm = VM::new(&DUMMY_PROGRAM, &DUMMY_DATA);
        vm.run(TRACE_LEN);
    }

    #[test]
    fn execute_add_instructions() {
        let address_a = 0;
        let value_a = 0xFFFFFFFB;
        let address_b = 1;
        let value_b = 7;
        let address_c = 2;
        let program = [Instruction {
            asm_type: ASM_ADD,
            address_a,
            address_b,
            address_c,
        }];
        let data: [u32; 2] = [value_a, value_b];

        let vm: VM = VM::new(&program, &data);
        let snapshot: Snapshot = vm.run(TRACE_LEN);

        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 2);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_sub_instructions() {
        let address_a = 0;
        let value_a = 0xFFFFFFFD;
        let address_b = 1;
        let value_b = 0xFFFFFFFB;
        let address_c = 2;
        let program = [Instruction {
            asm_type: ASM_SUB,
            address_a,
            address_b,
            address_c,
        }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 2);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // "negative" result
    fn execute_sub_instructions_2() {
        let address_a = 0;
        let value_a = 3;
        let address_b = 1;
        let value_b = 5;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_SUB, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 0xFFFFFFFE);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_and_instructions() {
        let address_a = 0;
        let value_a = 0b1100;
        let address_b = 1;
        let value_b = 0b0101;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_AND, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);

        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 0b0100); 

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_or_instructions() {
        let address_a = 0;
        let value_a = 0b1100;
        let address_b = 1;
        let value_b = 0b0101;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_OR, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);

        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 0b1101);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_xor_instructions() {
        let address_a = 0;
        let value_a = 0b1100;
        let address_b = 1;
        let value_b = 0b0101;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_XOR, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);

        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 0b1001); 

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_addi_instructions() {
        let address_a = 0;
        let value_a = 0xFFFFFFFB;
        let address_b = 7;
        let address_c = 1;
        let program = [Instruction { asm_type: ASM_ADDI, address_a, address_b, address_c }];
        let data = [ value_a ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 2) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_subi_instructions() {
        let address_a = 0;
        let value_a = 42;
        let address_b = 43;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_SUBI, address_a, address_b, address_c }];
        let data = [ value_a ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 0xFFFFFFFF);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_andi_instructions() {
        let address_a = 0;
        let value_a = 0b1100;
        let address_b = 0b0101;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_ANDI, address_a, address_b, address_c }];
        let data = [ value_a ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);

        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 0b0100);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_ori_instructions() {
        let address_a = 0;
        let value_a = 0b1100;
        let address_b = 0b0101;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_ORI, address_a, address_b, address_c }];
        let data = [ value_a ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);

        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 0b1101);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_xori_instructions() {
        let address_a = 0;
        let value_a = 0b1100;
        let address_b = 0b0101;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_XORI, address_a, address_b, address_c }];
        let data = [ value_a ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);

        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c, 0b1001);

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Case: True
    fn execute_beq_instructions() {
        let address_a = 0;
        let value_a = 42;
        let address_b = 1;
        let value_b = 42;
        let address_c = 210;
        let program = [Instruction { asm_type: ASM_BEQ, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify next program counter is address_c
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, address_c);
    }

    #[test] // Case: False
    fn execute_beq_instructions_2() {
        let address_a = 0;
        let value_a = 42;
        let address_b = 1;
        let value_b = 43;
        let address_c = 210;
        let program = [Instruction { asm_type: ASM_BEQ, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify next program counter is curr_pc + 1
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }


    #[test] // Case: True
    fn execute_bne_instructions() {
        let address_a = 0;
        let value_a = 42;
        let address_b = 1;
        let value_b = 43;
        let address_c = 210;
        let program = [Instruction { asm_type: ASM_BNE, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify next program counter is address_c
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, address_c);
    }


    #[test] // Case: False
    fn execute_bne_instructions_2() {
        let address_a = 0;
        let value_a = 42;
        let address_b = 1;
        let value_b = 42;
        let address_c = 210;
        let program = [Instruction { asm_type: ASM_BNE, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify next program counter is curr_pc + 1
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_rshift1_instructions() {
        let address_a = 0;
        let value_a = 0b1100;
        let address_c = 1;
        let program = [Instruction { asm_type: ASM_RSHIFT1, address_a, address_b: 0, address_c }];
        let data = [ value_a ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c,  0b0110 ) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Result: 1
    fn execute_sltu_instructions() {
        let address_a = 0;
        let value_a = 0xFFFFFFFE;
        let address_b = 1;
        let value_b = 0xFFFFFFFF;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_SLTU, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c,  1 ) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Result: 0
    fn execute_sltu_instructions_2() {
        let address_a = 0;
        let value_a = 0xFFFFFFFF;
        let address_b = 1;
        let value_b = 0xFFFFFFFE;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_SLTU, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c,  0 ) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Result: 1
    fn execute_slt_instructions() {
        let address_a = 0;
        let value_a = 0xFFFFFFF9;
        let address_b = 1;
        let value_b = 0x00000001;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_SLT, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c,  1 ) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test] // Result: 0
    fn execute_slt_instructions_2() {
        let address_a = 0;
        let value_a = 0xFFFFFFFB; // -5
        let address_b = 1;
        let value_b = 0xFFFFFFF9; // -7
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_SLT, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c,  0 ) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }

    #[test]
    fn execute_load_instructions() {
        // address_a is figured out at runtime from value_b -> address_a == value_b
        // value_a is loaded
        let value_a = 0x89ABCDEF;
        let address_b = 0;
        // Specifies where the address is stored
        let value_b = 17;
        let address_c = 1;
        let program = [Instruction { asm_type: ASM_LOAD, address_a: 0, address_b, address_c }];
        let data = [ value_b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, value_a ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c,  0x89ABCDEF ) ;
        
        // Verify that the instruction correctly sets address_a
        let address_a = snapshot.instruction.address_a;
        assert_eq!(address_a,  value_b );

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }
    
    #[test]
    fn execute_store_instructions() {
        // address_c is figured out at runtime from value_b -> address_c == value_b
        // value_a is stored
        let address_a = 0;
        let value_a = 0x89ABCDEF;
        let address_b = 1;
        // Specifies where the address is stored
        let value_b = 17;
        let program = [Instruction { asm_type: ASM_STORE, address_a, address_b, address_c: 0 }];
        let data = [ value_a, value_b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);
        
        // Verify that the instruction correctly sets address_c
        let address_c = snapshot.instruction.address_c;
        assert_eq!(address_c,  17 );

        // Verify result
        let value_c = snapshot.read(address_c);
        assert_eq!(value_c,  0x89ABCDEF ) ;

        // Verify program counter
        let curr_pc = vm.run(0).pc;
        let next_pc = snapshot.pc;
        assert_eq!(next_pc, curr_pc + 1);
    }


    #[test]
    fn merklize_its_memory() {
        let address_a = 1;  // TODO: set this to some random address, e.g., 42
        let value_a = 42;
        let address_b = 0;
        let value_b = 43;
        let address_c = 2;
        let program = [Instruction { asm_type: ASM_ADD, address_a, address_b, address_c }];
        let data = [ value_a, value_b ];

        let vm = VM::new(&program, &data);
        let snapshot = vm.run(TRACE_LEN);

        let path_root = snapshot.path(address_a).verify_up_to(0);

        assert_eq!(path_root, snapshot.root());
    }
}
