use std::{collections::HashMap, vec};
use crate::treepp::{pushable, script, Script};
use crate::u4::{u4_add_stack::*, u4_logic_stack::*, u4_rot_stack::*, u4_shift_stack::*, u4_std::*};
use bitcoin_script_stack::stack::{StackTracker, StackVariable};


const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITSTATE_MAPPING : [char; 8] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];

const INITSTATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn double_padding(num_bytes: u32) -> (Vec<Script>, u32) {
    //55 bytes fits in one block
    //56 to 64 requires two block padding

    let mut chunks = num_bytes / 64;
    chunks += 1;

    if num_bytes % 64 > 55 {

        let mut bytes_left_first_padding = 64 - (num_bytes % 64);
        bytes_left_first_padding -= 1; // remove the 0x80 that will be added always
        let script1 = script! {
            8
            0
            for _ in 0..bytes_left_first_padding { //can optimize with a couple of dups
                0
                0
            }
        };

        let script2 = script! {
            0
            OP_DUP
            for _ in 0..59 {
                OP_2DUP
            }
            { u4_number_to_nibble( num_bytes * 8 ) }
        };

        
        chunks += 1;

        let mut results = Vec::new();
        for _ in 0..(chunks - 2) {
            results.push(script!{});
        }
        results.push(script1);
        results.push(script2);

        (results, chunks)


    } else {
        let (script1,_) = padding(num_bytes);
        let mut results = Vec::new();
        for _ in 0..(chunks - 1) {
            results.push(script!{});
        }
        results.push(script1);
        (results, chunks)
    }

}




pub fn padding(num_bytes: u32) -> (Script, u32) {

    let l = (num_bytes * 8) as i32;
    let mut k = 512 - l - 8 - 32;     // heres is usually minus 8, but as 
                                            // there will be never that many bytes to process
                                            // one u32 will be enough
    let mut chunks = 1;
    while k < 0 {
        k += 512;
        chunks += 1;
    }
    let zeros = k/16;
    let extras = k % 16;

    ( script! {
        8
        0
        for i in 0..zeros {
            if i == 0 {
                0
                OP_DUP
                OP_2DUP
            } else {
                OP_2DUP
                OP_2DUP
            }
        }
        if extras > 0 {
            0
            0
        }
        { u4_number_to_nibble( l as u32 ) }
      },
      chunks
    )

}


pub fn calculate_s_stack(  stack: &mut StackTracker, 
                          number: StackVariable, 
                     shift_table: StackVariable, 
                     shift_value: Vec<u32>, 
                   last_is_shift: bool,  
                    lookup_table: StackVariable, 
                     logic_table: StackVariable,
                 do_xor_with_and:bool ) -> StackVariable 
{
    let mut results = Vec::new();
    for nib in 0..8 {
        u4_rrot_nib_from_u32(stack, shift_table, number, nib, shift_value[0], false);
        u4_rrot_nib_from_u32(stack, shift_table, number, nib, shift_value[1], false);
        u4_logic_stack_nib(stack, lookup_table, logic_table, do_xor_with_and);
        u4_rrot_nib_from_u32(stack, shift_table, number, nib, shift_value[2], last_is_shift);
        results.push(u4_logic_stack_nib(stack, lookup_table, logic_table, do_xor_with_and));
    }

    let var = stack.join_count(&mut results[0], 7);
    stack.rename(var, "s");
    var

}

pub fn ch_calculation_stack(stack: &mut StackTracker, e: StackVariable, f:StackVariable, g:StackVariable, lookup: StackVariable, andtable: StackVariable) -> StackVariable {

    let mut ret = Vec::new();
    for nib in 0..8 {
        stack.copy_var_sub_n(e, nib);   // e[nib]
        stack.op_dup();                        // e e

        stack.op_negate();                     // e ~e
        stack.number(15);
        stack.op_add();

        stack.copy_var_sub_n(g, nib);    // e ~e g[nib]

        u4_logic_with_table_stack(stack, lookup, andtable); // e  ( ~e & g )
        stack.op_swap();                       // ( ~e & g ) e

        stack.copy_var_sub_n(f, nib);   // ( ~e & g ) e f[nib]

        u4_logic_with_table_stack(stack, lookup, andtable); // ( ~e & g ) (e & f)
        ret.push(u4_xor_with_and_stack(stack, lookup, andtable)); // ( ~e & g ) ^ (e & f)

    }

    stack.join_count(&mut ret[0], 7);
    stack.rename(ret[0], "ch");
    ret[0]

}

pub fn maj_calculation_stack(stack: &mut StackTracker, a: StackVariable, b:StackVariable, c:StackVariable, lookup: StackVariable, andtable: StackVariable) -> StackVariable {

    let mut ret = Vec::new();
    for nib in 0..8 {
        
        stack.copy_var_sub_n(a, nib);              // a[nib]

        stack.copy_var_sub_n(b, nib);              // a b[nib]

        stack.op_2dup();                                  // a b a b

        u4_xor_with_and_stack(stack, lookup, andtable);  // a b (a^b)

        stack.copy_var_sub_n(c, nib);                     // a b (a^b) c

        u4_logic_with_table_stack(stack, lookup, andtable); // a b ((a^b) & c)

        stack.op_rot();
        stack.op_rot();                                  // ((a^b) & c) a b

        u4_logic_with_table_stack(stack, lookup, andtable); // ((a^b) & c) (a & b)

        ret.push(u4_xor_with_and_stack(stack, lookup, andtable));  // ((a^b) & c) ^ (a & b)

    }

    stack.join_count(&mut ret[0], 7);
    stack.rename(ret[0], "maj");
    ret[0]

}


pub fn sha256_stack(mut stack: &mut StackTracker, num_bytes: u32) -> Script {

    // up to 55 is one block and always supports add table
    // probably up to 68 bytes I can afford to load the add tables for the first chunk (but have I would have to unload it)

    let (mut padding_scripts, chunks) = double_padding(num_bytes);
    let mut bytes_per_chunk : Vec<u32> = Vec::new();
    let mut bytes_remaining = num_bytes;
    while bytes_remaining > 0 {
        if bytes_remaining > 64 {
            bytes_per_chunk.push( 64);
            bytes_remaining -= 64;
        } else {
            bytes_per_chunk.push( bytes_remaining);
            bytes_remaining = 0;
        }
    } 
    if bytes_per_chunk.len() < chunks as usize {
        bytes_per_chunk.push(0);
    }
    //println!("{:?}", bytes_per_chunk);
    //println!("{:?}", padding_scripts);


    let mut use_add_table = chunks == 1;

    let mut message = (0..num_bytes*2).map(|i| stack.define(1, &format!("message[{}]", i))).collect::<Vec<StackVariable>>();

    let (mut modulo,mut quotient) = match use_add_table {
        true => {
            ( u4_push_modulo_table_stack(&mut stack), u4_push_quotient_table_stack(&mut stack) )
        },
        false => {
            (StackVariable::null(), StackVariable::null())
        }
    };


    stack.set_breakpoint("init");

    let shift_tables = u4_push_shift_tables_stack(&mut stack);
    let half_lookup = u4_push_lookup_table_stack(&mut stack);
    let mut xor_table = u4_push_xor_table_stack(&mut stack);
    let mut and_table = StackVariable::null();
    
    let mut varmap : HashMap<char, StackVariable> = HashMap::new();
    let mut initstate : HashMap<char, StackVariable> = HashMap::new();

    stack.set_breakpoint("load tables");


    for c in 0..chunks {

        //change tables
        if c > 0 {
            stack.drop(and_table);

            xor_table = u4_push_xor_table_stack(&mut stack);
            stack.set_breakpoint("change tables");
        }

        //move the message to the top of the stack
        //this can be optimized only moving the las nibbles that would form an u32 with the first part of the padding 
        let mut moved_message = (0..bytes_per_chunk[c as usize]*2)
                             .map(|i| stack.move_var( message[i as usize] ))
                             .collect::<Vec<StackVariable>>(); 
        message.drain(0..moved_message.len());


        stack.set_breakpoint("moved message");

        //complete message with padding
        stack.custom(padding_scripts.remove(0), 0, false, 0, "padding");
        let len = moved_message.len();
        if len < 128 {
            for i in 0..(128 - len) {
                moved_message.push( stack.define(1, &format!("padding[{}]", i)) );
            }
        }
        stack.set_breakpoint("padding");

        //redefine from nibbles to u32
        assert!(moved_message.len() == 128);
        let mut schedule = Vec::new();
        for i in 0..16 {
            let joined = stack.join_count(&mut moved_message[0], 7) ;
            stack.rename(joined, &format!("schedule[{}]", i));
            schedule.push(joined);
            moved_message.drain(0..8);
        }
        stack.set_breakpoint("schedule");

        
        //schedule loop 
        for i in 16..64 {
            let mut s0 = calculate_s_stack(&mut stack, schedule[i-15], shift_tables, vec![7,18,3], true, half_lookup, xor_table, false);
            let mut s1 = calculate_s_stack(&mut stack, schedule[i-2], shift_tables, vec![17,19,10], true, half_lookup, xor_table, false);
            u4_add_stack(&mut stack, 8, 4, vec![schedule[i-16], schedule[i-7]], vec![&mut s0, &mut s1], vec![], quotient, modulo);
            let sched_i = stack.from_altstack_joined(8, &format!("schedule[{}]", i));
            schedule.push(sched_i);
            
            stack.set_breakpoint(&format!("schedule[{}]", i));
        }


        //exchange xor with and table
        stack.to_altstack_count(64);
        stack.drop(xor_table);

        and_table = u4_push_and_table_stack(stack);
        stack.from_altstack_count(64);


        if c == 0 {
            for i in 0..INITSTATE.len() {
                let var = stack.number_u32(INITSTATE[i]);
                varmap.insert(INITSTATE_MAPPING[i], var);
            }
        } else {

            for i in 0..INITSTATE_MAPPING.len() {
                varmap.insert(INITSTATE_MAPPING[i], stack.from_altstack_joined(8, &format!("{}", INITSTATE_MAPPING[i])));
                initstate.insert(INITSTATE_MAPPING[i], stack.copy_var(varmap[&INITSTATE_MAPPING[i]]));
            }
        }

        for i in 0..64 {

            //calculated that after 6 iterations of chunk 2 the add tables fit in the stack
            if i == 6 && c == 1 {
                modulo = u4_push_modulo_table_stack(&mut stack);
                quotient = u4_push_quotient_table_stack(&mut stack);
                use_add_table = true;
            }

            //Calculate S1
            let mut s1 = calculate_s_stack( stack, varmap[&'e'], shift_tables, vec![6, 11, 25], false, half_lookup, and_table, true) ;

            //calculate ch
            let mut ch = ch_calculation_stack(&mut stack, varmap[&'e'], varmap[&'f'], varmap[&'g'], half_lookup, and_table);

            //calculate temp1 
            let mut h = varmap[&'h'].clone();
            if use_add_table {
                u4_add_stack(&mut stack, 8, 2, vec![],  vec![&mut schedule[i]], vec![K[i as usize]], quotient, modulo);
                let mut parts = stack.from_altstack_count(8);
                let mut part1 = stack.join_count(&mut parts[0], 7);
                u4_add_stack(&mut stack, 8, 4, vec![],  vec![&mut s1, &mut ch, &mut h, &mut part1, ],vec![], quotient, modulo);
            } else {
                u4_add_stack(&mut stack, 8, 5, vec![],  vec![&mut s1, &mut ch, &mut h, &mut schedule[i] ],vec![K[i as usize]], StackVariable::null(), StackVariable::null());
            }
            let mut temp1 = stack.from_altstack_joined(8, "temp1");

            //Calculate S0
            let mut s0 = calculate_s_stack( stack, varmap[&'a'], shift_tables, vec![2, 13, 22], false, half_lookup, and_table, true) ;

            //Calculate maj
            let mut maj = maj_calculation_stack(&mut stack, varmap[&'a'], varmap[&'b'], varmap[&'c'], half_lookup, and_table);


            //calculate a = temp1 + s0 + maj
            u4_add_stack(&mut stack, 8, 3, vec![temp1],  vec![&mut s0, &mut maj] ,vec![], quotient, modulo);
            let temp_a = stack.from_altstack_joined(8, "temp_a");

            //e = d + temp1 (consumes d)
            let mut d = varmap[&'d'].clone();
            u4_add_stack(&mut stack, 8, 2, vec![],  vec![&mut d, &mut temp1] ,vec![], quotient, modulo);
            let temp_e = stack.from_altstack_joined(8, "temp_e");

            //reorder variables
            varmap.insert('h', varmap[&'g']); 
            varmap.insert('g', varmap[&'f']);
            varmap.insert('f', varmap[&'e']);
            varmap.insert('e', temp_e);
            varmap.insert('d', varmap[&'c']);
            varmap.insert('c', varmap[&'b']);
            varmap.insert('b', varmap[&'a']);
            varmap.insert('a', temp_a);

            for c in INITSTATE_MAPPING.iter() {
                stack.rename(varmap[c], &format!("{}", c));
            }


            stack.set_breakpoint(&format!("loop[{}]", i));
        }


        if c == 0 {
            //first chunk adds with init state
            for i in (0..INITSTATE_MAPPING.len()).rev() {
                let mut x = varmap.get(&INITSTATE_MAPPING[i]).unwrap().clone();
                u4_add_stack(stack, 8, 2, vec![], vec![&mut x], vec![INITSTATE[i]], quotient, modulo);
            }
        } else {

            for i in (0..INITSTATE_MAPPING.len()).rev() {
                let mut prev_state = initstate.get(&INITSTATE_MAPPING[i]).unwrap().clone();
                let mut x = varmap.get(&INITSTATE_MAPPING[i]).unwrap().clone();
                u4_add_stack(stack, 8, 2, vec![], vec![&mut x, &mut prev_state],vec![], quotient, modulo);
            }
        }

        stack.set_breakpoint("var addition");

        // if last chunk drop the tables
        if c == chunks - 1 {
            if use_add_table && chunks == 2 {
                stack.drop(quotient);
                stack.drop(modulo);
            }
            stack.drop(and_table);
            stack.drop(half_lookup);
            stack.drop(shift_tables);
            if use_add_table && chunks == 1 {
                stack.drop(quotient);
                stack.drop(modulo);
            }
        }
        stack.set_breakpoint("dropped");


    }

    for i in 0..INITSTATE_MAPPING.len() {
        *varmap.get_mut(&INITSTATE_MAPPING[i]).unwrap() = stack.from_altstack_joined(8, &format!("h{}", i));
    }

    stack.set_breakpoint("final");

        
    stack.get_script()


}

#[cfg(test)]
mod tests {

use crate::{execute_script, treepp::script};
use super::*;
use sha2::{Digest, Sha256};


    #[test]
    fn test_sizes_tmp() {
        let mut stack = StackTracker::new();
        let x = sha256_stack(&mut stack, 32);
        println!("sha 32 bytes: {}",x.len());
        println!("max stack: {}", stack.get_max_stack_size());

        let mut stack = StackTracker::new();
        let x = sha256_stack(&mut stack, 80);
        println!("sha 80 bytes: {}",x.len());
        println!("max stack: {}", stack.get_max_stack_size());
    }

        
    #[test]
    fn test_shatemp() {

        let mut stack = StackTracker::new();
        stack.custom(script!{
            {u4_number_to_nibble(0xdeadbeaf)}
            {u4_number_to_nibble(0x01020304)}  
        }, 0, false, 0, "message");

        sha256_stack(&mut stack, 8);
        stack.run();
        
    }

    fn test_sha256( hex_in : &str ) {

        let mut hasher = Sha256::new();
        let data = hex::decode(hex_in).unwrap();
        hasher.update(&data);
        let result = hasher.finalize();
        let res = hex::encode(result);
        println!("Result: {}", res);
        

        let mut stack = StackTracker::new();
        stack.custom(script!{ {u4_hex_to_nibbles(hex_in)}}, 0, false, 0, "message");

        let shascript = sha256_stack(&mut stack, hex_in.len() as u32 / 2);


        let script = script! {
            { shascript } 
            { u4_hex_to_nibbles(res.as_str())}
            for _ in 0..64 {
                OP_TOALTSTACK
            }

            for i in 1..64 {
                {i}
                OP_ROLL
            }

            for _ in 0..64 {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
            OP_TRUE

        };


        let res = execute_script(script);
        assert!(res.success);

    }

    #[test]
    fn test_sha256_strs() {
        let message = "Hello.";
        let hex : String = message.as_bytes().iter().map(|&b| format!("{:02x}", b)).collect();
        test_sha256(&hex);
        let message = "This is a longer message that still fits in one block!";
        let hex : String = message.as_bytes().iter().map(|&b| format!("{:02x}", b)).collect();
        test_sha256(&hex)
    }

    #[test]
    fn test_sha256_two_blocks() {
        let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaaaaaaaa";
        test_sha256(&hex);
        let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001122334455667788";
        test_sha256(&hex);
        let hex = "7788ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaa001122334455667788";
        test_sha256(&hex);
    }

    #[test]
    fn test_padding() {

        let (script, _) = padding(1);
        let script = script! {
            { 0}
            { 1 }
            { script }
            { u4_drop(128) }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);

 
    }
    
    #[test]
    fn test_split_padding() {

        for num_bytes in 0..150 {

            let (padding_scripts, chunks) = double_padding(num_bytes);

            let script = script! {
                for _ in 0..num_bytes {
                    { 1 }
                    { 0 }
                }
                OP_DEPTH
                OP_TOALTSTACK
                for script in padding_scripts {
                    { script }
                    OP_DEPTH
                    OP_TOALTSTACK
                }
                { u4_drop(chunks*128) }
                OP_DEPTH
                OP_TOALTSTACK
                OP_TRUE
            };

            let res = execute_script(script);
            assert!(res.success);

        }
 
    }

    #[test]
    fn test_genesis_block() {
        // the genesis block header of bitcoin
        // version previous-block merkle-root time bits nonce
        // 01000000 0000000000000000000000000000000000000000000000000000000000000000 3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a 29ab5f49 ffff001d 1dac2b7c
        let block_header = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let mut hasher = Sha256::new();
        let data = hex::decode(block_header).unwrap();
        hasher.update(&data);
        let mut result = hasher.finalize();
        hasher = Sha256::new();
        hasher.update(result);
        result = hasher.finalize();
        let res = hex::encode(result);
        let genesis_block_hash = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
        assert_eq!(res.as_str(), genesis_block_hash);


        let mut stack = StackTracker::new();
        stack.custom(script!{ {u4_hex_to_nibbles(block_header)}}, 0, false, 0, "message");
        sha256_stack(&mut stack, block_header.len() as u32 / 2);
        let shascript = sha256_stack(&mut stack, 32);

        let script = script! {

            { shascript }
            
            { u4_hex_to_nibbles(res.as_str())}
            for _ in 0..64 {
                OP_TOALTSTACK
            }

            for i in 1..64 {
                {i}
                OP_ROLL
            }

            for _ in 0..64 {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
            OP_TRUE


        };
        let res = execute_script(script);
        assert!(res.success);
    }

}