use std::collections::HashMap;

use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub use bitcoin_script::script;
pub use bitcoin_script::builder::StructuredScript as Script;

use crate::u4::{u4_add_stack::*, u4_logic_stack::*, u4_shift_stack::*, u4_std::u4_repeat_number};

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [u8; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[derive(Clone, Debug, Copy)]
pub struct TablesVars {
    modulo: StackVariable,
    quotient: StackVariable,
    shift_tables: StackVariable,
    xor_table: StackVariable,
    depth_lookup: StackVariable,
    use_full_tables: bool,
}

impl TablesVars {
    pub fn new(stack: &mut StackTracker, use_full_tables: bool) -> Self {
        let depth_lookup = if !use_full_tables { u4_push_from_depth_half_lookup(stack, -18) } else { u4_push_from_depth_full_lookup(stack, -17) };
        let xor_table = if !use_full_tables { u4_push_half_xor_table_stack(stack) } else { u4_push_full_xor_table_stack(stack) };
        let shift_tables = u4_push_shift_for_blake(stack);
        let modulo = u4_push_modulo_for_blake(stack);
        let quotient = u4_push_quotient_for_blake(stack);
        TablesVars {
            modulo,
            quotient,
            shift_tables,
            xor_table,
            depth_lookup,
            use_full_tables,
        }
    }

    pub fn drop(&self, stack: &mut StackTracker) {
        stack.drop(self.quotient);
        stack.drop(self.modulo);
        stack.drop(self.shift_tables);
        stack.drop(self.xor_table);
        stack.drop(self.depth_lookup);
    }


}


pub fn right_rotate_xored(stack: &mut StackTracker, var_map: &mut HashMap<u8, StackVariable>, x:u8, y:u8, n: u8, use_full_tables: bool ) -> StackVariable {
    let pos_shift = 8 - n / 4;

    let y = var_map[&y];
    let x = var_map.get_mut(&x).unwrap();

    for i in pos_shift..pos_shift+8 {
        let n = i % 8;

        let mut z = 0;
        if i < 8 {
            z = pos_shift;
        }

        xor_2nib(stack, x, y, z, n, use_full_tables);
    }

    stack.join_count(&mut stack.get_var_from_stack(7), 7)

}    

pub fn xor_2nib_half(stack: &mut StackTracker, x: &mut StackVariable, y: StackVariable, nx: u8, ny: u8 )  -> StackVariable {

    stack.op_depth();

    stack.op_dup();

    stack.copy_var_sub_n(y, ny as u32);
    stack.move_var_sub_n(x, nx as u32);
    stack.op_2dup();
    stack.op_min();
    stack.to_altstack();

    stack.op_max();

    stack.op_sub();
    stack.op_1sub();

    stack.op_pick();


    stack.op_add();
    
    stack.from_altstack();

    stack.op_sub();
    
    stack.op_pick()
}

pub fn xor_2nib(stack: &mut StackTracker, x: &mut StackVariable, y: StackVariable, nx: u8, ny: u8, use_full_tables: bool )  -> StackVariable {
    if !use_full_tables {
        return xor_2nib_half(stack, x, y, nx, ny);
    }

    stack.op_depth();
    stack.op_dup();

    stack.copy_var_sub_n(y, ny as u32);

    stack.op_sub();
    stack.op_pick();

    stack.op_add();

    stack.move_var_sub_n(x, nx as u32);

    stack.op_add();
    stack.op_pick()
}

pub fn right_rotate7_xored_sub(
    stack: &mut StackTracker,
    x: &mut StackVariable,
    y: StackVariable,
    tables: &TablesVars,
    n: u8,
) {
    stack.from_altstack();

    let r0 = xor_2nib(stack, x, y, 0, n, tables.use_full_tables);

    stack.rename(r0, &format!("z{}", n));
    stack.copy_var(r0);

    stack.to_altstack();

    // r7 r0 >> 3
    let w1 = u4_2_nib_shift_blake(stack, tables.shift_tables);
    stack.rename(w1, &format!("w{}", n + 1));
}

pub fn right_rotate7_xored(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    x: u8,
    y: u8,
    tables: &TablesVars,
) -> StackVariable {
    // x    = x0 x1 x2 x3 x4 x5 x6 x7
    // y    = y0 y1 y2 y3 y4 y5 y6 y7
    // x^y = z
    // z             = z0 z1 z2 z3 z4 z5 z6 z7
    // rrot4( z )    = z7 z0 z1 z2 z3 z4 z5 z6
    // w = rrot7( z ) = (z6) z7 z0 z1 z2 z3 z4 z5 z6  >> 3
    let y = var_map[&y];
    let x = var_map.get_mut(&x).unwrap();

    // nib 6 xored

    let z6 = xor_2nib(stack, x, y, 6, 6, tables.use_full_tables);
    stack.rename(z6, "z6");

    // nib 6 copy saved
    stack.copy_var(z6);
    stack.to_altstack();
    
    //nib 7 xored
    let z7 = xor_2nib(stack, x, y, 6, 7, tables.use_full_tables);
    stack.rename(z7, "z7");
    stack.copy_var(z7);
    stack.to_altstack();


    // z6 z7 >> 3
    let mut w0 = u4_2_nib_shift_blake(stack, tables.shift_tables);
    stack.rename(w0, "w0");

    for i in 0..6 {
        right_rotate7_xored_sub(stack, x, y, tables, i);
    }

    stack.from_altstack();
    stack.from_altstack();

    let w7 = u4_2_nib_shift_blake(stack, tables.shift_tables);
    stack.rename(w7, "w7");
    

    stack.join_count(&mut w0, 7)
}


pub fn u4_add_direct( stack: &mut StackTracker, nibble_count: u32, 
            to_copy: Vec<StackVariable>, 
            mut to_move: Vec<&mut StackVariable>, 
            mut constants: Vec<u32>, tables: &TablesVars) 
{

    // add all the constants together
    if constants.len() > 1 {
        let mut sum : u32 = 0;
        for c in constants.iter() {
            sum = sum.wrapping_add(*c);
        }
        constants = vec![sum];
    }

    //split the parts of the constant (still one element)
    let mut constant_parts : Vec<Vec<u32>> = Vec::new();
    for n in constants {
        let parts = (0..8).rev().map(|i| (n >> (i * 4)) & 0xF ).collect();
        constant_parts.push(parts);
    }

    let number_count = to_copy.len() + to_move.len() + constant_parts.len();

    for i in (0..nibble_count).rev() {

        //copy the nibbles from the back
        for x in to_copy.iter() {
            stack.copy_var_sub_n(*x, i);
        }

        for x in to_move.iter_mut() {
            stack.move_var_sub_n(x, i);
        }

        for parts in constant_parts.iter() {
            stack.number(parts[i as usize]);
        }

        //add the numbers
        for _ in 0..number_count - 1 {
            stack.op_add();
        }

        //add the carry of the previous addition
        if i < nibble_count - 1 {
            stack.op_add();
        }

        if i > 0 {
            //dup the result to be used to get the carry except for the last nibble
            stack.op_dup();
        }

        //save value
        let modulo = stack.get_value_from_table(tables.modulo, None);
        stack.rename(modulo, &format!("modulo[{}]", i).to_string());
        stack.to_altstack();

        if i > 0 {
            let carry = stack.get_value_from_table(tables.quotient, None);
            stack.rename(carry, "carry");
        }


    }

}

#[allow(clippy::too_many_arguments)]
pub fn g(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    mut mx: StackVariable,
    mut my: StackVariable,
    tables: &TablesVars,
    last_round: bool,
) {
    //adds a + b + mx
    //consumes a and mx and copies b
    let vb = var_map[&b];
    let mut va = var_map.get_mut(&a).unwrap();

    if last_round {
        u4_add_direct(stack, 8, vec![vb], vec![&mut va, &mut mx], vec![], tables);
    } else {
        u4_add_direct(stack, 8, vec![vb, mx], vec![&mut va], vec![], tables);
    }
    
    //stores the results in a
    *va = stack.from_altstack_joined(8, &format!("state_{}", a));

    // right rotate d xor a ( consumes d and copies a)
    let ret = right_rotate_xored(stack, var_map, d, a, 16, tables.use_full_tables);
    // saves in d
    var_map.insert(d, ret);

    let vd = var_map[&d];
    let mut vc = var_map.get_mut(&c).unwrap();
    u4_add_direct(
        stack,
        8,
        vec![vd],
        vec![&mut vc],
        vec![],
        tables,
    );
    *vc = stack.from_altstack_joined(8, &format!("state_{}", c));

    let ret = right_rotate_xored(stack, var_map, b, c, 12, tables.use_full_tables);
    var_map.insert(b, ret);

    let vb = var_map[&b];
    let mut va = var_map.get_mut(&a).unwrap();
    if last_round {
        u4_add_direct(stack, 8, vec![vb], vec![&mut va, &mut my], vec![], tables);
    } else {
        u4_add_direct(stack, 8, vec![vb, my], vec![&mut va], vec![], tables);
    }

    *va = stack.from_altstack_joined(8, &format!("state_{}", a));

    let ret = right_rotate_xored(stack, var_map, d, a, 8, tables.use_full_tables);
    var_map.insert(d, ret);
    stack.rename(ret, &format!("state_{}", d));

    let vd = var_map[&d];
    let mut vc = var_map.get_mut(&c).unwrap();
    u4_add_direct(
        stack,
        8,
        vec![vd],
        vec![&mut vc],
        vec![],
        tables,
    );
    *vc = stack.from_altstack_joined(8, &format!("state_{}", c));

    let ret = right_rotate7_xored(stack, var_map, b, c, tables);
    var_map.insert(b, ret);
    stack.rename(ret, &format!("state_{}", b));
}

pub fn round(
    stack: &mut StackTracker,
    state_var_map: &mut HashMap<u8, StackVariable>,
    message_var_map: &HashMap<u8, StackVariable>,
    tables: &TablesVars,
    last_round: bool
) {
    g(
        stack,
        state_var_map,
        0,
        4,
        8,
        12,
        message_var_map[&0],
        message_var_map[&1],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        1,
        5,
        9,
        13,
        message_var_map[&2],
        message_var_map[&3],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        2,
        6,
        10,
        14,
        message_var_map[&4],
        message_var_map[&5],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        3,
        7,
        11,
        15,
        message_var_map[&6],
        message_var_map[&7],
        tables,
        last_round,
    );

    g(
        stack,
        state_var_map,
        0,
        5,
        10,
        15,
        message_var_map[&8],
        message_var_map[&9],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        1,
        6,
        11,
        12,
        message_var_map[&10],
        message_var_map[&11],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        2,
        7,
        8,
        13,
        message_var_map[&12],
        message_var_map[&13],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        3,
        4,
        9,
        14,
        message_var_map[&14],
        message_var_map[&15],
        tables,
        last_round,
    );
}

pub fn permutate(message_var_map: &HashMap<u8, StackVariable>) -> HashMap<u8, StackVariable> {
    let mut ret = HashMap::new();
    for i in 0..16_u8 {
        ret.insert(i, message_var_map[&MSG_PERMUTATION[i as usize]]);
    }
    ret
}

pub fn init_state(
    stack: &mut StackTracker,
    chaining: bool,
    counter: u32,
    block_len: u32,
    flags: u32,
) -> HashMap<u8, StackVariable> {
    let mut state = Vec::new();

    if chaining {
        for i in 0..8 {
            state.push(stack.from_altstack_joined(8, &format!("prev-hash[{}]", i)));
        }
    } else {
        for u32 in IV {
            state.push(stack.number_u32(u32));
        }
    }
    for u32 in &IV[0..4] {
        state.push(stack.number_u32(*u32));
    }
    state.push(stack.number_u32(0));
    state.push(stack.number_u32(counter));
    state.push(stack.number_u32(block_len));
    state.push(stack.number_u32(flags));

    let mut state_map = HashMap::new();
    for (i, s) in state.iter().enumerate() {
        state_map.insert(i as u8, *s);
        stack.rename(*s, &format!("state_{}", i));
    }
    state_map
}

#[allow(clippy::too_many_arguments)]
pub fn compress(
    stack: &mut StackTracker,
    chaining: bool,
    counter: u32,
    block_len: u32,
    flags: u32,
    mut message: HashMap<u8, StackVariable>,
    tables: &TablesVars,
    final_rounds: u8,
    last_round: bool,
) {
    //chaining value needs to be copied for multiple blocks
    //every time that is provided

    let mut state = init_state(stack, chaining, counter, block_len, flags);

    for i in 0..7 {
        //round 6 could consume the message
        round(stack, &mut state, &message, tables, i == 6);

        if i == 6 {
            break;
        }
        message = permutate(&message);
    }

    for i in (0..final_rounds).rev() {
        let mut tmp = Vec::new();

        //iterate nibbles
        for n in 0..8 {
            let v2 = *state.get(&(i + 8)).unwrap();
            let v1 = state.get_mut(&i).unwrap();
            tmp.push(xor_2nib(stack, v1, v2, 0, n, tables.use_full_tables));

            if last_round && n % 2 == 1 {
                stack.to_altstack();
                stack.to_altstack();
            }
        }
        if !last_round {
            for _ in 0..8 {
                stack.to_altstack();
            }
        }
    }
}

pub fn get_flags_for_block(i: u32, num_blocks: u32) -> u32 {
    if num_blocks == 1 {
        return 0b00001011;
    }
    if i == 0 {
        return 0b00000001;
    }
    if i == num_blocks - 1 {
        return 0b00001010;
    }
    0
}

// final rounds: 8 => 32 bytes hash
// final rounds: 5 => 20 bytes hash (blake_160)
pub fn blake3(stack: &mut StackTracker, mut msg_len: u32, final_rounds: u8) {
    assert!(
        msg_len <= 288,
        "This blake3 implementation supports up to 288 bytes"
    );

    let use_full_tables = msg_len <= 232;

    let num_blocks = msg_len.div_ceil(64);
    let mut num_padding_bytes = num_blocks * 64 - msg_len;

    //to handle the message the padding needs to be multiple of 4
    //so if it's not multiple it needs to be added at the beginning
    let mandatory_first_block_padding = num_padding_bytes % 4;
    num_padding_bytes -= mandatory_first_block_padding;

    if mandatory_first_block_padding > 0 {
        stack.custom(
            u4_repeat_number(0, (mandatory_first_block_padding) * 2),
            0,
            false,
            0,
            "padding",
        );
    }

    let mut original_message = Vec::new();
    for i in 0..msg_len / 4 {
        let m = stack.define(8, &format!("msg_{}", i));
        original_message.push(m);
    }

    for _ in original_message.iter() {
        stack.to_altstack();
    }


    let tables = TablesVars::new(stack, use_full_tables);

    for _ in original_message.iter() {
        stack.from_altstack();
    }


    //process every block
    for i in 0..num_blocks {
        let last_round = i == num_blocks - 1;
        let intermediate_rounds = if last_round { final_rounds } else { 8 };

        let flags = get_flags_for_block(i, num_blocks);

        // add the padding on the last round
        if last_round && num_padding_bytes > 0 {
            stack.custom(
                u4_repeat_number(0, (num_padding_bytes) * 2),
                0,
                false,
                0,
                "padding",
            );
            for i in 0..(num_padding_bytes / 4) {
                let m = stack.define(8, &format!("padd_{}", i));
                original_message.push(m);
            }
        }

        // create the current block message map
        let mut message = HashMap::new();
        for m in 0..16 {
            message.insert(m as u8, original_message[m + (16 * i) as usize]);
        }

        // compress the block
        compress(
            stack,
            i > 0,
            0,
            msg_len.min(64),
            flags,
            message,
            &tables,
            intermediate_rounds,
            last_round,
        );

        if msg_len > 64 {
            msg_len -= 64;
        }

        //drop the rest of the state
        for _ in 0..16 - intermediate_rounds {
            stack.drop(stack.get_var_from_stack(0));
        }

    }

    //drop tables
    tables.drop(stack);

    //get the result hash
    stack.from_altstack_joined(final_rounds as u32 * 8, "blake3-hash");
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    pub use bitcoin_script::script;
    //pub use bitcoin::ScriptBuf as Script;
    use bitcoin_script_stack::{debugger::debug_script, script_util::verify_n, stack::StackTracker, optimizer::optimize};

    use super::*;
    use crate::u4::u4_std::u4_hex_to_nibbles;

    fn verify_blake3_hash(result: &str) -> Script {
        script! {
            { u4_hex_to_nibbles(result)}
            for _ in 0..result.len() {
                OP_TOALTSTACK
            }

            for i in 1..result.len() {
                {i}
                OP_ROLL
            }

            for _ in 0..result.len() {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }

        }
    }

    #[test]
    fn test_blake3_for_nibble_array() {
        fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
            let mut msg_bytes = Vec::with_capacity(digits.len() / 2);
        
            for nibble_pair in digits.chunks(2) {
                let byte = (nibble_pair[0] << 4) | (nibble_pair[1] & 0b00001111);
                msg_bytes.push(byte);
            }
        
            fn le_to_be_byte_array(byte_array: Vec<u8>) -> Vec<u8> {
                assert!(byte_array.len() % 4 == 0, "Byte array length must be a multiple of 4");
                byte_array
                    .chunks(4) // Process each group of 4 bytes (one u32)
                    .flat_map(|chunk| chunk.iter().rev().cloned()) // Reverse each chunk
                    .collect()
            }
            le_to_be_byte_array(msg_bytes)
        }


        let mut stack = StackTracker::new();
        let msg:Vec<u8> = vec![2, 3, 14, 5, 5, 11, 1, 4, 6, 6, 2, 0, 6, 2, 7, 11, 5, 5, 15, 10, 5, 1, 9, 2, 10, 6, 12, 9, 4, 8, 9, 14, 13, 13, 5, 10, 12, 11, 5, 12, 5, 3, 14, 15, 11, 12, 12, 12, 12, 13, 10, 11, 2, 0, 14, 9, 10, 9, 4, 4, 2, 3, 10, 15, 1, 8, 14, 13, 7, 13, 2, 12, 14, 7, 7, 15, 13, 14, 4, 6, 11, 4, 0, 15, 8, 2, 3, 1, 7, 2, 12, 1, 13, 1, 4, 5, 4, 7, 4, 6, 15, 10, 13, 11, 6, 11, 3, 8, 12, 15, 7, 1, 2, 11, 1, 14, 10, 1, 7, 13, 12, 14, 2, 9, 4, 7, 15, 13, 0, 9, 12, 13, 2, 14, 3, 9, 14, 9, 11, 12, 0, 5, 1, 2, 10, 10, 9, 12, 1, 2, 14, 0, 10, 7, 6, 1, 5, 11, 7, 8, 13, 5, 7, 7, 1, 7, 15, 11, 6, 0, 12, 4, 14, 10, 3, 2, 2, 9, 5, 5, 14, 5, 8, 1, 4, 5, 3, 1, 15, 7, 3, 15, 0, 0, 11, 15, 4, 12, 10, 10, 2, 13, 5, 5, 11, 11, 3, 9, 10, 15, 12, 13, 10, 13, 0, 10, 7, 0, 9, 9, 15, 12, 15, 11, 4, 15, 5, 12, 3, 5, 5, 12, 10, 3, 12, 13, 13, 2, 11, 4, 14, 13, 7, 5, 11, 8, 4, 5, 1, 9, 8, 10, 2, 9, 9, 15, 0, 4, 15, 4, 2, 15, 11, 7, 4, 0, 13, 1, 15, 9, 4, 11, 5, 8, 2, 15, 0, 12, 8, 14, 7, 2, 8, 9, 8, 8, 15, 11, 3, 9, 15, 9, 3, 9, 7, 10, 11, 8, 5, 0, 5, 2, 2, 0, 11, 10, 15, 14, 8, 10, 15, 15, 13, 3, 2, 8, 5, 5, 4, 13, 0, 10, 4, 14, 10, 4, 9, 1, 9, 11, 12, 1, 5, 4, 8, 10, 3, 5, 13, 10, 11, 1, 7, 7, 13, 14, 9, 5, 10, 4, 4, 9, 12, 5, 14, 12, 1, 13, 6, 10, 5, 15, 8, 5, 5, 12, 2, 11, 2, 1, 1, 2, 6, 8, 6, 13, 7, 11, 3, 7, 13, 10, 2, 11].to_vec();

        let msg_len = msg.len();


        let expected_hex_out = blake3::hash(&nib_to_byte_array(&msg)).to_string();
        println!("expected {:?}", expected_hex_out);

        let inp =     script! {
            for nibble in msg {
                { nibble }
            }
        };
        stack.custom(
            script! { { inp } },
            0,
            false,
            0,
            "msg",
        );


        let start = stack.get_script().len();
        blake3(&mut stack, (msg_len/2) as u32, 8);
        let end = stack.get_script().len();
        println!("Blake3 size: {} for: {} bytes", end - start, (msg_len/2) as u32);


        stack.custom(
            script! { {verify_blake3_hash(&expected_hex_out)}},
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();
        let res =  stack.run();
        assert!(res.success);
    }

    #[test]
    fn test_blake3() {
        let hex_out = "86ca95aefdee3d969af9bcc78b48a5c1115be5d66cafc2fc106bbd982d820e70";

        let mut stack = StackTracker::new();

        let hex_in = "00000001".repeat(16);
        stack.custom(
            script! { { u4_hex_to_nibbles(&hex_in) } },
            0,
            false,
            0,
            "msg",
        );

        let start = stack.get_script().len();
        let optimized_start = optimize(stack.get_script().compile()).len();

        blake3(&mut stack, 64, 8);
        let end = stack.get_script().len();
        println!("Blake3 size: {}", end - start);

        let optimized_end = optimize(stack.get_script().compile()).len();
        println!("Blake3 optimized size: {}", optimized_end - optimized_start);

        stack.custom(
            script! { {verify_blake3_hash(hex_out)}},
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();

        assert!(stack.run().success);

        //assert optimized version too
        let optimized = optimize(stack.get_script().compile());
        assert!(debug_script(optimized).0.result().unwrap().success);        

    }

    #[test]
    fn test_blake3_160() {
        let hex_out = "290eef2c4633e64835e2ea6395e9fc3e8bf459a7";

        let mut stack = StackTracker::new();

        let hex_in = "00000001".repeat(10);
        stack.custom(
            script! { { u4_hex_to_nibbles(&hex_in) } },
            0,
            false,
            0,
            "msg",
        );

        let start = stack.get_script().len();
        blake3(&mut stack, 40, 5);
        let end = stack.get_script().len();
        println!("Blake3 size: {}", end - start);

        stack.custom(
            script! { {verify_blake3_hash(hex_out)}},
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();

        assert!(stack.run().success);
    }

    fn test_long_blakes(repeat: u32, hex_out: &str) {
        let mut stack = StackTracker::new();

        let hex_in = "00000001".repeat(repeat as usize);
        stack.custom(
            script! { { u4_hex_to_nibbles(&hex_in) } },
            0,
            false,
            0,
            "msg",
        );

        let start = stack.get_script().len();
        let start_optimized = optimize(stack.get_script().compile()).len();
        blake3(&mut stack, repeat * 4, 8);
        let end = stack.get_script().len();
        println!("Blake3 size: {} for: {} bytes", end - start, repeat * 4);

        let end_optimized = optimize(stack.get_script().compile()).len();
        println!("Blake3 optimized size: {} for: {} bytes", end_optimized - start_optimized, repeat * 4);

        stack.custom(
            script! { {verify_blake3_hash(hex_out)}},
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_blake3_long() {
        let hex_out = "9bd93dd19a93d1d3522c6717d77a2e20e11b8627efa5df80c76d727ca7431892";
        test_long_blakes(20, hex_out);

        let hex_out = "08729d0161b725b93e83ce79b06c534ce7684d39e21ad05074b67e0ac89ef44a";
        test_long_blakes(40, hex_out);

        //limit not moving padding
        let hex_out = "f2487b9f736cc30faf28952733c95560dc60e72cc7731b03a9ecfc86665e2e85";
        test_long_blakes(48, hex_out);

        //limit full tables
        let hex_out = "034acb9761990badc714913b9bb6329d96ed91ea01530a55e8fd4c8ffb3aee42";
        test_long_blakes(57, hex_out);

        let hex_out = "a23e7a7e11ff2febf28a205c8dc0ca57ae4eb2d0eb079bb5c6a5bdcdd3e56de1";
        test_long_blakes(60, hex_out);

        //max limit
        let hex_out = "b6c1b3d6b1555e0d20bd5188e4b8b20488c36105fd9c8971ac10dd267e612e4f";
        test_long_blakes(72, hex_out);
    }

    #[test]
    fn test_rrot7() {
        let mut stack = StackTracker::new();
        let tables = TablesVars::new(&mut stack, true);

        let mut ret = Vec::new();
        ret.push(stack.number_u32(0xdeadbeaf));
        ret.push(stack.number_u32(0x01020304));

        let mut var_map: HashMap<u8, StackVariable> = HashMap::new();
        var_map.insert(0, ret[0]);
        var_map.insert(1, ret[1]);

        right_rotate7_xored(&mut stack, &mut var_map, 0, 1, &tables);

        stack.number_u32(0x57bf5f7b);

        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.drop(ret[1]);

        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_g() {
        let mut stack = StackTracker::new();

        let tables = TablesVars::new(&mut stack, true);

        let mut ret = Vec::new();
        for i in 0..6 {
            ret.push(stack.number_u32(i));
        }

        let mut var_map: HashMap<u8, StackVariable> = HashMap::new();
        var_map.insert(0, ret[0]);
        var_map.insert(1, ret[1]);
        var_map.insert(2, ret[2]);
        var_map.insert(3, ret[3]);

        let start = stack.get_script().len();
        g(
            &mut stack,
            &mut var_map,
            0,
            1,
            2,
            3,
            ret[4],
            ret[5],
            &tables,
            false,
        );
        let end = stack.get_script().len();
        println!("G size: {}", end - start);

        stack.number_u32(0xc4d46c6c); //b
        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.number_u32(0x6a063602); //c
        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.number_u32(0x6a003600); //d
        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.number_u32(0x0030006a); //a
        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.drop(ret[5]);
        stack.drop(ret[4]);
        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_round() {
        let mut stack = StackTracker::new();

        let tables = TablesVars::new(&mut stack, true);

        let mut var_map: HashMap<u8, StackVariable> = HashMap::new();
        let mut msg_map: HashMap<u8, StackVariable> = HashMap::new();
        for i in 0..16 {
            var_map.insert(i, stack.number_u32(i as u32));
            msg_map.insert(i, stack.number_u32(i as u32));
        }

        let start = stack.get_script().len();
        round(&mut stack, &mut var_map, &msg_map, &tables, false);
        let end = stack.get_script().len();
        println!("Round size: {}", end - start);
    }
}
