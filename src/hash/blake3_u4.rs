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
    half_lookup: StackVariable,
    xor_table: StackVariable,
}

impl TablesVars {
    pub fn new(stack: &mut StackTracker, use_full_tables: bool) -> Self {
        let modulo = u4_push_modulo_for_blake(stack);
        let quotient = u4_push_quotient_for_blake(stack);
        let shift_tables = u4_push_shift_for_blake(stack);
        let half_lookup = if !use_full_tables {
            u4_push_lookup_table_stack(stack)
        } else {
            u4_push_full_lookup_table_stack(stack)
        };
        let xor_table = if !use_full_tables {
            u4_push_xor_table_stack(stack)
        } else {
            u4_push_xor_full_table_stack(stack)
        };
        TablesVars {
            modulo,
            quotient,
            shift_tables,
            half_lookup,
            xor_table,
        }
    }

    pub fn drop(&self, stack: &mut StackTracker) {
        stack.drop(self.xor_table);
        stack.drop(self.half_lookup);
        stack.drop(self.shift_tables);
        stack.drop(self.quotient);
        stack.drop(self.modulo);
    }
}

pub fn right_rotate_xored(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    x: u8,
    y: u8,
    n: u8,
    tables: &TablesVars,
) -> StackVariable {
    let pos_shift = 8 - n / 4;

    let y = var_map[&y];
    let x = var_map.get_mut(&x).unwrap();

    let mut ret = Vec::new();

    for i in pos_shift..pos_shift + 8 {
        let n = i % 8;

        let mut z = 0;
        if i < 8 {
            z = pos_shift;
        }

        stack.move_var_sub_n(x, z as u32);
        stack.copy_var_sub_n(y, n as u32);

        let r0 = u4_logic_stack_nib(stack, tables.half_lookup, tables.xor_table, false);
        ret.push(r0);
    }

    stack.join_count(&mut ret[0], 7)
}

pub fn right_rotate7_xored_sub(
    stack: &mut StackTracker,
    x: &mut StackVariable,
    y: StackVariable,
    tables: &TablesVars,
    n: u8,
) {
    stack.from_altstack();

    stack.move_var_sub_n(x, 0);
    stack.copy_var_sub_n(y, n as u32);

    let r0 = u4_logic_stack_nib(stack, tables.half_lookup, tables.xor_table, false);
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
    stack.move_var_sub_n(x, 6);
    stack.copy_var_sub_n(y, 6);
    let z6 = u4_logic_stack_nib(stack, tables.half_lookup, tables.xor_table, false);
    stack.rename(z6, "z6");

    // nib 6 copy saved
    stack.copy_var(z6);
    stack.to_altstack();

    //nib 7 xored
    stack.move_var_sub_n(x, 6); // previous nib 7 as it was consumed
    stack.copy_var_sub_n(y, 7);

    let z7 = u4_logic_stack_nib(stack, tables.half_lookup, tables.xor_table, false);
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

pub fn g(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    mx: StackVariable,
    my: StackVariable,
    tables: &TablesVars,
) {
    //adds a + b + mx
    //consumes a and mx and copies b
    let vb = var_map[&b];
    let mut va = var_map.get_mut(&a).unwrap();
    u4_add_stack(
        stack,
        8,
        vec![vb, mx],
        vec![&mut va],
        vec![],
        tables.quotient,
        tables.modulo,
    );
    //stores the results in a
    *va = stack.from_altstack_joined(8, &format!("state_{}", a));

    // right rotate d xor a ( consumes d and copies a)
    let ret = right_rotate_xored(stack, var_map, d, a, 16, tables);
    // saves in d
    var_map.insert(d, ret);

    let vd = var_map[&d];
    let mut vc = var_map.get_mut(&c).unwrap();
    u4_add_stack(
        stack,
        8,
        vec![vd],
        vec![&mut vc],
        vec![],
        tables.quotient,
        tables.modulo,
    );
    *vc = stack.from_altstack_joined(8, &format!("state_{}", c));

    let ret = right_rotate_xored(stack, var_map, b, c, 12, tables);
    var_map.insert(b, ret);

    let vb = var_map[&b];
    let mut va = var_map.get_mut(&a).unwrap();
    u4_add_stack(
        stack,
        8,
        vec![vb, my],
        vec![&mut va],
        vec![],
        tables.quotient,
        tables.modulo,
    );
    *va = stack.from_altstack_joined(8, &format!("state_{}", a));

    let ret = right_rotate_xored(stack, var_map, d, a, 8, tables);
    var_map.insert(d, ret);
    stack.rename(ret, &format!("state_{}", d));

    let vd = var_map[&d];
    let mut vc = var_map.get_mut(&c).unwrap();
    u4_add_stack(
        stack,
        8,
        vec![vd],
        vec![&mut vc],
        vec![],
        tables.quotient,
        tables.modulo,
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
        for i in 0..8 {
            state.push(stack.number_u32(IV[i]));
        }
    }
    for i in 0..4 {
        state.push(stack.number_u32(IV[i]));
    }
    state.push(stack.number_u32(0));
    state.push(stack.number_u32(counter));
    state.push(stack.number_u32(block_len));
    state.push(stack.number_u32(flags));

    let mut state_map = HashMap::new();
    for i in 0..16 {
        state_map.insert(i as u8, state[i]);
        stack.rename(state[i], &format!("state_{}", i));
    }
    state_map
}

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
        round(stack, &mut state, &message, tables);

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
            stack.copy_var_sub_n(v2, n);
            let v1 = state.get_mut(&i).unwrap();
            stack.move_var_sub_n(v1, 0);
            tmp.push(u4_logic_stack_nib(
                stack,
                tables.half_lookup,
                tables.xor_table,
                false,
            ));

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

    let num_blocks = (msg_len + 64 - 1) / 64;
    let mut num_padding_bytes = num_blocks * 64 - msg_len;

    //to handle the message the padding needs to be multiple of 4
    //so if it's not multiple it needs to be added at the beginning
    let mandatory_first_block_padding = num_padding_bytes % 4;
    num_padding_bytes -= mandatory_first_block_padding;

    //to optimize space the original message already processed is moved and dropped early
    //but it consumes more opcodes, so it's done only if necessary
    let optimize_space = num_blocks > 3;

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

    let tables = TablesVars::new(stack, use_full_tables);

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

        // drop the processed messasge if we are in optimize space mode
        if optimize_space && !last_round {
            for j in 0..16 {
                let x = stack.move_var(original_message[j + (16 * i as usize)]);
                stack.drop(x);
            }
        }
    }

    // drop the padding
    for _ in 0..num_padding_bytes / 4 {
        stack.drop(stack.get_var_from_stack(0));
    }

    //drop tables
    tables.drop(stack);

    //drop the original message
    let mut to_drop = if optimize_space { 16 } else { 16 * num_blocks };
    to_drop -= num_padding_bytes / 4;
    for _ in 0..to_drop {
        stack.drop(stack.get_var_from_stack(0));
    }

    //get the result hash
    stack.from_altstack_joined(final_rounds as u32 * 8, "blake3-hash");
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    pub use bitcoin_script::script;
    //pub use bitcoin::ScriptBuf as Script;
    use bitcoin_script_stack::{script_util::verify_n, stack::StackTracker};

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

        let start = stack.get_script_len();
        blake3(&mut stack, 64, 8);
        let end = stack.get_script_len();
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

        let start = stack.get_script_len();
        blake3(&mut stack, 40, 5);
        let end = stack.get_script_len();
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

        let start = stack.get_script_len();
        blake3(&mut stack, repeat * 4, 8);
        let end = stack.get_script_len();
        println!("Blake3 size: {} for: {} bytes", end - start, repeat * 4);

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

        let start = stack.get_script_len();
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
        );
        let end = stack.get_script_len();
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

        let start = stack.get_script_len();
        round(&mut stack, &mut var_map, &msg_map, &tables);
        let end = stack.get_script_len();
        println!("Round size: {}", end - start);
    }
}
