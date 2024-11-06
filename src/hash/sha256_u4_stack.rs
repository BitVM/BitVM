use crate::u4::{
    u4_add::{u4_add_carry_nested, u4_add_nested},
    u4_add_stack::*,
    u4_logic_stack::*,
    u4_rot_stack::*,
    u4_shift_stack::*,
    u4_std::*,
};
use bitcoin_script_stack::stack::{define_pushable, script, Script, StackTracker, StackVariable};
use bitcoin_scriptexec::Stack;
define_pushable!();
use core::num;
use std::{collections::HashMap, vec};

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

const INITSTATE_MAPPING: [char; 8] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];

const INITSTATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn scheduling_64_padding() -> [u32; 64] {
    const PADDING_64_BYTES: [u32; 16] = [
        0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000200,
    ];
    let mut result = [0; 64];
    result[..16].clone_from_slice(PADDING_64_BYTES.as_ref());

    for i in 16..64 {
        let s0 = result[i - 15].rotate_right(7)
            ^ result[i - 15].rotate_right(18)
            ^ (result[i - 15] >> 3);
        let s1 =
            result[i - 2].rotate_right(17) ^ result[i - 2].rotate_right(19) ^ (result[i - 2] >> 10);
        result[i] = result[i - 16]
            .wrapping_add(s0)
            .wrapping_add(result[i - 7])
            .wrapping_add(s1);
    }
    result
}

pub fn u4_number_to_nibble(n: u32) -> Script {
    //constant number used during "compile" time
    script! {
       for i in (0..8).rev() {
            { (n >> (i * 4)) & 0xF }
        }
    }
}

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
            results.push(script! {});
        }
        results.push(script1);
        results.push(script2);

        (results, chunks)
    } else {
        let (script1, _) = padding(num_bytes);
        let mut results = Vec::new();
        for _ in 0..(chunks - 1) {
            results.push(script! {});
        }
        results.push(script1);
        (results, chunks)
    }
}

pub fn padding(num_bytes: u32) -> (Script, u32) {
    let l = (num_bytes * 8) as i32;
    let mut k = 512 - l - 8 - 32; // heres is usually minus 8, but as
                                  // there will be never that many bytes to process
                                  // one u32 will be enough
    let mut chunks = 1;
    while k < 0 {
        k += 512;
        chunks += 1;
    }
    let zeros = k / 16;
    let extras = k % 16;

    (
        script! {
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
        chunks,
    )
}

pub fn calculate_s_nib(
    stack: &mut StackTracker,
    number: [StackVariable; 8],
    nib: u32,
    shift_table: StackVariable,
    shift_values: Vec<u32>,
    last_is_shift: bool,
    lookup_table: StackVariable,
    logic_table: StackVariable,
) -> StackVariable {
    let i = 7 - nib;
    let mut res = StackVariable::null();
    for (j, shift_value) in shift_values.iter().enumerate() {
        let pos_shift = shift_value / 4;
        let bit_shift = shift_value % 4;

        let do_first = !last_is_shift || j < shift_values.len() - 1 || (i + pos_shift) < 8;
        let do_second = !last_is_shift || j < shift_values.len() - 1 || (i + pos_shift + 1) < 8;

        let first_nibble = (i + pos_shift) % 8;
        let second_nibble = (i + pos_shift + 1) % 8;
        if do_first {
            let v = stack.copy_var(number[7 - first_nibble as usize]);
            stack.rename(v, format!("to_be_r_shifted_{}_{nib}", shift_value).as_str());
            let rshift = u4_rshift_stack(stack, shift_table, bit_shift);
            stack.rename(rshift, format!("r_shifted_{}_{nib}", shift_value).as_str());
        }
        if do_second {
            let v = stack.copy_var(number[7 - second_nibble as usize]);
            stack.rename(v, format!("to_be_l_shifted_{}_{nib}", shift_value).as_str());
            let lshift = u4_lshift_stack(stack, shift_table, 4 - bit_shift);
            stack.rename(lshift, format!("l_shifted_{}_{nib}", shift_value).as_str());
            let shifted = stack.op_add();
            stack.rename(shifted, format!("shifted_{}_{nib}", shift_value).as_str());
        }
        if j != 0 && do_first {
            res = u4_logic_with_table_stack(stack, lookup_table, logic_table);
        }
    }
    stack.rename(res, format!(r"s_{nib}").as_str());
    res
}

pub fn ch1_calculation_nib_stack(
    stack: &mut StackTracker,
    e: StackVariable,
    f: StackVariable,
    g: StackVariable,
    nib: u32,
    lookup: StackVariable,
    xortable: StackVariable,
    shift_table: StackVariable,
) -> StackVariable {
    stack.copy_var(g); // g[nib]
    stack.op_dup(); // g g

    stack.copy_var(f); // g g f[nib]

    u4_logic_with_table_stack(stack, lookup, xortable); // g (g^f)

    stack.copy_var(e); // // g (g^f) e

    u4_and_with_xor_stack(stack, lookup, xortable, shift_table); // g (g^f & e)

    let var = u4_logic_with_table_stack(stack, lookup, xortable); // g ^ ((f ^ g) & e)

    stack.rename(var, format!("ch_i_{}", nib).as_str());
    var
}

pub fn maj1_calculation_nib_stack(
    stack: &mut StackTracker,
    a: StackVariable,
    b: StackVariable,
    c: StackVariable,
    nib: u32,
    lookup: StackVariable,
    xortable: StackVariable,
    shift_table: StackVariable,
) -> StackVariable {
    stack.copy_var(a); // a[nib]

    stack.copy_var(b); // a b[nib]

    stack.copy_var(c); // a b c[nib]

    stack.op_3dup(); // a b c a b c

    u4_logic_with_table_stack(stack, lookup, xortable); // a b c a (b^c)

    u4_logic_with_table_stack(stack, lookup, xortable); // a b c (a^b^c)

    stack.op_sub(); // a b (c-a^b^c)
    stack.op_add(); // a (b+c-a^b^c)
    stack.op_add(); // a+b+c-a^b^c

    let var = u4_rshift_stack(stack, shift_table, 1);

    stack.rename(var, format!("maj_{nib}").as_str());
    var
}

pub fn u4_add_nibble_stack(
    stack: &mut StackTracker,
    carry: &mut StackVariable,
    number_count: u32,
    is_last: bool,
    quotient_table: StackVariable,
    modulo_table: StackVariable,
) -> StackVariable {
    if !carry.is_null() {
        stack.move_var(*carry);
        stack.op_add();
    }

    if modulo_table.is_null() || quotient_table.is_null() {
        if !is_last {
            let output_vars = vec![(1, "add_no_table".into()), (1, "carry_no_table".into())];
            let out = stack.custom_ex(
                u4_add_carry_nested(0, number_count).compile(),
                1,
                output_vars,
                0,
            );
            *carry = out[1];
            out[0]
        } else {
            {
                let output_vars = vec![(1, "add_no_table".into())];
                stack.custom_ex(u4_add_nested(0, number_count).compile(), 1, output_vars, 0)[0]
            }
        }
    } else {
        if !is_last {
            stack.op_dup();
        }
        let var = stack.get_value_from_table(modulo_table, None);

        //we don't care about the last carry
        if !is_last {
            stack.op_swap();
            //obtain the quotinent to be used as carry for the next addition
            *carry = stack.get_value_from_table(quotient_table, None);
        }
        var
    }
}

pub fn sha256_stack(
    stack: &mut StackTracker,
    num_bytes: u32,
    use_add_table: bool,
    use_full_xor: bool,
) -> Script {
    // up to 55 is one block and always supports add table
    // probably up to 68 bytes I can afford to load the add tables for the first chunk (but have I would have to unload it)

    let (mut padding_scripts, chunks) = double_padding(num_bytes);
    let mut bytes_per_chunk: Vec<u32> = Vec::new();
    let mut bytes_remaining = num_bytes;
    while bytes_remaining > 0 {
        if bytes_remaining > 64 {
            bytes_per_chunk.push(64);
            bytes_remaining -= 64;
        } else {
            bytes_per_chunk.push(bytes_remaining);
            bytes_remaining = 0;
        }
    }
    if bytes_per_chunk.len() < chunks as usize {
        bytes_per_chunk.push(0);
    }
    //println!("{:?}", bytes_per_chunk);
    //println!("{:?}", padding_scripts);

    let scheduling_64 = scheduling_64_padding();

    let mut message = (0..num_bytes * 2)
        .map(|i| stack.define(1, &format!("message[{}]", i)))
        .collect::<Vec<StackVariable>>();

    let (mut modulo, mut quotient) = match use_add_table {
        true => (
            u4_push_modulo_table_stack(stack),
            u4_push_quotient_table_stack(stack),
        ),
        false => (StackVariable::null(), StackVariable::null()),
    };

    stack.set_breakpoint("init");

    let shift_tables = u4_push_shift_tables_stack(stack);

    let (lookup, xor_table) = if use_full_xor {
        (
            u4_push_full_lookup_table_stack(stack),
            u4_push_xor_full_table_stack(stack),
        )
    } else {
        (
            u4_push_lookup_table_stack(stack),
            u4_push_xor_table_stack(stack),
        )
    };

    let mut varmap: HashMap<char, [StackVariable; 8]> = HashMap::new();
    let mut initstate: HashMap<char, [StackVariable; 8]> = HashMap::new();

    stack.set_breakpoint("load tables");
    for c in 0..chunks {
        //move the message to the top of the stack
        //this can be optimized only moving the las nibbles that would form an u32 with the first part of the padding
        let mut moved_message = (0..bytes_per_chunk[c as usize] * 2)
            .map(|i| stack.move_var(message[i as usize]))
            .collect::<Vec<StackVariable>>();
        message.drain(0..moved_message.len());

        stack.set_breakpoint("moved message");
        let is_64bytes_padding = num_bytes == 64 && c == 1;

        //complete message with padding
        if !is_64bytes_padding {
            stack.custom(padding_scripts.remove(0), 0, false, 0, "padding");
            let len = moved_message.len();
            if len < 128 {
                for i in 0..(128 - len) {
                    moved_message.push(stack.define(1, &format!("padding[{}]", i)));
                }
            }
            stack.set_breakpoint("padding");

            //redefine from nibbles to u32
            assert!(moved_message.len() == 128);
        }

        let mut schedule = Vec::new();
        for i in 0..16 {
            if is_64bytes_padding {
                break;
            }

            let mut sched = [StackVariable::null(); 8];
            for nib in 0..8 {
                sched[nib as usize] = moved_message[nib];
                stack.rename(
                    sched[nib as usize],
                    format!("schedule[{}][{}]", i, nib).as_str(),
                );
            }

            schedule.push(sched);
            moved_message.drain(0..8);
        }
        stack.set_breakpoint("schedule");
        for jj in 0..4 {
            if jj != 0 {
                //schedule loop
                for i in 16 * jj..16 * (jj + 1) {
                    if is_64bytes_padding {
                        break;
                    }
                    let mut sched: [StackVariable; 8] = [StackVariable::null(); 8];
                    let mut sched_carry = StackVariable::null();
                    for nib in (0..8).rev() {
                        calculate_s_nib(
                            stack,
                            schedule[i - 15],
                            nib,
                            shift_tables,
                            vec![7, 18, 3],
                            true,
                            lookup,
                            xor_table,
                        );
                        calculate_s_nib(
                            stack,
                            schedule[i - 2],
                            nib,
                            shift_tables,
                            vec![17, 19, 10],
                            true,
                            lookup,
                            xor_table,
                        );
                        stack.op_add();
                        stack.copy_var(schedule[i - 7][nib as usize]);
                        stack.op_add();
                        stack.move_var(schedule[i - 16][nib as usize]);
                        stack.op_add();
                        sched[nib as usize] = u4_add_nibble_stack(
                            stack,
                            &mut sched_carry,
                            4,
                            nib == 0,
                            quotient,
                            modulo,
                        );
                        stack.rename(sched[nib as usize], format!("sched_{}_{}", i, nib).as_str());
                    }
                    schedule.push(sched);

                    stack.set_breakpoint(&format!("schedule[{}]", i));
                }
            } else if c == 0 {
                for i in 0..INITSTATE.len() {
                    varmap.insert(INITSTATE_MAPPING[i], [StackVariable::null(); 8]);
                    for nib in 0..8 {
                        let var = stack.number(INITSTATE[i] << (nib * 4) >> 28);
                        stack.rename(var, format!("{}_{}", INITSTATE_MAPPING[i], nib).as_str());
                        varmap.get_mut(&INITSTATE_MAPPING[i]).unwrap()[nib as usize] = var;
                    }
                }
            } else {
                for i in 0..INITSTATE_MAPPING.len() {
                    for nib in 0..8 {
                        varmap.get_mut(&INITSTATE_MAPPING[i]).unwrap()[nib as usize] =
                            stack.copy_var(initstate[&INITSTATE_MAPPING[i]][nib as usize]);
                    }
                }
            }
            for i in 16 * jj..16 * (jj + 1) {
                let mut temp1_carry = StackVariable::null();
                let mut a_carry = StackVariable::null();
                let mut e_carry = StackVariable::null();
                let mut new_e = [StackVariable::null(); 8];
                let mut new_a = [StackVariable::null(); 8];
                for nib in (0..8).rev() {
                    let s1 = calculate_s_nib(
                        stack,
                        varmap[&'e'],
                        nib,
                        shift_tables,
                        vec![6, 11, 25],
                        false,
                        lookup,
                        xor_table,
                    );
                    stack.rename(s1, format!("s1_{}_{}", i, nib).as_str());
                    //calculate ch
                    ch1_calculation_nib_stack(
                        stack,
                        varmap[&'e'][nib as usize],
                        varmap[&'f'][nib as usize],
                        varmap[&'g'][nib as usize],
                        nib,
                        lookup,
                        xor_table,
                        shift_tables,
                    );

                    //calculate temp1
                    let h = varmap[&'h'][nib as usize];

                    stack.op_add();
                    stack.move_var(h);
                    stack.op_add();

                    if is_64bytes_padding {
                        let constant = K[i].wrapping_add(scheduling_64[i]);
                        stack.number((constant << (nib * 4)) >> 28);
                        stack.op_add();
                    }

                    let temp1 = if use_add_table && quotient.size() < 80 {
                        let mut temp1 = u4_add_nibble_stack(
                            stack,
                            &mut temp1_carry,
                            4,
                            nib == 0,
                            quotient,
                            modulo,
                        );

                        if nib != 0 {
                            stack.op_swap();
                        }

                        if !is_64bytes_padding {
                            stack.number((K[i] << (nib * 4)) >> 28);
                            stack.op_add();
                            if jj == 3 {
                                stack.move_var(schedule[i][nib as usize]);
                            } else {
                                stack.copy_var(schedule[i][nib as usize]);
                            }
                            stack.op_add();

                            temp1 = u4_add_nibble_stack(
                                stack,
                                &mut StackVariable::null(),
                                3,
                                nib == 0,
                                quotient,
                                modulo,
                            );

                            if nib != 0 {
                                //obtain the quotinent to be used as carry for the next addition
                                stack.op_rot();
                                temp1_carry = stack.op_add();
                                stack.rename(temp1_carry, "temp1_carry");
                                stack.op_swap();
                            }
                        }
                        temp1
                    } else {
                        let mut number_count = 4;
                        if !is_64bytes_padding {
                            number_count = 5;
                            stack.number((K[i] << (nib * 4)) >> 28);
                            stack.op_add();
                            if jj == 3 {
                                stack.move_var(schedule[i][nib as usize]);
                            } else {
                                stack.copy_var(schedule[i][nib as usize]);
                            }
                            stack.op_add();
                        }
                        let temp1 = u4_add_nibble_stack(
                            stack,
                            &mut temp1_carry,
                            number_count,
                            nib == 0,
                            quotient,
                            modulo,
                        );
                        if nib != 0 {
                            stack.op_swap();
                        }
                        temp1
                    };
                    stack.rename(temp1, format!("temp1_{}", nib).as_str());

                    stack.op_dup();
                    //Calculate S0
                    let s0 = calculate_s_nib(
                        stack,
                        varmap[&'a'],
                        nib,
                        shift_tables,
                        vec![2, 13, 22],
                        false,
                        lookup,
                        xor_table,
                    );
                    stack.rename(s0, format!("s0_{}_{}", i, nib).as_str());
                    stack.op_add();
                    //Calculate maj
                    let maj = maj1_calculation_nib_stack(
                        stack,
                        varmap[&'a'][nib as usize],
                        varmap[&'b'][nib as usize],
                        varmap[&'c'][nib as usize],
                        nib,
                        lookup,
                        xor_table,
                        shift_tables,
                    );
                    stack.rename(maj, "maj");
                    stack.op_add();
                    new_a[nib as usize] =
                        u4_add_nibble_stack(stack, &mut a_carry, 3, nib == 0, quotient, modulo);

                    stack.rename(a_carry, "a_carry");
                    stack.rename(new_a[nib as usize], format!("a_{}", nib).as_str());

                    if nib != 0 {
                        stack.op_rot();
                    } else {
                        stack.op_swap();
                    }
                    //e = d + temp1 (consumes d)
                    let d = varmap[&'d'][nib as usize];
                    stack.move_var(d);
                    stack.op_add();

                    new_e[nib as usize] =
                        u4_add_nibble_stack(stack, &mut e_carry, 2, nib == 0, quotient, modulo);
                    stack.rename(e_carry, "e_carry");
                }
                //reorder variables
                for nib in 0..8 {
                    varmap.get_mut(&'h').unwrap()[nib as usize] = varmap[&'g'][nib as usize];
                    varmap.get_mut(&'g').unwrap()[nib as usize] = varmap[&'f'][nib as usize];
                    varmap.get_mut(&'f').unwrap()[nib as usize] = varmap[&'e'][nib as usize];
                    varmap.get_mut(&'e').unwrap()[nib as usize] = new_e[nib as usize];
                    varmap.get_mut(&'d').unwrap()[nib as usize] = varmap[&'c'][nib as usize];
                    varmap.get_mut(&'c').unwrap()[nib as usize] = varmap[&'b'][nib as usize];
                    varmap.get_mut(&'b').unwrap()[nib as usize] = varmap[&'a'][nib as usize];
                    varmap.get_mut(&'a').unwrap()[nib as usize] = new_a[nib as usize];
                    for c in INITSTATE_MAPPING.iter() {
                        stack.rename(varmap[c][nib as usize], &format!("{}_{}_{}", c, i, nib));
                    }
                }

                stack.set_breakpoint(&format!("loop[{}]", i));
            }
        }

        if c == 0 {
            //first chunk adds with init state
            for i in (0..INITSTATE_MAPPING.len()).rev() {
                initstate.insert(INITSTATE_MAPPING[i], [StackVariable::null(); 8]);
                for nib in (0..8).rev() {
                    let x = (*varmap.get(&INITSTATE_MAPPING[i]).unwrap())[nib as usize];
                    stack.move_var(x);
                    if nib != 7 {
                        stack.op_add();
                    }

                    stack.number(INITSTATE[i] << (nib * 4) >> 28);
                    stack.op_add();
                    initstate.get_mut(&INITSTATE_MAPPING[i]).unwrap()[nib as usize] =
                        u4_add_nibble_stack(
                            stack,
                            &mut StackVariable::null(),
                            2,
                            nib == 0,
                            quotient,
                            modulo,
                        );
                    stack.rename(
                        initstate.get(&INITSTATE_MAPPING[i]).unwrap()[nib as usize],
                        &format!("h{}_{}", i, nib),
                    );
                }
            }
        } else {
            //first chunk adds with init state
            for i in (0..INITSTATE_MAPPING.len()).rev() {
                for nib in (0..8).rev() {
                    let x = (*varmap.get(&INITSTATE_MAPPING[i]).unwrap())[nib as usize];
                    stack.move_var(x);
                    if nib != 7 {
                        stack.op_add();
                    }

                    stack.move_var(initstate[&INITSTATE_MAPPING[i]][nib as usize]);
                    stack.op_add();
                    initstate.get_mut(&INITSTATE_MAPPING[i]).unwrap()[nib as usize] =
                        u4_add_nibble_stack(
                            stack,
                            &mut StackVariable::null(),
                            2,
                            nib == 0,
                            quotient,
                            modulo,
                        );
                    stack.rename(
                        initstate.get(&INITSTATE_MAPPING[i]).unwrap()[nib as usize],
                        &format!("h{}_{}", i, nib),
                    );
                }
            }
        }

        stack.set_breakpoint("var addition");

        // if last chunk drop the tables
        if c == chunks - 1 {
            // reverse the order of the variables
            for i in 0..INITSTATE_MAPPING.len() {
                for nib in 0..8 {
                    stack.move_var(initstate[&INITSTATE_MAPPING[i]][nib as usize]);
                }
            }

            stack.to_altstack_count(64);
            stack.drop(xor_table);
            stack.drop(lookup);
            stack.drop(shift_tables);
            if use_add_table {
                stack.drop(quotient);
                stack.drop(modulo);
            }
        }
        stack.set_breakpoint("dropped");
    }
    for i in 0..INITSTATE_MAPPING.len() {
        *varmap.get_mut(&INITSTATE_MAPPING[i]).unwrap() =
            stack.from_altstack_count(8).try_into().unwrap();
    }

    stack.set_breakpoint("final");

    stack.get_script()
}

#[cfg(test)]
mod tests {
    use bitcoin_script::Script as StructuredScript;
    use bitcoin_script_stack::stack::{define_pushable, script, Script, StackTracker};
    define_pushable!();

    use super::*;
    use crate::execute_script;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_sizes_tmp() {
        let mut stack = StackTracker::new();
        let x = sha256_stack(&mut stack, 32, true, true);
        println!("sha 32 bytes: {}", x.len());
        println!("max stack: {}", stack.get_max_stack_size());

        let mut stack = StackTracker::new();
        let x = sha256_stack(&mut stack, 80, true, true);
        println!("sha 80 bytes: {}", x.len());
        println!("max stack: {}", stack.get_max_stack_size());
    }

    #[test]
    fn test_shatemp() {
        let mut stack = StackTracker::new();
        stack.custom(
            script! {
                {u4_number_to_nibble(0xdeadbeaf)}
                {u4_number_to_nibble(0x01020304)}
            },
            0,
            false,
            0,
            "message",
        );

        sha256_stack(&mut stack, 8, true, true);
        stack.run();
    }
    pub fn u4_hex_to_nibbles(hex_str: &str) -> Script {
        let nibbles: Result<Vec<u8>, std::num::ParseIntError> = hex_str
            .chars()
            .map(|c| u8::from_str_radix(&c.to_string(), 16))
            .collect();
        let nibbles = nibbles.unwrap();
        script! {
            for nibble in nibbles {
                { nibble }
            }
        }
    }
    fn test_sha256(hex_in: &str, use_add_table: bool, use_full_xor: bool) {
        let mut hasher = Sha256::new();
        let data = hex::decode(hex_in).unwrap();
        hasher.update(&data);
        let result = hasher.finalize();
        let res = hex::encode(result);
        println!("Result: {}", res);

        let mut stack = StackTracker::new();
        stack.custom(
            script! {
                {u4_hex_to_nibbles(hex_in)}
            },
            0,
            false,
            0,
            "message",
        );
        // stack.custom(y, 0, false, 0, "message");
        let s = sha256_stack(
            &mut stack,
            hex_in.len() as u32 / 2,
            use_add_table,
            use_full_xor,
        );
        println!("script len{}", s.len());

        stack.to_altstack_count(64);
        let mut expected = stack.var(64, u4_hex_to_nibbles(res.as_str()), "expected");
        let mut result = stack.from_altstack_joined(64, "res");
        stack.debug();
        stack.op_true();
        stack.equals(&mut result, true, &mut expected, true);
        let res = stack.run();
        assert!(res.success);
        let s = stack.get_script();
        println!("{}", s.len());
        let res = execute_script(StructuredScript::new("").push_script(s));
        assert!(res.success);
    }
    #[test]
    fn foostack80() {
        test_sha256("b2222696d574e2c595e60b97b5fd30fe5efb9535de84214ad9dac92fb9a82f477cb5ffa4cefe9f749c4c5dd6190cfd197c30d1351a9db171a05883bf3f207a1045654654457567547547456775647654", true, true);
        test_sha256("b2222696d574e2c595e60b97b5fd30fe5efb9535de84214ad9dac92fb9a82f477cb5ffa4cefe9f749c4c5dd6190cfd197c30d1351a9db171a05883bf3f207a1045654654457567547547456775647654", true, false);
        test_sha256("b2222696d574e2c595e60b97b5fd30fe5efb9535de84214ad9dac92fb9a82f477cb5ffa4cefe9f749c4c5dd6190cfd197c30d1351a9db171a05883bf3f207a1045654654457567547547456775647654", false, true);
        test_sha256("b2222696d574e2c595e60b97b5fd30fe5efb9535de84214ad9dac92fb9a82f477cb5ffa4cefe9f749c4c5dd6190cfd197c30d1351a9db171a05883bf3f207a1045654654457567547547456775647654", false, false);
    }
    #[test]
    fn foostack64() {
        test_sha256("b2222696d574e2c595e60b97b5fd30fe5efb9535de84214ad9dac92fb9a82f477cb5ffa4cefe9f749c4c5dd6190cfd197c30d1351a9db171a05883bf3f207a10", true, true);
        test_sha256("b2222696d574e2c595e60b97b5fd30fe5efb9535de84214ad9dac92fb9a82f477cb5ffa4cefe9f749c4c5dd6190cfd197c30d1351a9db171a05883bf3f207a10", true, false);
        test_sha256("b2222696d574e2c595e60b97b5fd30fe5efb9535de84214ad9dac92fb9a82f477cb5ffa4cefe9f749c4c5dd6190cfd197c30d1351a9db171a05883bf3f207a10", false, true);
        test_sha256("b2222696d574e2c595e60b97b5fd30fe5efb9535de84214ad9dac92fb9a82f477cb5ffa4cefe9f749c4c5dd6190cfd197c30d1351a9db171a05883bf3f207a10", false, false);
    }
    #[test]
    fn foostack32() {
        test_sha256(
            "b2222696d574e2c595e60b97b5fd30fe5efb9535de8421654543534534742475",
            true,
            true,
        );
        test_sha256(
            "b2222696d574e2c595e60b97b5fd30fe5efb9535de8421654543534534742475",
            true,
            false,
        );
        test_sha256(
            "b2222696d574e2c595e60b97b5fd30fe5efb9535de8421654543534534742475",
            false,
            true,
        );
        test_sha256(
            "b2222696d574e2c595e60b97b5fd30fe5efb9535de8421654543534534742475",
            false,
            false,
        );
    }
    #[test]
    fn test_sha256_strs() {
        let message = "Hello.";
        let hex: String = message
            .as_bytes()
            .iter()
            .map(|&b| format!("{:02x}", b))
            .collect();
        test_sha256(&hex, true, true);
        let message = "This is a longer message that still fits in one block!";
        let hex: String = message
            .as_bytes()
            .iter()
            .map(|&b| format!("{:02x}", b))
            .collect();
        test_sha256(&hex, true, true)
    }

    #[test]
    fn test_sha256_two_blocks() {
        let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaaaaaaaa";
        test_sha256(hex, true, true);
        let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001122334455667788";
        test_sha256(hex, true, true);
        let hex = "7788ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaa001122334455667788";
        test_sha256(hex, true, true);
    }

    #[test]
    fn test_padding() {
        let (script, _) = padding(1);
        let script = script! {
            { 0}
            { 1 }
            { script }
            { u4_drop(128).compile() }
            OP_TRUE
        };

        let res = execute_script(StructuredScript::new("").push_script(script));
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
                { u4_drop(chunks*128).compile() }
                OP_DEPTH
                OP_TOALTSTACK
                OP_TRUE
            };

            let res = execute_script(StructuredScript::new("").push_script(script));
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
        stack.custom(
            script! { {u4_hex_to_nibbles(block_header)}},
            0,
            false,
            0,
            "message",
        );
        sha256_stack(&mut stack, block_header.len() as u32 / 2, true, true);
        let shascript = sha256_stack(&mut stack, 32, true, true);

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
        let res = execute_script(StructuredScript::new("").push_script(script));
        assert!(res.success);
    }
}
