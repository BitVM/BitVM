use crate::treepp::{pushable, script, Script};
use crate::u4::{u4_add::*, u4_logic::*, u4_rot::*, u4_std::*};
use std::vec;

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

pub fn calculate_s_part_1(
    offset_number: u32,
    offset_rrot: u32,
    shift_value: Vec<u32>,
    last_is_shift: bool,
) -> Script {
    script! {
        { u4_rrot(shift_value[0], offset_number, offset_rrot, false) }
        { u4_rrot(shift_value[1], offset_number, offset_rrot, false) }
        { u4_rrot(shift_value[2], offset_number, offset_rrot, last_is_shift) }
    }
}

pub fn calculate_s_part_2(offset_and: u32, do_xor_with_and: bool) -> Script {
    script! {
        for _ in 0..24 {
            OP_FROMALTSTACK
        }

        { u4_xor_u32(vec![0,8,16], offset_and + 24, do_xor_with_and) }

    }
}

pub fn calculate_s(
    offset_number: u32,
    offset_rrot: u32,
    offset_and: u32,
    shift_value: Vec<u32>,
    last_is_shift: bool,
    do_xor_with_and: bool,
) -> Script {
    script! {
        { calculate_s_part_1(offset_number, offset_rrot, shift_value, last_is_shift) }
        { calculate_s_part_2(offset_and, do_xor_with_and) }
    }
}

fn get_w_pos(i: u32) -> u32 {
    
    (i + 1) * 8
}

fn get_extra_pos(i: u32) -> u32 { (i - 16) * 8 }

fn get_pos_var(name: char) -> u32 {
    let i = match name {
        'a' => 0,
        'b' => 1,
        'c' => 2,
        'd' => 3,
        'e' => 4,
        'f' => 5,
        'g' => 6,
        'h' => 7,
        _ => 0,
    };

    let top = 8 * 8;
    let base = top - 8;
    base - i * 8
}
pub fn debug() -> Script {
    script! {
        OP_DEPTH
        OP_TOALTSTACK
        60000
        OP_PICK
    }
}

pub fn ch_calculation(e: u32, f: u32, g: u32, offset_and: u32) -> Script {
    script! {
        for nib in 0..8 {

            { e + 7  }                         // e_nib_pos
            OP_PICK                                 // e[nib]
            OP_DUP                                  // e e

            OP_NEGATE
            OP_15
            OP_ADD                                  // e ~e

            { g + 7  + 2}                      // e  ~e  g_nib_pos (account for e and ~e)
            OP_PICK                                 // e  ~e  g

            { u4_and_half_table(nib + offset_and + 3) }   // e  ( ~e & g )
            OP_SWAP                                 // ( ~e & g ) e


            { f + 7  + 2}                      // ( ~e & g ) e f_nib_pos
            OP_PICK                                 // ( ~e & g ) e f

            { u4_and_half_table(nib + offset_and + 3) }   // ( ~e & g ) (e & f)
            { u4_xor_with_and_table(nib + offset_and + 2) }   // ( ~e & g ) ^ (e & f)

            //OP_TOALTSTACK
        }
    }
}

pub fn maj_calculation(a: u32, b: u32, c: u32, offset_and: u32) -> Script {
    script! {
        for nib in 0..8 {

            { a + 7  }                                    // a_nib_pos
            OP_PICK                                       // a[nib]

            { b + 7 + 1 }                                 // a b_nib_pos
            OP_PICK                                       // a b
            OP_2DUP                                       // a b a b

            { u4_xor_with_and_table(nib + offset_and + 4) }   // a b (a^b)

            { c + 7 + 3 }                                 // a b (a^b) c_nib_pos
            OP_PICK                                       // a b (a^b) c

            { u4_and_half_table(nib + offset_and + 4) }   // a b ((a^b) & c)
            OP_ROT
            OP_ROT                                        // ((a^b) & c) a b

            { u4_and_half_table(nib + offset_and + 3) }   // ((a^b) & c) (a & b)

            { u4_xor_with_and_table(nib + offset_and + 2) }   // ((a^b) & c) ^ (a & b)

        }
    }
}

pub fn schedule_iteration(
    i: u32,
    offset_top_sched: u32,
    offset_rot: u32,
    offset_and: u32,
    offset_add: u32,
    use_add_table: bool,
    do_xor_with_and: bool,
) -> Script {
    script! {
        { calculate_s( offset_top_sched - get_w_pos(i-15), offset_rot, offset_and, vec![7,18,3], true, do_xor_with_and)}
        { calculate_s( offset_top_sched - get_w_pos(i-2), offset_rot, offset_and, vec![17,19,10], true, do_xor_with_and)}
        { u4_fromaltstack(16) }
        { u4_copy_u32_from(offset_top_sched - get_w_pos(i-16)+16 )}   // this can be avoided arranging directly with roll
        { u4_copy_u32_from(offset_top_sched - get_w_pos(i-7)+24 )}
        { u4_add(8, vec![0, 8, 16, 24], offset_add + 32, use_add_table )}
        { u4_fromaltstack(8) }
    }
}

fn get_full_w_pos(top_table: u32, i: u32) -> u32 { top_table - (i + 1) * 8 }

pub fn sha256(num_bytes: u32) -> Script {
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
    println!("{:?}", bytes_per_chunk);
    println!("{:?}", padding_scripts);

    let add_size = 130;
    let sched_size = 128;
    let rrot_size = 96;
    let half_logic_size = 136 + 16;
    let mut tables_size = rrot_size + half_logic_size;
    let use_add_table = chunks == 1;
    if use_add_table {
        tables_size += add_size;
    }

    let sched_loop_offset_and = sched_size;
    let sched_loop_offset_rrot = sched_loop_offset_and + half_logic_size;
    let sched_loop_offset_add = sched_loop_offset_rrot + rrot_size;

    let full_sched_size = 512;
    let temp_vars_size = 8 * 8;

    let vars_top = temp_vars_size + full_sched_size;
    let main_loop_offset_and = vars_top;
    let main_loop_offset_rrot = main_loop_offset_and + half_logic_size;
    let main_loop_offset_add = main_loop_offset_rrot + rrot_size;

    script! {

        if use_add_table {
            { u4_push_add_tables() }
        }
        { u4_push_rrot_tables() }     // rshiftn 16*6= 96
        { u4_push_half_xor_table() }  // 136
        { u4_push_half_lookup() }     // 16
                                      // total :  136 + 16 + 96 = 248

        for c in 0..chunks {

            if c > 0 {
                //change and with xor
                //TODO: if lookup table is pushed first and substracted
                // then we could avoid changing it  ~(32 * chunk)
                { u4_drop_half_lookup() }
                { u4_drop_half_and() }
                { u4_push_half_xor_table() }
                { u4_push_half_lookup() }
            }

            for _ in 0..bytes_per_chunk[c as usize]*2 {
                { (tables_size + (num_bytes * 2) - 1 - (c*128))  }
                OP_ROLL
            }


            { padding_scripts.remove(0) }

            //schedule loop
            for i in 16..64 {
                { schedule_iteration(i, sched_size + get_extra_pos(i), sched_loop_offset_rrot + get_extra_pos(i), sched_loop_offset_and + get_extra_pos(i), sched_loop_offset_add + get_extra_pos(i), use_add_table, false) }
            }

            //change xor with and table
            { u4_toaltstack(full_sched_size) }
            { u4_drop_half_lookup() }
            { u4_drop_half_and() }
            { u4_push_half_and_table() }
            { u4_push_half_lookup() }
            { u4_fromaltstack(full_sched_size) }

            if c == 0 {
                //set initial variables a,b,c,d,e,f,g,h
                for value in INITSTATE.iter() {
                    { u4_number_to_nibble(*value) }
                }
            } else {
                { u4_fromaltstack( 64 )}
            }




            for i in 0..64 {

                //Calculate S1
                { calculate_s( get_pos_var('e'), main_loop_offset_rrot, main_loop_offset_and, vec![6, 11, 25], false, true  ) }
                { u4_fromaltstack(8)}


                //calculate ch (this leaves on the stack)
                { ch_calculation(8 + get_pos_var('e'), 8 + get_pos_var('f'), 8 + get_pos_var('g'), 8 + main_loop_offset_and ) }

                //calculate temp1
                { u4_copy_u32_from( 16 + get_full_w_pos(vars_top, i) ) }
                { u4_number_to_nibble(K[i as usize])}                    //this add can be optimized by adding nibble constants
                if use_add_table {
                    { u4_add(8, vec![0, 8], 32 + main_loop_offset_add, true) }        //this could be joined with the next one and a bigger table
                    { u4_fromaltstack(8)}
                    { u4_add(8, vec![0, 8, 16, 24 + get_pos_var('h') ], 24 + main_loop_offset_add, true) }  //consumes h
                } else {
                    { u4_add_no_table(8, vec![0, 8, 16, 24, 32 + get_pos_var('h') ]) }  //consumes h
                }
                //consumes previous numbers and leaves result on altstack

                //puts temp1 on stack
                { u4_fromaltstack(8)}

                //Calculate S0   (on altstack)
                { calculate_s( get_pos_var('a'),  main_loop_offset_rrot,  main_loop_offset_and, vec![2, 13, 22], false, true  ) }

                //Calculate maj  (on stack)
                { maj_calculation( get_pos_var('a'),  get_pos_var('b'),  get_pos_var('c'),  main_loop_offset_and ) }

                //copies temp1
                { u4_copy_u32_from(8) }

                //put S0 on stack
                { u4_fromaltstack(8)}

                //temp2 = maj + s0
                //calculate a = temp1 + temp2
                //consumes the three values and leaves a on the stack updated
                { u4_add(8, vec![0, 8, 16], main_loop_offset_add + 24, use_add_table) }
                { u4_fromaltstack(8)}


                //all this moves can be avoided doing index magic with get_pos_var('X', round)
                //b = a
                { u4_move_u32_from( temp_vars_size  ) }
                //c = b
                { u4_move_u32_from( temp_vars_size  ) }
                //d = c
                { u4_move_u32_from( temp_vars_size  ) }

                //e = d + temp1
                { u4_add(8, vec![32, temp_vars_size], main_loop_offset_add + 8, use_add_table ) }
                { u4_fromaltstack(8)}

                //f = e
                { u4_move_u32_from( temp_vars_size - 8 ) }
                //g = f
                { u4_move_u32_from( temp_vars_size - 8 ) }
                //h = g
                { u4_move_u32_from( temp_vars_size - 8) }

            }


            if c == 0 {
                // add constants to variables
                // and leave the result on the altstack
                // first chunk is added with the init state
                for i in (0..8).rev() {
                    { u4_number_to_nibble( INITSTATE[i] ) }
                    { u4_add(8, vec![0, 8], main_loop_offset_add + 8 - ((7-i) as u32 * 8), use_add_table ) }
                }
            } else {
                // following chunks are added with the previous result
                { u4_fromaltstack( 64 )}
                for i in 0..8 {
                    { u4_add_no_table(8, vec![0, 64 - i * 8]) }
                }
            }

            { u4_drop(64*8) }       // drop the whole schedule

            //if it's not the last chunk
            //save a copy of the result
            if chunks > 1 && c < chunks - 1 {
                { u4_fromaltstack( 64 )}
                for _ in 0..64 {
                    { 63 }
                    OP_PICK
                }
                { u4_toaltstack( 128 )}
            }


        }

        { u4_drop_half_lookup() }
        { u4_drop_half_and() }
        { u4_drop_rrot_tables() }
        if use_add_table {
            { u4_drop_add_tables() }
        }

        { u4_fromaltstack( 64 )}

    }
}

#[cfg(test)]
mod tests {

    use crate::hash::sha256_u4::*;
    use crate::{execute_script, treepp::script};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_sizes() {
        let x = sha256(80);
        println!("sha 80 bytes: {}", x.len());
        let x = sha256(32);
        println!("sha 32 bytes: {}", x.len());
        let x = calculate_s(20, 30, 40, vec![7, 18, 3], true, false);
        println!("compute s (xor)  : {}", x.len());
        let x = calculate_s(20, 30, 40, vec![7, 18, 3], true, true);
        println!("compute s (and)  : {}", x.len());
        let x = schedule_iteration(16, 128, 128, 300, 400, false, true);
        println!("schedule it : {}", x.len());
        let x = ch_calculation(10, 20, 30, 300);
        println!("compute ch  : {}", x.len());
        let x = maj_calculation(10, 20, 30, 300);
        println!("compute maj : {}", x.len());
    }

    #[test]
    fn test_shatemp() {
        let script = script! {
            { u4_number_to_nibble(0xdeadbeaf) }
            { u4_number_to_nibble(0x01020304) }
            { sha256(8) }
            { u4_drop(64)}
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
    }

    fn test_sha256(hex_in: &str) {
        let mut hasher = Sha256::new();
        let data = hex::decode(hex_in).unwrap();
        hasher.update(&data);
        let result = hasher.finalize();
        let res = hex::encode(result);
        println!("Result: {}", res);

        let script = script! {
            { u4_hex_to_nibbles(hex_in) }
            { sha256(hex_in.len() as u32 /2)}


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
        let hex: String = message
            .as_bytes()
            .iter()
            .map(|&b| format!("{:02x}", b))
            .collect();
        test_sha256(&hex);
        let message = "This is a longer message that still fits in one block!";
        let hex: String = message
            .as_bytes()
            .iter()
            .map(|&b| format!("{:02x}", b))
            .collect();
        test_sha256(&hex)
    }

    #[test]
    fn test_sha256_two_blocks() {
        let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaaaaaaaa";
        test_sha256(hex);
        let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001122334455667788";
        test_sha256(hex);
        let hex = "7788ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaa001122334455667788";
        test_sha256(hex);
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
        let script = script! {

            { u4_hex_to_nibbles(block_header) }
            { sha256(block_header.len() as u32 /2)}
            { sha256(32) }


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
