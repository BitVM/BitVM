use crate::treepp::{pushable, script, Script};

use crate::u4::u4_add::u4_arrange_nibbles;

use super::u4_std::u4_drop;


// And / Or / Xor tables are created here and can be used for bitwise operations
// Sadly for sha256 those does not fit well in memory at the same time and therefor
// and optimized version that is called half table is used for the operations

// As this operations are commutative there is no need to have the tables for both
// i.e: 15 & 7  AND  7 & 15  as the result would be the same, so half of the values 
// are stored on the tables, and to be used the values are ordered using min/max
// before using the lookup table



pub fn u4_push_or_table() -> Script {
    script! {
        OP_15
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_15
        OP_14
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_15
        OP_14
        OP_13
        OP_12
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_15
        OP_DUP
        OP_2DUP
        OP_11
        OP_DUP
        OP_2DUP
        OP_15
        OP_DUP
        OP_2DUP
        OP_11
        OP_DUP
        OP_2DUP
        OP_15
        OP_14
        OP_2DUP
        OP_11
        OP_10
        OP_2DUP
        OP_15
        OP_14
        OP_2DUP
        OP_11
        OP_10
        OP_2DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_11
        OP_DUP
        OP_9
        OP_DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_11
        OP_DUP
        OP_9
        OP_DUP
        OP_15
        OP_14
        OP_13
        OP_12
        OP_11
        OP_10
        OP_9
        OP_8
        OP_15
        OP_14
        OP_13
        OP_12
        OP_11
        OP_10
        OP_9
        OP_8
        OP_15
        OP_DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_7
        OP_DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_15
        OP_14
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_7
        OP_6
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_7
        OP_DUP
        OP_5
        OP_DUP
        OP_7
        OP_DUP
        OP_5
        OP_DUP
        OP_15
        OP_14
        OP_13
        OP_12
        OP_2OVER
        OP_2OVER
        OP_7
        OP_6
        OP_5
        OP_4
        OP_2OVER
        OP_2OVER
        OP_15
        OP_DUP
        OP_2DUP
        OP_11
        OP_DUP
        OP_2DUP
        OP_7
        OP_DUP
        OP_2DUP
        OP_3
        OP_DUP
        OP_2DUP
        OP_15
        OP_14
        OP_2DUP
        OP_11
        OP_10
        OP_2DUP
        OP_7
        OP_6
        OP_2DUP
        OP_3
        OP_2
        OP_2DUP
        OP_15
        OP_DUP
        OP_13
        OP_DUP
        OP_11
        OP_DUP
        OP_9
        OP_DUP
        OP_7
        OP_DUP
        OP_5
        OP_DUP
        OP_3
        OP_DUP
        OP_1
        OP_DUP
        OP_15
        OP_14
        OP_13
        OP_12
        OP_11
        OP_10
        OP_9
        OP_8
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
    }
}

pub fn u4_push_xor_table() -> Script {
    script! {
        OP_0
        OP_1
        OP_2
        OP_3
        OP_4
        OP_5
        OP_6
        OP_7
        OP_8
        OP_9
        OP_10
        OP_11
        OP_12
        OP_13
        OP_14
        OP_15
        OP_1
        OP_0
        OP_3
        OP_2
        OP_5
        OP_4
        OP_7
        OP_6
        OP_9
        OP_8
        OP_11
        OP_10
        OP_13
        OP_12
        OP_15
        OP_14
        OP_2
        OP_3
        OP_0
        OP_1
        OP_6
        OP_7
        OP_4
        OP_5
        OP_10
        OP_11
        OP_8
        OP_9
        OP_14
        OP_15
        OP_12
        OP_13
        OP_3
        OP_2
        OP_1
        OP_0
        OP_7
        OP_6
        OP_5
        OP_4
        OP_11
        OP_10
        OP_9
        OP_8
        OP_15
        OP_14
        OP_13
        OP_12
        OP_4
        OP_5
        OP_6
        OP_7
        OP_0
        OP_1
        OP_2
        OP_3
        OP_12
        OP_13
        OP_14
        OP_15
        OP_8
        OP_9
        OP_10
        OP_11
        OP_5
        OP_4
        OP_7
        OP_6
        OP_1
        OP_0
        OP_3
        OP_2
        OP_13
        OP_12
        OP_15
        OP_14
        OP_9
        OP_8
        OP_11
        OP_10
        OP_6
        OP_7
        OP_4
        OP_5
        OP_2
        OP_3
        OP_0
        OP_1
        OP_14
        OP_15
        OP_12
        OP_13
        OP_10
        OP_11
        OP_8
        OP_9
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
        OP_15
        OP_14
        OP_13
        OP_12
        OP_11
        OP_10
        OP_9
        OP_8
        OP_8
        OP_9
        OP_10
        OP_11
        OP_12
        OP_13
        OP_14
        OP_15
        OP_0
        OP_1
        OP_2
        OP_3
        OP_4
        OP_5
        OP_6
        OP_7
        OP_9
        OP_8
        OP_11
        OP_10
        OP_13
        OP_12
        OP_15
        OP_14
        OP_1
        OP_0
        OP_3
        OP_2
        OP_5
        OP_4
        OP_7
        OP_6
        OP_10
        OP_11
        OP_8
        OP_9
        OP_14
        OP_15
        OP_12
        OP_13
        OP_2
        OP_3
        OP_0
        OP_1
        OP_6
        OP_7
        OP_4
        OP_5
        OP_11
        OP_10
        OP_9
        OP_8
        OP_15
        OP_14
        OP_13
        OP_12
        OP_3
        OP_2
        OP_1
        OP_0
        OP_7
        OP_6
        OP_5
        OP_4
        OP_12
        OP_13
        OP_14
        OP_15
        OP_8
        OP_9
        OP_10
        OP_11
        OP_4
        OP_5
        OP_6
        OP_7
        OP_0
        OP_1
        OP_2
        OP_3
        OP_13
        OP_12
        OP_15
        OP_14
        OP_9
        OP_8
        OP_11
        OP_10
        OP_5
        OP_4
        OP_7
        OP_6
        OP_1
        OP_0
        OP_3
        OP_2
        OP_14
        OP_15
        OP_12
        OP_13
        OP_10
        OP_11
        OP_8
        OP_9
        OP_6
        OP_7
        OP_4
        OP_5
        OP_2
        OP_3
        OP_0
        OP_1
        OP_15
        OP_14
        OP_13
        OP_12
        OP_11
        OP_10
        OP_9
        OP_8
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0

    }
}

pub fn u4_push_and_table() -> Script {
    script! {
        OP_15
        OP_14
        OP_13
        OP_12
        OP_11
        OP_10
        OP_9
        OP_8
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
        OP_14
        OP_DUP
        OP_12
        OP_DUP
        OP_10
        OP_DUP
        OP_8
        OP_DUP
        OP_6
        OP_DUP
        OP_4
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_13
        OP_12
        OP_2DUP
        OP_9
        OP_8
        OP_2DUP
        OP_5
        OP_4
        OP_2DUP
        OP_1
        OP_0
        OP_2DUP
        OP_12
        OP_DUP
        OP_2DUP
        OP_8
        OP_DUP
        OP_2DUP
        OP_4
        OP_DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_11
        OP_10
        OP_9
        OP_8
        OP_2OVER
        OP_2OVER
        OP_3
        OP_2
        OP_1
        OP_0
        OP_2OVER
        OP_2OVER
        OP_10
        OP_DUP
        OP_8
        OP_DUP
        OP_10
        OP_DUP
        OP_8
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_9
        OP_8
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_1
        OP_0
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_8
        OP_DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
        OP_6
        OP_DUP
        OP_4
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_6
        OP_DUP
        OP_4
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_5
        OP_4
        OP_2DUP
        OP_1
        OP_0
        OP_2DUP
        OP_5
        OP_4
        OP_2DUP
        OP_1
        OP_0
        OP_2DUP
        OP_4
        OP_DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_4
        OP_DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_3
        OP_2
        OP_1
        OP_0
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_1
        OP_0
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
    }
}

pub fn u4_drop_logic_table() -> Script {
    u4_drop(16 * 16)
}

pub fn u4_push_lookup() -> Script {
    script! {
        256
        240
        224
        208
        192
        176
        160
        144
        128
        112
        96
        80
        64
        48
        32
        16
        OP_0   //zero is extra so it can be used as lshift4 changing the offset
    }
}

pub fn u4_push_half_xor_table() -> Script {
    script! {
        OP_0
        OP_1
        OP_0
        OP_2
        OP_3
        OP_0
        OP_3
        OP_2
        OP_1
        OP_0
        OP_4
        OP_5
        OP_6
        OP_7
        OP_0
        OP_5
        OP_4
        OP_7
        OP_6
        OP_1
        OP_0
        OP_6
        OP_7
        OP_4
        OP_5
        OP_2
        OP_3
        OP_0
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
        OP_8
        OP_9
        OP_10
        OP_11
        OP_12
        OP_13
        OP_14
        OP_15
        OP_0
        OP_9
        OP_8
        OP_11
        OP_10
        OP_13
        OP_12
        OP_15
        OP_14
        OP_1
        OP_0
        OP_10
        OP_11
        OP_8
        OP_9
        OP_14
        OP_15
        OP_12
        OP_13
        OP_2
        OP_3
        OP_0
        OP_11
        OP_10
        OP_9
        OP_8
        OP_15
        OP_14
        OP_13
        OP_12
        OP_3
        OP_2
        OP_1
        OP_0
        OP_12
        OP_13
        OP_14
        OP_15
        OP_8
        OP_9
        OP_10
        OP_11
        OP_4
        OP_5
        OP_6
        OP_7
        OP_0
        OP_13
        OP_12
        OP_15
        OP_14
        OP_9
        OP_8
        OP_11
        OP_10
        OP_5
        OP_4
        OP_7
        OP_6
        OP_1
        OP_0
        OP_14
        OP_15
        OP_12
        OP_13
        OP_10
        OP_11
        OP_8
        OP_9
        OP_6
        OP_7
        OP_4
        OP_5
        OP_2
        OP_3
        OP_0
        OP_15
        OP_14
        OP_13
        OP_12
        OP_11
        OP_10
        OP_9
        OP_8
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
    }
}

pub fn u4_push_half_and_table() -> Script {
    script! {
        OP_15
        OP_14
        OP_DUP
        OP_13
        OP_12
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_11
        OP_10
        OP_9
        OP_8
        OP_11
        OP_10
        OP_DUP
        OP_8
        OP_DUP
        OP_10
        OP_DUP
        OP_9
        OP_8
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
        OP_7
        OP_6
        OP_DUP
        OP_4
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_6
        OP_DUP
        OP_5
        OP_4
        OP_2DUP
        OP_1
        OP_0
        OP_2DUP
        OP_5
        OP_4
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_4
        OP_DUP
        OP_2DUP
        OP_3
        OP_2
        OP_1
        OP_0
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_3
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_1
        OP_0
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
    }
}

pub fn u4_drop_half_and() -> Script {
    u4_drop(136)
}

pub fn u4_push_half_lookup() -> Script {
    script! {
        136
        135
        133
        130
        126
        121
        115
        108
        100
        91
        81
        70
        58
        45
        31
        16
    }
}

pub fn u4_drop_half_lookup() -> Script {
    u4_drop(16)
}

pub fn u4_drop_lookup() -> Script {
    u4_drop(17)
}

pub fn u4_sort() -> Script {
    script! {
        OP_2DUP
        OP_MIN
        OP_TOALTSTACK
        OP_MAX
        OP_FROMALTSTACK
    }
}

pub fn u4_and_half_table(lookup: u32) -> Script {
    script! {
        { u4_sort() }
        { lookup - 1 }
        OP_ADD
        OP_PICK
        { lookup - 2 }
        OP_ADD
        OP_ADD
        OP_PICK
    }
}

pub fn u4_and(lookup: u32, table: u32) -> Script {
    script! {
        { lookup }
        OP_ADD
        OP_PICK
        { table }
        OP_ADD
        OP_ADD
        OP_PICK
    }
}

//(a xor b) = (a + b) - 2*(a & b)) = b - 2(a&b) + a
pub fn u4_xor_with_and(lookup: u32, table: u32) -> Script {
    script! {
        OP_2DUP
        { u4_and( lookup+2, table+2) }
        OP_DUP
        OP_ADD
        OP_SUB
        OP_ADD
    }
}

pub fn u4_xor_with_and_table(lookup: u32) -> Script {
    script! {
        OP_2DUP
        { u4_and_half_table( lookup+2) }
        OP_DUP
        OP_ADD
        OP_SUB
        OP_ADD
    }
}


pub fn u4_logic_nibs(nibble_count: u32, bases: Vec<u32>, offset: u32, do_xor_with_and: bool ) -> Script {
    let numbers = bases.len() as u32;
    script! {
        { u4_arrange_nibbles(nibble_count, bases) }
        for nib in 0..nibble_count {
            for i in 0..numbers-1 {
                if do_xor_with_and {
                    { u4_xor_with_and_table( offset - i - nib * numbers ) }
                } else {
                    { u4_and_half_table( offset - i - nib * numbers ) }
                }
            }
            OP_TOALTSTACK
        }

    }
}

pub fn u4_and_u32(bases: Vec<u32>, offset: u32) -> Script {
    u4_logic_nibs(8, bases, offset, false)
}

pub fn u4_xor_u32(bases: Vec<u32>, offset: u32, do_xor_with_and: bool) -> Script {
    u4_logic_nibs(8, bases, offset, do_xor_with_and)
}

#[cfg(test)]
mod tests {

    use crate::u4::u4_logic::*;
    use crate::u4::u4_shift::{u4_drop_rshift_tables, u4_push_rshift_tables};
    use crate::u4::u4_std::{u4_number_to_nibble, u4_u32_verify_from_altstack};
    use crate::{execute_script, treepp::script};

    #[test]
    fn test_xor_u32() {
        let script = script! {
            { u4_push_half_xor_table() }
            { u4_push_half_lookup()}
            { u4_number_to_nibble(0x87878787)}
            { u4_number_to_nibble(0xFF010203)}
            { u4_number_to_nibble(0xAABBCCDD)}
            { u4_logic_nibs( 8, vec![0,8,16], 24, false )}
            { u4_drop_half_lookup() }
            { u4_drop_half_and() }

            { u4_number_to_nibble(0xD23D4959)}
            { u4_u32_verify_from_altstack() }
            OP_TRUE


        };

        let res = execute_script(script);
        assert!(res.success);
    }
    #[test]
    fn test_xor_u32_with_and() {
        let script = script! {
            { u4_push_half_and_table() }
            { u4_push_half_lookup()}
            { u4_number_to_nibble(0x87878787)}
            { u4_number_to_nibble(0xFF010203)}
            { u4_number_to_nibble(0xAABBCCDD)}
            { u4_logic_nibs( 8, vec![0,8,16], 24, true )}
            { u4_drop_half_lookup() }
            { u4_drop_half_and() }

            { u4_number_to_nibble(0xD23D4959)}
            { u4_u32_verify_from_altstack() }
            OP_TRUE


        };

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_logic_u32_size() {
        let xor_x2 = u4_logic_nibs( 8, vec![0,8], 24, true );
        println!("{}", xor_x2.len());
        let xor_x3 = u4_logic_nibs( 8, vec![0,8,16], 24, true );
        println!("{}", xor_x3.len());
        let xor_x2 = u4_logic_nibs( 8, vec![0,8], 24, false );
        println!("{}", xor_x2.len());
        let xor_x3 = u4_logic_nibs( 8, vec![0,8,16], 24, false );
        println!("{}", xor_x3.len());

    }

    #[test]
    fn test_and_u32() {
        let script = script! {
            { u4_push_half_and_table() }
            { u4_push_half_lookup()}
            { u4_number_to_nibble(0x87878787)}
            { u4_number_to_nibble(0xFF010203)}
            { u4_number_to_nibble(0xAABBCCDD)}
            { u4_logic_nibs( 8, vec![0,8,16], 24, false )}
            { u4_drop_half_lookup() }
            { u4_drop_half_and() }

            { u4_number_to_nibble(0x82010001)}
            { u4_u32_verify_from_altstack() }
            OP_TRUE


        };

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_xor_half() {
        for x in 0..16 {
            for y in 0..16 {
                let script = script! {
                    { u4_push_half_and_table() }
                    { u4_push_half_lookup()}
                    {x}      // X
                    {y}       // Y
                    { u4_xor_with_and_table(2)}
                    { x ^ y}
                    OP_EQUALVERIFY
                    { u4_drop_half_lookup() }
                    { u4_drop_half_and() }
                    OP_TRUE
                };

                let res = execute_script(script);
                assert!(res.success);
            }
        }
    }
    #[test]
    fn test_and_half() {
        for x in 0..16 {
            for y in 0..16 {
                let script = script! {
                    { u4_push_half_and_table() }
                    { u4_push_half_lookup()}
                    {x}      // X
                    {y}       // Y
                    { u4_and_half_table(2)}
                    { x & y}
                    OP_EQUALVERIFY
                    { u4_drop_half_lookup() }
                    { u4_drop_half_and() }
                    OP_TRUE
                };

                let res = execute_script(script);
                assert!(res.success);
            }
        }
    }

    #[test]
    fn test_xor_with_and() {
        for x in 0..16 {
            for y in 0..16 {
                let script = script! {
                    { u4_push_and_table() }
                    { u4_push_lookup()}
                    {x}      // X
                    {y}       // Y
                    { u4_xor_with_and(1, 17)}
                    {x^y}
                    OP_EQUALVERIFY
                    { u4_drop_lookup() }
                    { u4_drop_logic_table() }
                    OP_TRUE
                };

                println!("{}", script.len());
                let res = execute_script(script);

                assert!(res.success);
            }
        }
    }

    #[test]
    fn test_xor_func() {
        let script = script! {
            { u4_push_xor_table() }
            { u4_push_lookup()}
            12      // X
            5       // Y
            { u4_and(1, 17)}
            9
            OP_EQUALVERIFY
            { u4_drop_lookup() }
            { u4_drop_logic_table() }
            OP_TRUE
        };

        println!("{}", script.len());
        let res = execute_script(script);

        assert!(res.success);
    }

    #[test]
    fn test_and_func() {
        let script = script! {
            { u4_push_and_table() }
            { u4_push_lookup()}
            12      // X
            5       // Y
            { u4_and(1, 17)}
            4
            OP_EQUALVERIFY
            { u4_drop_lookup() }
            { u4_drop_logic_table() }
            OP_TRUE
        };

        println!("{}", script.len());
        let res = execute_script(script);
        assert!(res.success);
    }
    #[test]
    fn test_lookup() {
        let script = script! {
            { u4_push_lookup() }
            15
            1
            OP_ADD
            OP_PICK
            256
            OP_EQUALVERIFY
            { u4_drop_lookup() }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
        let script = script! {
            { u4_push_lookup() }
            0
            1
            OP_ADD
            OP_PICK
            16
            OP_EQUALVERIFY
            { u4_drop_lookup() }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_shift4() {
        let script = script! {
            { u4_push_lookup() }
            0
            OP_PICK
            0
            OP_EQUALVERIFY
            { u4_drop_lookup() }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);

        let script = script! {
            { u4_push_lookup() }
            15
            OP_PICK
            240
            OP_EQUALVERIFY
            { u4_drop_lookup() }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_and() {
        let script = script! {
            { u4_push_and_table() }
            { u4_push_lookup()}
            { u4_push_rshift_tables() }
            12      // X
            5       // Y
            { 1 + 1 + 48 }       // offset (X + rshift size is the offset)
            OP_ADD
            OP_PICK
            { 1 + 48 }      // size of rshift
            OP_ADD
            OP_ADD
            OP_PICK
            4
            OP_EQUALVERIFY
            { u4_drop_rshift_tables() }
            { u4_drop_lookup() }
            { u4_drop_logic_table() }
            OP_TRUE
        };

        println!("{}", script.len());
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_xor() {
        let script = script! {
            { u4_push_xor_table() }
            { u4_push_lookup()}
            { u4_push_rshift_tables() }
            12      // X
            5       // Y
            { 1 + 1 + 48 }       // offset (X + rshift size is the offset)
            OP_ADD
            OP_PICK
            { 1 + 48 }      // size of rshift
            OP_ADD
            OP_ADD
            OP_PICK
            9
            OP_EQUALVERIFY
            { u4_drop_rshift_tables() }
            { u4_drop_lookup() }
            { u4_drop_logic_table() }
            OP_TRUE
        };

        println!("{}", script.len());
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_or() {
        let script = script! {
            { u4_push_or_table() }
            { u4_push_lookup()}
            { u4_push_rshift_tables() } // just as example for the delta
            12      // X
            5       // Y
            { 1 + 1 + 48 }       // offset (X + rshift size is the offset)
            OP_ADD
            OP_PICK
            { 1 + 48 }      // size of rshift
            OP_ADD
            OP_ADD
            OP_PICK
            13
            OP_EQUALVERIFY
            { u4_drop_rshift_tables() }
            { u4_drop_lookup() }
            { u4_drop_logic_table() }
            OP_TRUE
        };

        println!("{}", script.len());
        let res = execute_script(script);
        assert!(res.success);
    }
}
