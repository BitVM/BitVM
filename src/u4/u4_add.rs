use crate::treepp::{script, Script};
use bitcoin::opcodes::all::*;

use super::u4_std::{u4_drop, CalculateOffset};

// Add it's performed be adding nibble by nibble, then duplicating the result
// and then using two lookup tables to obtain the modulo and the quotient.

// The modulo represent the result for the particular nibble
// and the quotient it's used as carry for the next nibble

// The lookup tables currently have 65 entries
// because it was created to support up to 4 additions
// simultaneously to improve the performance as
// carry only needs to be calculated once
//
// 5 additions would be great and would allow to avoid one currently splitted operation on sha
// but it's not fitting on the 1000k stack limit (alongside the rest of the tables and variables)

pub fn u4_push_quotient_table() -> Script {
    script! {
        OP_4
        OP_3
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_2
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_1
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
    }
}

pub fn u4_push_quotient_table_5() -> Script {
    script! {
        OP_4
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_2
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_1
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
    }
}

pub fn u4_drop_quotient_table() -> Script { u4_drop(65) }

pub fn u4_push_modulo_table() -> Script {
    script! {
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

pub fn u4_push_modulo_table_5() -> Script {
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

pub fn u4_drop_modulo_table() -> Script { u4_drop(65) }

//130 bytes
pub fn u4_push_add_tables() -> Script {
    script! {
        { u4_push_modulo_table() }
        { u4_push_quotient_table() }
    }
}

pub fn u4_drop_add_tables() -> Script {
    script! {
        { u4_drop_quotient_table() }
        { u4_drop_modulo_table() }
    }
}

pub fn u4_arrange_nibbles(nibble_count: u32, mut bases: Vec<u32>) -> Script {
    bases.sort();
    bases.reverse();
    for i in 0..bases.len() {
        bases[i] += nibble_count - 1;
    }

    script! {
        for i in 0..nibble_count {
            for (n, base) in bases.iter().enumerate() {
                {  (base - i)  +  ((n as u32 + 1) * (i + 1)) - 1 }
                OP_ROLL
            }
        }
    }
}

pub fn u4_add_carry_nested(current: u32, limit: u32) -> Script {
    script! {
        OP_DUP
        OP_16
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_16
            OP_SUB
            if current + 1 == limit {
                { current }
            } else {
                { u4_add_carry_nested(current+1, limit)}
            }
        OP_ELSE
            { current }
        OP_ENDIF
    }
}

pub fn u4_add_nested(current: u32, limit: u32) -> Script {
    script! {
        OP_DUP
        OP_16
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_16
            OP_SUB
            if current + 1 < limit {
                { u4_add_nested(current+1, limit)}
            }
        OP_ENDIF
    }
}

pub fn u4_add_no_table_internal(nibble_count: u32, number_count: u32) -> Script {
    script! {

        for i in 0..nibble_count {

            //add the column of nibbles (needs one less add than nibble count)
            for _ in 0..number_count-1 {
                OP_ADD
            }

            if i < nibble_count - 1 {
                { u4_add_carry_nested(0, number_count ) }
                OP_SWAP
                OP_TOALTSTACK
                OP_ADD
            } else {
                { u4_add_nested(0, number_count ) }
                OP_TOALTSTACK
            }

        }

    }
}

//assumes to habe the numbers prepared alongside nibble by nibble
//tables offset
pub fn u4_add_internal(nibble_count: u32, number_count: u32, tables_offset: u32) -> Script {
    let quotient_table_size = 65;
    //extra size on the stack
    let mut offset_calc: i32 = 0;
    let script = script! {

        for i in 0..nibble_count {

            //extra add to add the carry from previous addition
            if i > 0 {
                { offset_calc.modify(OP_ADD) }
            }

            //add the column of nibbles (needs one less add than nibble count)
            for _ in 0..number_count-1 {
                { offset_calc.modify(OP_ADD) }
            }

            // duplicate the result to be used to get the carry except for the last nibble
            if i < nibble_count -1 {
                { offset_calc.modify( OP_DUP) }
            }

            //get the modulo of the addition
            {  (offset_calc - 1)  + tables_offset as i32 + quotient_table_size }   // this adds 1 to the calc
            OP_ADD                                                    // and this one consumes it
            { offset_calc.modify( OP_PICK) }
            { offset_calc.modify( OP_TOALTSTACK) }

            //we don't care about the last carry
            if i < nibble_count - 1 {
                //obtain the quotinent to be used as carry for the next addition
                {  (offset_calc - 1) + tables_offset as i32 }
                OP_ADD
                { offset_calc.modify( OP_PICK) }
            }
        }


    };

    script
}

pub fn u4_add_with_table(nibble_count: u32, bases: Vec<u32>, tables_offset: u32) -> Script {
    let numbers = bases.len() as u32;
    script! {
        { u4_arrange_nibbles(nibble_count, bases)  }
        { u4_add_internal(nibble_count, numbers, tables_offset) }
    }
}

pub fn u4_add_no_table(nibble_count: u32, bases: Vec<u32>) -> Script {
    let numbers = bases.len() as u32;
    script! {
        { u4_arrange_nibbles(nibble_count, bases)  }
        { u4_add_no_table_internal(nibble_count, numbers) }
    }
}

pub fn u4_add(
    nibble_count: u32,
    bases: Vec<u32>,
    tables_offset: u32,
    use_add_table: bool,
) -> Script {
    if use_add_table {
        u4_add_with_table(nibble_count, bases, tables_offset)
    } else {
        u4_add_no_table(nibble_count, bases)
    }
}

#[cfg(test)]
mod tests {

    use crate::u4::{u4_add::*, u4_std::u4_number_to_nibble};
    use crate::{execute_script, treepp::script};

    #[test]
    fn test_calc() {
        let x = u4_arrange_nibbles(8, vec![0, 1, 2, 4]);
        println!("{}", x.len());
        let x = u4_add_with_table(8, vec![0, 8, 16, 24, 32], 100);
        println!("{}", x.len());
        let x = u4_add_with_table(8, vec![0, 8, 16, 24], 100);
        println!("{}", x.len());
        let x = u4_add_no_table(8, vec![0, 8, 16, 24, 32]);
        println!("{}", x.len());
        let x = u4_add_no_table(8, vec![0, 8, 16, 24]);
        println!("{}", x.len());
        let x = u4_add_no_table(8, vec![0, 8, 16]);
        println!("{}", x.len());
        let x = u4_add_no_table(8, vec![0, 8]);
        println!("{}", x.len());
    }

    #[test]
    fn test_add_no_table() {
        let calc = script! {
            { u4_add_no_table( 8, vec![0,8,16,24]) }
        };

        let script = script! {
            { u4_number_to_nibble(100) }
            { u4_number_to_nibble(200) }
            { u4_number_to_nibble(1000) }
            { u4_number_to_nibble(2000) }
            { u4_add_no_table( 8, vec![0,8,16,24]) }
            { u4_number_to_nibble(3300) }

            for _ in 0..8 {
                OP_FROMALTSTACK
            }
            for i in 0..8 {
                { 8 - i}
                OP_ROLL
                OP_EQUALVERIFY
            }
            OP_TRUE

        };
        let res = execute_script(script);
        assert!(res.success);
        println!("{}", calc.len());
    }

    #[test]
    fn test_add_2_32() {
        let script = script! {
            { u4_push_add_tables() }
            { u4_number_to_nibble(253) }
            { u4_number_to_nibble(252) }
            { u4_add_with_table( 8, vec![0,8], 16) }
            { u4_drop_add_tables() }
            { u4_number_to_nibble(505) }

            for _ in 0..8 {
                OP_FROMALTSTACK
            }
            for i in 0..8 {
                { 8 - i}
                OP_ROLL
                OP_EQUALVERIFY
            }
            OP_TRUE

        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_add_4_32() {
        let script = script! {
            { u4_push_add_tables() }
            { u4_number_to_nibble(100) }
            { u4_number_to_nibble(200) }
            { u4_number_to_nibble(1000) }
            { u4_number_to_nibble(2000) }
            { u4_add_with_table( 8, vec![0,8,16,24], 32) }
            { u4_drop_add_tables() }
            { u4_number_to_nibble(3300) }

            for _ in 0..8 {
                OP_FROMALTSTACK
            }
            for i in 0..8 {
                { 8 - i}
                OP_ROLL
                OP_EQUALVERIFY
            }
            OP_TRUE

        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_add_2() {
        let script = script! {
            { u4_push_add_tables() }
            15
            15
            13
            12
            { u4_add_internal(2, 2, 4) }
            { u4_drop_add_tables() }
            OP_FROMALTSTACK
            15
            OP_EQUALVERIFY
            OP_FROMALTSTACK
            9
            OP_EQUALVERIFY
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_add_step_by_step() {
        let script = script! {
            { u4_push_modulo_table() }
            { u4_push_quotient_table() }
            // fd + fc = 1f9 % 100 = f9
            15          // F
            15          // F F
            13          // F F D
            12          // F F D C

            OP_ADD      // F F 19
            OP_DUP      // F F 19 19
            { 65 + 3 }  // F F 19 19 68=offset modulo
            OP_ADD
            OP_PICK         // F F 19 9
            OP_TOALTSTACK   // F F 19     | 9
            { 2 }           // F F 19 2   | 9
            OP_ADD          // F F 21     | 9
            OP_PICK         // F F 1

            OP_ADD          // F 10
            OP_ADD          // 1F
            { 65 }          // 1F 65      | 9
            OP_ADD          // 1F+65      | 9
            OP_PICK         // F          | 9

            OP_FROMALTSTACK
            9
            OP_EQUALVERIFY
            15
            OP_EQUALVERIFY
            { u4_drop_modulo_table() }
            { u4_drop_quotient_table() }

            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
    }
    #[test]
    fn test_quotient() {
        for i in 0..65 {
            let script = script! {
                { u4_push_quotient_table() }
                { i as u32 }
                OP_PICK
                { i / 16 }
                OP_EQUALVERIFY
                { u4_drop_quotient_table() }
                OP_TRUE
            };

            let res = execute_script(script);
            assert!(res.success);
        }
    }

    #[test]
    fn test_modulo() {
        for i in 0..65 {
            let script = script! {
                { u4_push_modulo_table() }
                { i as u32 }
                OP_PICK
                { i % 16 }
                OP_EQUALVERIFY
                { u4_drop_modulo_table() }
                OP_TRUE
            };

            let res = execute_script(script);
            assert!(res.success);
        }
    }

    #[test]
    fn test_arrange() {
        let script = script! {
            1
            2
            3
            4
            5
            6
            7
            8
            9
            10
            11
            12
            { u4_arrange_nibbles(4, vec![0,4,8]) }

        };

        let _res = execute_script(script);
    }
}
