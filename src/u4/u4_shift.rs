use super::u4_std::u4_drop;
use crate::treepp::{pushable, script, Script};

// right and left shift tables for 3 bits options
// compressed to reduce the size of the script
// but in memory it will be 16*3 = 48

pub fn u4_push_lshift_tables() -> Script {
    //lshift3, lshift2, lshift1
    script! {
        OP_8
        OP_0
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_12
        OP_8
        OP_4
        OP_0
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_14
        OP_12
        OP_10
        OP_8
        OP_6
        OP_4
        OP_2
        OP_0
        OP_14
        OP_12
        OP_10
        OP_8
        OP_6
        OP_4
        OP_2
        OP_0
    }
}

pub fn u4_drop_lshift_tables() -> Script { u4_drop(16 * 3) }

pub fn u4_push_rshift_tables() -> Script {
    //rshift3, rshift2, rshift1
    script! {
    OP_1
    OP_DUP
    OP_2DUP
    OP_2DUP
    OP_2DUP
    OP_0
    OP_DUP
    OP_2DUP
    OP_2DUP
    OP_2DUP
    OP_3
    OP_DUP
    OP_2DUP
    OP_2
    OP_DUP
    OP_2DUP
    OP_1
    OP_DUP
    OP_2DUP
    OP_0
    OP_DUP
    OP_2DUP
    OP_7
    OP_DUP
    OP_6
    OP_DUP
    OP_5
    OP_DUP
    OP_4
    OP_DUP
    OP_3
    OP_DUP
    OP_2
    OP_DUP
    OP_1
    OP_DUP
    OP_0
    OP_DUP
      }
}

pub fn u4_drop_rshift_tables() -> Script { u4_drop(16 * 3) }

pub fn u4_push_2_nib_rshift_tables() -> Script {
    script! {
       { u4_push_lshift_tables() }
       { u4_push_rshift_tables() }
    }
}

pub fn u4_drop_2_nib_rshift_tables() -> Script {
    script! {
       { u4_drop_rshift_tables() }
       { u4_drop_lshift_tables() }
    }
}

//It will process a nibble and shift it left 1,2 or 3 bits
pub fn u4_lshift(n: u32, lshift_offset: u32) -> Script {
    script! {
        { lshift_offset + (16*(n-1)) }
        OP_ADD
        OP_PICK
    }
}

//It will process a nibble and shift it right 1,2 or 3 bits
pub fn u4_rshift(n: u32, rshift_offset: u32) -> Script {
    script! {
        { rshift_offset + (16*(n-1)) }
        OP_ADD
        OP_PICK
    }
}

// Assumes Y and X are on the stack and will produce YX >> n
// It calculates the offset doing (Y << (4-n)) & 15 + (X >> n) & 15
pub fn u4_2_nib_shift_n(n: u32, tables_offset: u32) -> Script {
    script! {
        { u4_lshift(4-n, tables_offset + (16*3) + 1)  }
        OP_SWAP
        { u4_rshift(n, tables_offset + 1)  }
        OP_ADD
    }
}

#[cfg(test)]
mod tests {

    use crate::treepp::{execute_script, script};
    use crate::u4::u4_shift::*;

    #[test]
    fn test_rshift() {
        let script = script! {
            { u4_push_rshift_tables() }
            15
            16         // 16 is the size of rshift 1,2,3 choosing 2
            OP_ADD
            OP_PICK
            3
            OP_EQUALVERIFY
            { u4_drop_rshift_tables() }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_lshift() {
        let script = script! {
            { u4_push_lshift_tables() }
            7
            0         // 16 is the size of rshift 1,2,3 choosing 1
            OP_ADD
            OP_PICK
            14
            OP_EQUALVERIFY
            { u4_drop_lshift_tables() }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_lshift_func() {
        for n in 1..4 {
            for x in 0..16 {
                let script = script! {

                    { u4_push_lshift_tables() }
                    { x }           //  X
                    { u4_lshift(n , 0)}
                    { (x << n) % 16 }
                    OP_EQUALVERIFY
                    { u4_drop_lshift_tables() }
                    OP_TRUE
                };

                let res = execute_script(script);
                assert!(res.success);
            }
        }
    }

    #[test]
    fn test_rshift_func() {
        for n in 1..4 {
            for x in 0..16 {
                let script = script! {

                    { u4_push_rshift_tables() }
                    { x }           //  X
                    { u4_lshift(n , 0)}
                    { (x >> n) % 16 }
                    OP_EQUALVERIFY
                    { u4_drop_rshift_tables() }
                    OP_TRUE
                };

                let res = execute_script(script);
                assert!(res.success);
            }
        }
    }

    #[test]
    fn test_2_nib_rshift_function() {
        for n in 1..4 {
            for y in 0..16 {
                for x in 0..16 {
                    let script = script! {
                        { u4_push_2_nib_rshift_tables() }
                        { x }           //  X
                        { y }          //  X  |  Y
                        { u4_2_nib_shift_n(n, 0) }
                        { (((y << 4)+x) >> n) % 16 }
                        OP_EQUALVERIFY
                        { u4_drop_2_nib_rshift_tables() }
                        OP_TRUE
                    };

                    let res = execute_script(script);
                    assert!(res.success);
                }
            }
        }
    }
}
