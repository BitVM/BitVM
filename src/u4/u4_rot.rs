use crate::treepp::{pushable, script, Script};
use crate::u4::u4_shift::*;

// rot right for n bits is constructed using shifting operations of two nibbles
// also, there is a function to prepare the nibbles to be shifted
// so if 0xff000001 is shifted right, then the nibble 1 is copied in front to be shifted into f

pub fn u4_push_rrot_tables() -> Script {
    script! {
       {  u4_push_2_nib_rshift_tables() }
    }
}

pub fn u4_drop_rrot_tables() -> Script {
    script! {
        { u4_drop_2_nib_rshift_tables() }
    }
}

pub fn u4_prepare_number(shift: u32, number_pos: u32, is_shift: bool) -> Script {
    let pos_shift = shift / 4;

    let pos_shift_extra = pos_shift + 1;
    script! {
        for _ in 8-pos_shift_extra ..8 {
            if is_shift {
                OP_0
            } else {
                { number_pos + 7-(8-pos_shift_extra) }
                OP_PICK
            }
        }
        for _ in 0..8-pos_shift {
            { number_pos + 7 + pos_shift_extra  }
            OP_PICK
        }

    }
}

pub fn u4_rrot(shift: u32, number_pos: u32, shift_tables: u32, is_shift: bool) -> Script {
    let bit_shift = shift % 4;
    //TODO: to improve, some operations of shifting zero into zero can be removed
    script! {
        { u4_prepare_number(shift, number_pos, is_shift ) }

        for i in 0..8 {
            if i == 7 {
                OP_SWAP
                { u4_2_nib_shift_n(bit_shift, shift_tables - 2 + (9-i) ) }
            } else {
                OP_OVER
                { u4_2_nib_shift_n(bit_shift, shift_tables - 2 + (10-i) ) }
            }
            OP_TOALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::u4::{
        u4_rot::*,
        u4_std::{u4_drop, u4_number_to_nibble},
    };
    use crate::{execute_script, treepp::script};
    use rand::Rng;

    #[test]
    fn test_prepare_number() {
        let script = script! {
            0
            255
            0
            1
            2
            3
            4
            5
            6
            7
            255
            255
            { u4_prepare_number( 7, 2, false ) }
        };

        let _ = execute_script(script);
    }

    #[test]
    fn test_prepare_number_for_shift() {
        let script = script! {
            0
            255
            15
            1
            2
            3
            4
            5
            6
            7
            255
            255
            { u4_prepare_number( 10, 2, true ) }
        };

        let _ = execute_script(script);
    }

    fn rrot(x: u32, n: u32) -> u32 {
        if n == 0 {
            return x;
        }
        (x >> n) | (x << (32 - n))
    }

    fn rshift(x: u32, n: u32) -> u32 {
        if n == 0 {
            return x;
        }
        x >> n
    }

    #[test]
    fn test_x() {
        let script = script! {
            { u4_number_to_nibble(0x80_00_00_01) }
            { u4_prepare_number(3, 0, false) }
            OP_OVER
        };
        let _ = execute_script(script);
    }
    #[test]
    fn test_rrot_shift() {
        let script = script! {
            { u4_push_rrot_tables() }
            { u4_number_to_nibble(0xF0_FF_FF_FF) }
            { u4_rrot(10, 0, 8, true ) }

            { u4_drop(8) }
            { u4_drop_rrot_tables() }

            { u4_number_to_nibble(rshift(0xF0FF_FFFF, 10)) }

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
    fn test_rrot() {
        let script = script! {
            { u4_rrot(7, 0, 8, false ) }
        };
        println!("{}", script.len());

        let script = script! {
            { u4_push_rrot_tables() }
            { u4_number_to_nibble(0xF0_00_10_01) }

            { u4_rrot(7, 0, 8, false ) }

            { u4_drop(8) }
            { u4_drop_rrot_tables() }

            { u4_number_to_nibble(rrot(0xF0_00_10_01, 7)) } //OP_FROMALTSTACK

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
    fn test_rrot_rand() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let x: u32 = rng.gen();
            let mut n: u32 = rng.gen();
            n %= 32;
            if n % 4 == 0 {
                n += 1;
            }

            let script = script! {
                { u4_push_rrot_tables() }
                { u4_number_to_nibble(x) }

                { u4_rrot(n, 0, 8, false ) }

                { u4_drop(8) }
                { u4_drop_rrot_tables() }

                { u4_number_to_nibble(rrot(x, n)) } //OP_FROMALTSTACK

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
    }

    #[test]
    fn test_rshift_rand() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let x: u32 = rng.gen();
            let mut n: u32 = rng.gen();
            n %= 32;
            if n % 4 == 0 {
                n += 1;
            }

            let script = script! {
                { u4_push_rrot_tables() }
                { u4_number_to_nibble(x) }

                { u4_rrot(n, 0, 8, true ) }

                { u4_drop(8) }
                { u4_drop_rrot_tables() }

                { u4_number_to_nibble(rshift(x, n)) } //OP_FROMALTSTACK

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
    }
}
