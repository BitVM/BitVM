
#[cfg(test)]
mod test {
    use tapscripts::opcodes::execute_script;
    use bitcoin_script::bitcoin_script as script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use tapscripts::opcodes::u32_std::{u32_equal, u32_push};
    use tapscripts::opcodes::u32_add::*;
    use tapscripts::opcodes::pushable;
    
    #[test]
    fn test_u32_add() {
        let u32_value_a = 0xFFEEFFEEu32;
        let u32_value_b = 0xEEFFEEFFu32;

        let script = script! {
            { u32_push(u32_value_a) }
            { u32_push(u32_value_b) }
            { u32_add_drop(1, 0) }
            0xed OP_EQUALVERIFY
            0xee OP_EQUALVERIFY
            0xee OP_EQUALVERIFY
            0xee OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32_1add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let u32_value_a: u32 = prng.gen();
            let u32_value_a_plus_1 = u32_value_a.wrapping_add(1);

            let script = script! {
                { u32_push(u32_value_a) }
                u32_1add
                { u32_push(u32_value_a_plus_1) }
                u32_equal
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
