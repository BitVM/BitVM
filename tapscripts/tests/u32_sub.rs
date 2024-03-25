#[cfg(test)]
mod test {
    use tapscripts::opcodes::execute_script;
    use bitcoin_script::bitcoin_script as script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use tapscripts::opcodes::u32_std::{u32_equalverify, u32_push};
    use tapscripts::opcodes::u32_sub::*;
    use tapscripts::opcodes::pushable;
    
    #[test]
    fn test_u32_sub() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let u32_value_a: u32 = prng.gen();
        let u32_value_b: u32 = prng.gen();
        let u32_value_c = u32_value_a.wrapping_sub(u32_value_b);

        let script = script! {
            { u32_push(u32_value_a) }
            { u32_push(u32_value_b) }
            { u32_sub_drop(1, 0) }
            { u32_push(u32_value_c) }
            { u32_equalverify() }
            OP_PUSHNUM_1
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let script = script! {
            { u32_push(u32_value_b) }
            { u32_push(u32_value_a) }
            { u32_sub_drop(0, 1) }
            { u32_push(u32_value_c) }
            { u32_equalverify() }
            OP_PUSHNUM_1
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
}
