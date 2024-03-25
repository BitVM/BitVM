
#[cfg(test)]
mod test {
    use bitcoin::opcodes::OP_EQUALVERIFY;
    use tapscripts::opcodes::execute_script;
    use bitcoin_script::bitcoin_script as script;
    use tapscripts::opcodes::u256_std::u256_push;
    use tapscripts::opcodes::u256_zip::u256_zip;
    use tapscripts::opcodes::{pushable, unroll};
    
    #[test]
    fn test_u256_zip() {
        let u256_value_a: [u8; 32] = [0xFF, 0xEE, 0xFF, 0xEE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let u256_value_b: [u8; 32] = [0xEE, 0xFF, 0xEE, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let script = script! {
            { u256_push(u256_value_a) }
            { u256_push(u256_value_b) }
            { u256_zip(1, 0) }
            0xFF OP_EQUALVERIFY
            0xEE OP_EQUALVERIFY
            0xEE OP_EQUALVERIFY
            0xFF OP_EQUALVERIFY
            0xFF OP_EQUALVERIFY
            0xEE OP_EQUALVERIFY
            0xEE OP_EQUALVERIFY
            0xFF OP_EQUALVERIFY
            { unroll(56, |_| script! { 0 OP_EQUALVERIFY }) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
}