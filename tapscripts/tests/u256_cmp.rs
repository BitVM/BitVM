
#[cfg(test)]
mod test {
    use tapscripts::opcodes::execute_script;
    use bitcoin_script::bitcoin_script as script;
    use tapscripts::opcodes::u256_std_16x16::u256_push;
    use tapscripts::opcodes::u256_cmp_16x16::{u256_greaterthan, u256_lessthan};
    use tapscripts::opcodes::pushable;
    
    #[test]
    fn test_u256_lessthan() {
        let u256_value_a = [5u8; 32];
        let u256_value_b = [7u8; 32];

        let script = script! {
            { u256_push(u256_value_a) }
            { u256_push(u256_value_b) }
            u256_lessthan
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
    
    #[test]
    fn test_u256_greaterthan() {
        let u256_value_a = [0xFFu8; 32];
        let u256_value_b = [0x00u8; 32];

        let script = script! {
            { u256_push(u256_value_a) }
            { u256_push(u256_value_b) }
            u256_greaterthan
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
}