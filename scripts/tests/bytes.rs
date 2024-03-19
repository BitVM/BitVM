
#[cfg(test)]
mod test {
    use scripts::opcodes::bytes::*;
    use scripts::opcodes::execute_script;
    use scripts::opcodes::pushable;
    use bitcoin_script::bitcoin_script as script;
    
    #[test]
    fn test_santize_bytes__succeed() {
        let script = script! {
            0x22
            0x23
            0x24
            0x25
            { sanitize_bytes(2) }
            OP_2DROP OP_2DROP
            1
        };
        assert!(execute_script(script).success)
    }

    #[test]
    fn test_santize_bytes__fail() {
        let script = script! {
            0x256
            { sanitize_bytes(1) }
            OP_DROP
            1
        };
        assert!(!execute_script(script).success)
    }
}
