
#[cfg(test)]
mod test {
    use tapscripts::opcodes::pushable;
    use bitcoin_script::bitcoin_script as script;
    use tapscripts::opcodes::execute_script;
    use tapscripts::opcodes::vec::*;

    #[test]
    fn test_vec_equalverify(){
        // Case: succeed
        let script = script! {
            1 2 3 4 5 6 7 8
            1 2 3 4 5 6 7 8
            { vec_equalverify(8) }
            1
        };
        assert!(execute_script(script).success);

        // Case: fail
        let script = script! {
            1 2 3 4 5 6 7 8
            1 2 3 4 5 6 7 9
            { vec_equalverify(8) }
            1
        };
        assert!(!execute_script(script).success)
    }

    #[test]
    fn test_vec_equal(){
        // Case: succeed
        let script = script! {
            1 2 3 4 5 6 7 8
            1 2 3 4 5 6 7 8
            { vec_equal(8) }
        };
        assert!(execute_script(script).success);

        // Case: fail
        let script = script! {
            1 2 3 4 5 6 7 8
            1 2 3 4 5 6 7 9
            { vec_equal(8) }
        };
        assert!(!execute_script(script).success);
    }


}

