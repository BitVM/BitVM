
#[cfg(test)]
pub mod tests {
    use scripts::opcodes::pushable;
    use bitcoin_script::bitcoin_script as script;

    use scripts::opcodes::u32_state::{
        bit_state, bit_state_unlock, u2_state, u2_state_unlock, u8_state, u8_state_unlock,
    };
    use scripts::opcodes::execute_script;
    use scripts::opcodes::u32_state::{u32_state_bit, u32_state_bit_unlock};
    use scripts::actor::{Player};

    pub fn test_player() -> Player {
        Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398")
    }

    #[test]
    fn test_bit_state() {
        bit_state_test(0);
        bit_state_test(1);
    }

    fn bit_state_test(test_value: u32) {
        let mut player = test_player();
        let test_identifier = "my_test_identifier";
        let script = script! {
            // Unlocking script
            { bit_state_unlock(&mut player, test_identifier, None, test_value) }
            // Locking script
            { bit_state(&mut player, test_identifier, None) }

            // Ensure the correct value was pushed onto the stack
            {test_value} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }

    #[test]
    fn test_u2_state() {
        u2_state_test(0);
        u2_state_test(1);
        u2_state_test(2);
        u2_state_test(3);
    }

    fn u2_state_test(test_value: u32) {
        let mut player = test_player();
        let test_identifier = "my_test_identifier";
        let script = script! {
            // Unlocking script
            { u2_state_unlock(&mut player, test_identifier, None, test_value) }
            // Locking script
            { u2_state(&mut player, test_identifier, None) }

            // Ensure the correct value was pushed onto the stack
            {test_value} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }

    #[test]
    fn test_u8_state() {
        u8_state_test(0);
        u8_state_test(1);
        u8_state_test(3);
        u8_state_test(128);
        u8_state_test(255);
    }

    fn u8_state_test(test_value: u32) {
        let mut player = test_player();
        let test_identifier = "my_test_identifier";
        let script = script! {
            // Unlocking script
            { u8_state_unlock(&mut player, test_identifier, test_value as u8) }
            // Locking script
            { u8_state(&mut player, test_identifier) }

            // Ensure the correct value was pushed onto the stack
            {test_value} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }

    #[test]
    fn test_u32_state_bit() {
        let mut player = test_player();
        let test_identifier = "my_test_identifier";
        let bit_index = 15;
        let value = 0b1000_0000_0000_0000;
        let script = script! {
            // Unlocking script
            { u32_state_bit_unlock(&mut player, test_identifier, value, bit_index) }
            // Locking script
            { u32_state_bit(&mut player, test_identifier, bit_index) }

            // Ensure the correct value was pushed onto the stack
            1 OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }
}
