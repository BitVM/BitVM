
#[cfg(test)]
mod tests {
    use scripts::opcodes::pushable;
    use bitcoin_script::bitcoin_script as script;
    use scripts::opcodes::u160_std::*;
    use scripts::{opcodes::execute_script};
    use scripts::actor::{Player};

    pub fn test_player() -> Player {
        Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398")
    }

    #[test]
    fn test_from_hex_string() {
        // Test valid input
        let hex_string = "0x0123456789abcdef0123456789abcdef01234567";
        let u160 = U160::from(hex_string);
        assert_eq!(
            format!("{}", u160),
            "0x0123456789abcdef0123456789abcdef01234567"
        );

        // Test invalid input (wrong length)
        let invalid_hex_string = "0123456789abcdef0123456789abcdef012345";
        assert!(std::panic::catch_unwind(|| U160::from(invalid_hex_string)).is_err());
    }

    #[test]
    fn test_from_bytes() {
        let bytes: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let u160 = U160::from(bytes);
        assert_eq!(
            format!("{}", u160),
            "0x0102030405060708090a0b0c0d0e0f1011121314"
        );
    }

    #[test]
    fn test_u160_state() {
        let hex_string = "0x0123456789abcdef0123456789abcdef01234567";
        let u160 = U160::from(hex_string);
        let mut player = test_player();
        let script = script! {
            { u160_state_unlock(&mut player, "TEST_U160", u160.clone()) }
            { u160_state(&mut player, "TEST_U160") }
            { u160_push(u160) }
            u160_equalverify
            1
        };
        assert!(execute_script(script).success)
    }

    #[test]
    fn test_u160_push() {
        let u160_value = U160::from("0x0123456789abcdef0123456789abcdef01234567");
        let script = script! {
            { u160_push(u160_value) }

            // TODO: Removing the { } escape around hex values throws InvalidScript(NonMinimalPush)
            // in the interpreter so the macro seems to create wrong opcodes for this case
            0x67
            OP_EQUALVERIFY
            0x45
            OP_EQUALVERIFY
            0x23
            OP_EQUALVERIFY
            0x01
            OP_EQUALVERIFY
            0xef
            OP_EQUALVERIFY
            0xcd
            OP_EQUALVERIFY
            0xab
            OP_EQUALVERIFY
            0x89
            OP_EQUALVERIFY

            0x67
            OP_EQUALVERIFY
            0x45
            OP_EQUALVERIFY
            0x23
            OP_EQUALVERIFY
            0x01
            OP_EQUALVERIFY
            0xef
            OP_EQUALVERIFY
            0xcd
            OP_EQUALVERIFY
            0xab
            OP_EQUALVERIFY
            0x89
            OP_EQUALVERIFY

            0x67
            OP_EQUALVERIFY
            0x45
            OP_EQUALVERIFY
            0x23
            OP_EQUALVERIFY
            0x01
            OP_EQUAL
        };
        assert!(execute_script(script).success)
    }
}
