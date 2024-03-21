
use tapscripts::opcodes::pushable;
use bitcoin_script::bitcoin_script as script;
use tapscripts::opcodes::u32_std::*;
use tapscripts::opcodes::execute_script;

#[test]
fn test_u32_push() {
    let script = script! {
        { u32_push(0x01020304) }
        0x04
        OP_EQUALVERIFY
        0x03
        OP_EQUALVERIFY
        0x02
        OP_EQUALVERIFY
        0x01
        OP_EQUAL
    };

    assert!(execute_script(script).success)
}
