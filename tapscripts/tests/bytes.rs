
use tapscripts::opcodes::bytes::*;
use tapscripts::opcodes::execute_script;
use tapscripts::opcodes::pushable;
use bitcoin_script::bitcoin_script as script;

#[test]
fn test_santize_bytes_succeed() {
    let script = script! {
        0x22
        0x23
        0x24
        0x25
        { sanitize_bytes(2) }
        OP_2DROP OP_2DROP
        1
    };
    assert!(execute_script(script).success);

    let script = script! {
        0x256
        { sanitize_bytes(1) }
        OP_DROP
        1
    };
    assert!(!execute_script(script).success)
}

