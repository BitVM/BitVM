use scripts::opcodes::execute_script;
use scripts::opcodes::u32_std::u32_push;
use bitcoin_script::bitcoin_script as script;
use scripts::opcodes::u32_mul::*;
use scripts::opcodes::pushable;

#[test]
fn test_u8_to_bits() {
    let u8_value = 0x34u32;

    let script = script! {
        {u8_value}
        u8_to_bits
        0 OP_EQUALVERIFY
        0 OP_EQUALVERIFY
        1 OP_EQUALVERIFY
        0 OP_EQUALVERIFY
        1 OP_EQUALVERIFY
        1 OP_EQUALVERIFY
        0 OP_EQUALVERIFY
        0 OP_EQUAL
    };
    let exec_result = execute_script(script);
    assert!(exec_result.success)
}

#[test]
fn test_u32_to_bits() {
    let u32_value = 0x12345678u32;
    let script = script! {
        { u32_push(u32_value) }
        u32_to_bits
        0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY
        1 OP_EQUALVERIFY 1 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
        0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
        1 OP_EQUALVERIFY 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
        0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
        1 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY
        0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY
        1 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUAL
    };
    let exec_result = execute_script(script);
    assert!(exec_result.success)
}

#[test]
fn test_u32_to_u32compact() {
    let u32_value = 0x12345678u32;
    let script = script! {
        { u32_push(u32_value) }
        u32_to_u32compact
        0x5678 OP_EQUALVERIFY
        0x1234 OP_EQUAL
    };
    let exec_result = execute_script(script);
    assert!(exec_result.success)
}

#[test]
fn test_u32compact_to_u32() {
    let u32_value = 0x12345678u32;
    let script = script! {
        { u32_push(u32_value) }
        u32_to_u32compact
        u32compact_to_u32
        0x78 OP_EQUALVERIFY
        0x56 OP_EQUALVERIFY
        0x34 OP_EQUALVERIFY
        0x12 OP_EQUAL
    };
    let exec_result = execute_script(script);
    assert!(exec_result.success)
}

#[test]
fn test_u32compact_double() {
    let u32_value = 0x12345678u32;
    let script = script! {
        { u32_push(u32_value) }
        u32_to_u32compact
        u32compact_double
        0xacf0 OP_EQUALVERIFY
        0x2468 OP_EQUAL
    };
    let exec_result = execute_script(script);
    assert!(exec_result.success)
}

#[test]
fn test_u32compact_add() {
    let u32_value_a = 0xFFEEFFEEu32;
    let u32_value_b = 0xEEFFEEFFu32;

    let script = script! {
        { u32_push(u32_value_a) }
        u32_to_u32compact
        { u32_push(u32_value_b) }
        u32_to_u32compact
        { u32compact_add_drop(1, 0) }
        0xeeed OP_EQUALVERIFY
        0xeeee OP_EQUAL
    };
    let exec_result = execute_script(script);
    assert!(exec_result.success)
}

#[test]
fn test_u32compact_mul() {
    let u32_value_a = 0x12345678u32;
    let u32_value_b = 0x89abcdefu32;
    let script = script! {
        { u32_push(u32_value_a) }
        u32_to_u32compact
        { u32_push(u32_value_b) }
        u32compact_mul_drop
        0xd208 OP_EQUALVERIFY
        0xe242 OP_EQUAL
    };
    let exec_result = execute_script(script);
    assert!(exec_result.success)
}

#[test]
fn test_u32_mul() {
    let u32_value_a = 0x12345678u32;
    let u32_value_b = 0x89abcdefu32;

    let script = script! {
        { u32_push(u32_value_a) }
        { u32_push(u32_value_b) }
        u32_mul_drop
        0x08 OP_EQUALVERIFY
        0xd2 OP_EQUALVERIFY
        0x42 OP_EQUALVERIFY
        0xe2 OP_EQUAL
    };
    let exec_result = execute_script(script);
    assert!(exec_result.success)
}

