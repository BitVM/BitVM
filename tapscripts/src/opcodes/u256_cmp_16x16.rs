#![allow(dead_code)]

use crate::opcodes::{
    unroll,
    u64_std_4x16::{
        u64_swap,
        u64_roll,
        u64_equal,
    }
};

use super::{pushable, u64_cmp_4x16::{u64_greaterthan, u64_lessthan}};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

// ((((((A_0 > B_0) && A_1 == B_1) || A_1 > B_1) && A_2 == B_2) || A_2 > B_2) && A_3 == B_3) || A_3 > B_3
fn u256_cmp(comparator: fn() -> Script) -> Script {
    script! {
        // A0 A1 A2 A3 B0 B1 B2 B3
        { u64_roll(4) } // 4 OP_ROLL
        // A0 A1 A2 B0 B1 B2 B3 A3
        u64_swap // OP_SWAP
        // A0 A1 A2 B0 B1 B2 A3 B3
        comparator
        // A0 A1 A2 B0 B1 B2 {comparator}
        {unroll(4, |_| script! {4 OP_ROLL})} // OP_SWAP
        // A0 A1 A2 B0 B1 {comparator} B2
        {unroll(4, |_| script! {16 OP_ROLL})} // 4 OP_ROLL
        // A0 A1 B0 B1 {comparator} B2 A2
        {unroll(8, |_| script! {7 OP_PICK})} // OP_2DUP
        // A0 A1 B0 B1 {comparator} B2 A2 B2 A2
        u64_equal // OP_EQUAL
        // A0 A1 B0 B1 {comparator} B2 A2 OP_EQUAL
        9 OP_ROLL // 3 OP_ROLL
        // A0 A1 B0 B1 B2 A2 OP_EQUAL {comparator}
        OP_BOOLAND
        // A0 A1 B0 B1 B2 A2 OP_BOOLAND
        {unroll(4, |_| script! {4 OP_ROLL})} // OP_SWAP
        // A0 A1 B0 B1 B2 OP_BOOLAND A2
        {unroll(4, |_| script! {8 OP_ROLL})} // OP_ROT
        // A0 A1 B0 B1 OP_BOOLAND A2 B2
        comparator
        // A0 A1 B0 B1 OP_BOOLAND {comparator}
        OP_BOOLOR
        // A0 A1 B0 B1 OP_BOOLOR
        {unroll(4, |_| script! {4 OP_ROLL})} // OP_SWAP
        // A0 A1 B0 OP_BOOLOR B1
        {unroll(4, |_| script! {12 OP_ROLL})} // 3 OP_ROLL
        // A0 B0 OP_BOOLOR B1 A1
        {unroll(8, |_| script! {7 OP_PICK})} // OP_2DUP
        // A0 B0 OP_BOOLOR B1 A1 B1 A1
        u64_equal
        // A0 B0 OP_BOOLOR B1 A1 OP_EQUAL
        9 OP_ROLL // 3 OP_ROLL
        // A0 B0 B1 A1 OP_EQUAL OP_BOOLOR
        OP_BOOLAND
        // A0 B0 B1 A1 OP_BOOLAND
        {unroll(4, |_| script! {4 OP_ROLL})} // OP_SWAP
        // A0 B0 B1 OP_BOOLAND A1
        {unroll(4, |_| script! {8 OP_ROLL})} // OP_ROT
        // A0 B0 OP_BOOLAND A1 B1
        comparator
        // A0 B0 OP_BOOLAND {comparator}
        OP_BOOLOR
        // A0 B0 OP_BOOLOR
        {unroll(4, |_| script! {4 OP_ROLL})} // OP_SWAP
        // A0 OP_BOOLOR B0
        {unroll(4, |_| script! {8 OP_ROLL})} // OP_ROT
        // OP_BOOLOR B0 A0
        {unroll(8, |_| script! {7 OP_PICK})} // OP_2DUP
        // OP_BOOLOR B0 A0 B0 A0
        u64_equal
        // OP_BOOLOR B0 A0 OP_EQUAL
        9 OP_ROLL // 3 OP_ROLL
        // B0 A0 OP_EQUAL OP_BOOLOR
        OP_BOOLAND
        // B0 A0 OP_BOOLAND
        {unroll(4, |_| script! {4 OP_ROLL})} // OP_SWAP
        // B0 OP_BOOLAND A0
        {unroll(4, |_| script! {8 OP_ROLL})} // OP_ROT
        // OP_BOOLAND A0 B0
        comparator
        // OP_BOOLAND {comparator}
        OP_BOOLOR
    }
}

/// Compares the top two stack items.
/// Returns 1 if the top item is less than the second-to-top item
/// Otherwise, returns 0
pub fn u256_lessthan() -> Script {
    // A_3 <> B_3 || (A_3 == B_3 && (A_2 <> B_2 || (A_2 == B_2 && (A_1 <> B_1 || (A_1 == B_1 && A_0 <> B_0)))))
    u256_cmp(u64_lessthan)
}

/// Compares the top two stack items.
/// Returns 1 if the top item is greater than the second-to-top item
/// Otherwise, returns 0
pub fn u256_greaterthan() -> Script {
    u256_cmp(u64_greaterthan)
}