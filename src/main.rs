mod opcodes;
mod actor;
mod model;
use bitcoin_script::bitcoin_script as script;
use opcodes::pseudo::OP_4PICK;
use opcodes::pushable;

use crate::opcodes::{
    blake3::blake3, pseudo::{op_2k_mul, OP_4ROLL}, u32_xor::{u32_drop_xor_table, u32_push_xor_table, u32_xor}, unroll
};


fn main() {
    //let y = 13;
    //let my_script = script! {
    //    {(|x: i32| -> i32 {x + y} )(7)} OP_4ROLL
    //};
    //println!("{:?}", my_script);
    //
    //let my_script = script!{
    //    {unroll(18, |i| script!{ OP_4ROLL {i} {y}})}
    //};
    //println!("{:?}", my_script);

    //let my_script = script!{
    //    {op_2k_mul(8)}
    //    OP_4PICK
    //};
    //println!("{:?}", my_script);

    //let my_script = script!{
    //    u32_push_xor_table
    //    {u32_xor(1, 0, 1234)}
    //    u32_drop_xor_table
    //};

    let my_script = script! {
        {String::from("HALLOTHISISVERYLONGANDVERYMUCHINTHEELIMITIASJDAKJSDAKJSHDHALLOTHISISVERYLONGANDVERYMUCHINTHEELIMITIASJDAKJSDAKJSHDHALLOTHISISVERYLONGANDVERYMUCHINTHEELIMITIASJDAKJSDAKJSHDHALLOTHISISVERYLONGANDVERYMUCHINTHEELIMITIASJDAKJSDAKJSHD").into_bytes()}
    };

    let my_script = script! {
        blake3
    };
    println!("{:?}", my_script.to_asm_string())
}
