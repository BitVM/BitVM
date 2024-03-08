use bitcoin_script::define_pushable;

pub mod pseudo;
pub mod u32_zip;
pub mod u32_xor;
pub mod u32_sub;
pub mod u32_std;
pub mod u32_state;
pub mod u32_rrot;
pub mod u32_or;
pub mod u32_and;
pub mod u32_cmp;
pub mod u32_add;
pub mod u256_std;
pub mod blake3;

define_pushable!();

pub fn unroll<F, T>(count: u32, closure: F) -> Vec<T>
where
    F: Fn(u32) -> T,
    T: pushable::Pushable,
{
    let mut result = vec![];

    for i in 0..count {
        result.push(closure(i))
    }
    result
}
