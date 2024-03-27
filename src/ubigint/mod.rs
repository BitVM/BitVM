mod add;
mod bits;
mod cmp;
mod std;
mod sub;
mod mul;

pub struct UBigIntImpl<const N_BITS: u32>{}

impl <const N_BITS: u32>UBigIntImpl<N_BITS>{
    pub const N_LIMBS : u32 = (N_BITS + 30 - 1) / 30;
    pub const N_BITS: u32 = N_BITS;
}

pub type U254 = UBigIntImpl::<254>;