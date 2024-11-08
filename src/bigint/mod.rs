pub mod add;
pub mod bits;
pub mod cmp;
pub mod inv;
pub mod mul;
pub mod std;
pub mod sub;
pub mod u29x9;
pub mod u32x8;

pub struct BigIntImpl<const N_BITS: u32, const LIMB_SIZE: u32> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub const N_BITS: u32 = N_BITS;
    pub const N_LIMBS: u32 = (N_BITS + LIMB_SIZE - 1) / LIMB_SIZE;
    pub const HEAD: u32 = N_BITS - (Self::N_LIMBS - 1) * LIMB_SIZE;
    pub const HEAD_OFFSET: u32 = 1u32 << Self::HEAD;
}

pub type U254 = BigIntImpl<254, 29>;
pub type U64 = BigIntImpl<64, 16>;
