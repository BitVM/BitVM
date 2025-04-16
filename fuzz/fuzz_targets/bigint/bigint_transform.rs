#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use bitcoin::ScriptBuf;
use bitcoin_script_stack::optimizer::optimize;
use libfuzzer_sys::fuzz_target;

use bitvm::execute_script_buf;
use bitvm::bigint::{std::bigint_verify_output_script, BigIntImpl, U254, U256, U64};
use bitvm_fuzz::match_bigint_type;

pub type U384 = BigIntImpl<384, 29>;

pub const BIGINT_TYPE_LAST_INDEX: u32 = 3;

#[derive(Debug)]
pub enum BigIntType {
    U64(U64),
    U254(U254),
    U256(U256),
    U384(U384), // We use 256bit (BN254), but test for others (e.g. BLS12-381)
}

// We are 99.999% confident with 500 limb transformations that all 31 values are covered, assuming random distribution (see inclusion-exclusion principle)
// Note: This doesn't consider every limb permutation
#[derive(Debug)]
pub struct BigIntConfig<const TRANSFORM_LIST_SIZE: usize = 500> {
    pub value: Vec<u32>,
    pub bigint_type: BigIntType,
    pub transform_list: [u32; TRANSFORM_LIST_SIZE],
}

impl BigIntType {
    pub fn from_index(idx: u32) -> Self {
        match idx {
            0 => Self::U64(U64 {}),
            1 => Self::U254(U254 {}),
            2 => Self::U256(U256 {}),
            3 => Self::U384(U384 {}),
            _ => panic!("Invalid BigIntType index"),
        }
    }

    pub fn n_bits(&self) -> u32 {
        match self {
            BigIntType::U64(_) => U64::N_BITS,
            BigIntType::U254(_) => U254::N_BITS,
            BigIntType::U256(_) => U256::N_BITS,
            BigIntType::U384(_) => U384::N_BITS,
        }
    }

    pub fn limb_size(&self) -> u32 {
        match self {
            BigIntType::U64(_) => U64::LIMB_SIZE,
            BigIntType::U254(_) => U254::LIMB_SIZE,
            BigIntType::U256(_) => U256::LIMB_SIZE,
            BigIntType::U384(_) => U384::LIMB_SIZE,
        }
    }
}

impl BigIntConfig {
    pub fn create_transform_script(&self) -> Vec<u8> {
        let mut bytes = match_bigint_type!(self.bigint_type, push_u32_le, self.value.as_ref()).compile().to_bytes();

        let first_transform = match_bigint_type!(self.bigint_type, transform_limbsize, self.bigint_type.limb_size(), self.transform_list[0]);
        bytes.extend_from_slice(first_transform.compile().as_bytes());

        // Intermediate transforms
        for window in self.transform_list.windows(2) {
            let transform = match_bigint_type!(self.bigint_type, transform_limbsize, window[0], window[1]);
            bytes.extend_from_slice(transform.compile().as_bytes());
        }

        let final_transform = match_bigint_type!(self.bigint_type, transform_limbsize, *self.transform_list.last().unwrap(), self.bigint_type.limb_size());
        bytes.extend_from_slice(final_transform.compile().as_bytes());

        let push_original = match_bigint_type!(self.bigint_type, push_u32_le, self.value.as_ref());
        bytes.extend_from_slice(push_original.compile().as_bytes());

        bytes
    }
}

impl<'a, const TRANSFORM_LIST_SIZE: usize> Arbitrary<'a> for BigIntConfig<TRANSFORM_LIST_SIZE> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let bigint_type = BigIntType::from_index(u.int_in_range(0..=BIGINT_TYPE_LAST_INDEX)?);
        let n_bits = bigint_type.n_bits();
        let transform_list = std::array::from_fn(|_| u.int_in_range(1..=31).unwrap());
        let value = (0..(n_bits.div_ceil(bigint_type.limb_size())))
            .map(|_| u.arbitrary())
            .collect::<Result<Vec<u32>>>()?;

        Ok(BigIntConfig {
            value,
            bigint_type,
            transform_list,
        })
    }
}

fuzz_target!(|message: BigIntConfig| {
    let mut bytes = message.create_transform_script();
    bytes.extend_from_slice(
        bigint_verify_output_script(message.value.len() as u32)
            .compile()
            .as_bytes(),
    );

    let script = optimize(ScriptBuf::from_bytes(bytes));
    assert!(execute_script_buf(script).success);
});
