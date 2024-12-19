use std::str::FromStr;

use crate::bn254::{fp254impl::Fp254Impl, fq::Fq};
use num_bigint::BigUint;
use num_traits::Num;
use once_cell::sync::Lazy;

pub static P_POW3: Lazy<BigUint> =
    Lazy::new(|| BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32));

pub static LAMBDA: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_str(
        "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
    ).unwrap()
});
