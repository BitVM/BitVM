use ark_ff::{Field, UniformRand};
use num_bigint::BigUint;
use num_traits::Num;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::str::FromStr;
use std::sync::LazyLock;

use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    log_assert_eq, log_assert_ne,
};

pub static LAMBDA: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::from_str(
        "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
    ).unwrap()
});

pub static P: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_str_radix(Fq::MODULUS, 16).unwrap());
pub static R: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap()
});
pub const S: u32 = 3;
pub static EXP: LazyLock<BigUint> = LazyLock::new(|| P.pow(12_u32) - 1_u32);
pub static H: LazyLock<BigUint> = LazyLock::new(|| &*EXP / &*R);
pub static T: LazyLock<BigUint> = LazyLock::new(|| &*EXP / 3_u32.pow(S));
pub static K: LazyLock<BigUint> = LazyLock::new(|| (&*T + 1_u32) / 3_u32);
pub static M: LazyLock<BigUint> = LazyLock::new(|| &*LAMBDA / &*R);
pub const D: u32 = 3;
pub static MM: LazyLock<BigUint> = LazyLock::new(|| &*M / D);
pub static MM_INV: LazyLock<BigUint> = LazyLock::new(|| MM.modinv(&(&*R * &*H)).unwrap());
pub static COFACTOR_CUBIC: LazyLock<BigUint> = LazyLock::new(|| 3_u32.pow(S - 1) * &*T);

pub static W: LazyLock<ark_bn254::Fq12> = LazyLock::new(|| {
    let mut prng = ChaCha20Rng::seed_from_u64(0);
    // sample a proper scalar w which is cubic non-residue
    let w = {
        let (mut w, mut z) = (ark_bn254::Fq12::ONE, ark_bn254::Fq12::ONE);
        while w == ark_bn254::Fq12::ONE {
            // choose z which is 3-th non-residue
            let mut legendre = ark_bn254::Fq12::ONE;
            while legendre == ark_bn254::Fq12::ONE {
                z = ark_bn254::Fq12::rand(&mut prng);
                legendre = z.pow(&*COFACTOR_CUBIC.to_u64_digits());
            }
            // obtain w which is t-th power of z
            w = z.pow(&*T.to_u64_digits());
        }
        w
    };
    // make sure 27-th root w, is 3-th non-residue and r-th residue
    log_assert_ne!(
        w.pow(&*COFACTOR_CUBIC.to_u64_digits()),
        ark_bn254::Fq12::ONE
    );
    log_assert_eq!(w.pow(&*H.to_u64_digits()), ark_bn254::Fq12::ONE);
    w
});
