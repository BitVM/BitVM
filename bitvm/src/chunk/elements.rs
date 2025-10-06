use crate::{
    bn254::utils::Hint,
    chunk::{
        helpers::{extern_bigint_to_nibbles, extern_hash_nibbles, extern_nibbles_to_bigint},
        wrap_hasher::BLAKE3_HASH_LENGTH,
    },
};
use ark_bn254::g2::Config as G2Config;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use rand::Rng;
use std::fmt::Debug;
use std::str::FromStr;

use super::helpers::{extern_hash_fps, extern_nibbles_to_limbs};

/// Data Structure to hold values passed around in pairing check
#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
#[allow(clippy::large_enum_variant)]
pub enum DataType {
    /// Fp6 elements
    Fp6Data(ark_bn254::Fq6),

    /// point accumulator and partial products (Refer: ElementType)
    G2EvalData(ElemG2Eval),

    /// G1Affine points
    G1Data(FqPair),

    /// BigIntegers - Field & Scalar elements
    U256Data(ark_ff::BigInt<4>),
}

/// Represent coordinates by evaluation form (-x/y, 1/y), see more: https://github.com/BitVM/BitVM/issues/213
#[derive(Debug, Clone, Copy)]
pub struct FqPair {
    x: ark_bn254::Fq, // -x/y
    y: ark_bn254::Fq, // 1/y
    pub zero: bool,   // true if y is zero
}

impl FqPair {
    pub fn new(x: ark_bn254::Fq, y: ark_bn254::Fq) -> Self {
        Self {
            x,
            y,
            zero: y == ark_bn254::Fq::ZERO,
        }
    }

    pub fn x(&self) -> ark_bn254::Fq {
        self.x
    }

    pub fn y(&self) -> ark_bn254::Fq {
        self.y
    }

    /// Recover the evaluation form to original form.
    pub fn recover(&self) -> Self {
        if self.zero {
            if self.x == ark_bn254::Fq::ZERO {
                return Self::new(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO);
            }
            return Self::new(self.x, self.y);
        }

        let (nx, ny) = (self.x, self.y);
        let y = ny.inverse().expect("ny should be non-zero to recover");
        let x = -nx * y; // equivalent to -nx / ny⁻¹

        Self::new(x, y)
    }

    pub fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let p = ark_bn254::G1Affine::rand(rng);
        Self::new(p.x, p.y)
    }
}

impl From<ark_bn254::G1Affine> for FqPair {
    fn from(p: ark_bn254::G1Affine) -> Self {
        if p.y == ark_bn254::Fq::ZERO {
            return Self {
                x: p.x,
                y: p.y,
                zero: true,
            };
        }
        let (x, y) = (p.x, p.y);
        let ny = y.inverse().expect("y must be nonzero for evaluation form");
        let nx = -(x * ny);
        Self {
            x: nx,
            y: ny,
            zero: false,
        }
    }
}

//impl From<FqPair> for ark_bn254::G1Affine {
//    fn from(pi: FqPair) -> Self {
//        if pi.zero {
//            if pi.x == ark_bn254::Fq::ZERO {
//                return ark_bn254::G1Affine::zero();
//            }
//            return ark_bn254::G1Affine::new_unchecked(pi.x, pi.y);
//        }
//
//        let (nx, ny) = (pi.x, pi.y);
//        let y = ny
//            .inverse()
//            .expect("ny must be nonzero for evaluation form");
//        let x = -nx * y; // equivalent to -nx / ny⁻¹
//
//        ark_bn254::G1Affine::new_unchecked(x, y)
//    }
//}

/// Non-G2 Group on E'
#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub struct TwistPoint {
    x: ark_bn254::Fq2,
    y: ark_bn254::Fq2,
    pub zero: bool,
}

impl TwistPoint {
    pub fn new(x: ark_bn254::Fq2, y: ark_bn254::Fq2) -> Self {
        Self {
            x,
            y,
            zero: x == ark_bn254::Fq2::ZERO && y == ark_bn254::Fq2::ZERO,
        }
    }

    pub fn x(&self) -> ark_bn254::Fq2 {
        self.x
    }

    pub fn y(&self) -> ark_bn254::Fq2 {
        self.y
    }

    pub fn is_zero(&self) -> bool {
        self.zero
    }

    pub fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let p = ark_bn254::G2Affine::rand(rng);
        Self::new(p.x, p.y)
    }

    /// y^2 = x^3 + b'  (b' from E')
    pub fn is_on_curve(&self) -> bool {
        let y2 = self.y.square();
        let x3b = self.x.square() * self.x + <G2Config as SWCurveConfig>::COEFF_B;
        y2 == x3b
    }

    /// Negation
    pub fn neg(&self) -> Self {
        if self.zero {
            *self
        } else {
            Self::new(self.x, -self.y)
        }
    }

    /// Point doubling: (x3, y3) = 2 * (x1, y1)
    pub fn double(&self) -> Self {
        if self.zero {
            return *self;
        }

        let two = ark_bn254::Fq2::from(2u64);
        let three = ark_bn254::Fq2::from(3u64);

        let x1 = self.x;
        let y1 = self.y;

        if y1.is_zero() {
            return Self {
                x: ark_bn254::Fq2::zero(),
                y: ark_bn254::Fq2::zero(),
                zero: true,
            };
        }

        let slope = (three * x1.square()) / (two * y1);
        let x3 = slope.square() - (two * x1);
        let y3 = slope * (x1 - x3) - y1;

        Self::new(x3, y3)
    }

    /// Point addition on E': P3 = P1 + P2
    pub fn add(&self, other: &Self) -> Self {
        if self.zero {
            return *other;
        }
        if other.zero {
            return *self;
        }

        let x1 = self.x;
        let y1 = self.y;
        let x2 = other.x;
        let y2 = other.y;

        if x1 == x2 {
            if y1 + y2 == ark_bn254::Fq2::zero() {
                return Self {
                    x: ark_bn254::Fq2::zero(),
                    y: ark_bn254::Fq2::zero(),
                    zero: true,
                };
            } else {
                return self.double();
            }
        }

        let slope = (y2 - y1) / (x2 - x1);
        let x3 = slope.square() - x1 - x2;
        let y3 = slope * (x1 - x3) - y1;

        Self::new(x3, y3)
    }
}

impl From<ark_bn254::G2Affine> for TwistPoint {
    fn from(p: ark_bn254::G2Affine) -> Self {
        Self {
            x: p.x,
            y: p.y,
            zero: p.is_zero(),
        }
    }
}

/// Helper macro to reduce repetitive code for `TryFrom<Element>`.
macro_rules! impl_try_from_element {
    ($t:ty, { $($variant:ident),+ }) => {
        impl TryFrom<DataType> for $t {
            type Error = String;

            fn try_from(value: DataType) -> Result<Self, Self::Error> {
                match value {
                    $(
                        DataType::$variant(v) => Ok(v),
                    )+
                    other => {
                        Err(format!("attempted: {:?} found: {:?}",
                        stringify!($t),
                        other,
                    ))},
                }
            }
        }
    };
}

impl_try_from_element!(ark_bn254::Fq6, { Fp6Data });
impl_try_from_element!(ark_ff::BigInt<4>, { U256Data });
impl_try_from_element!(FqPair, { G1Data });
impl_try_from_element!(ElemG2Eval, { G2EvalData });

/// Abstraction over DataType that specifies how the
/// data moved around Pairing Check will be interpreted
/// Example: Uint256 is DataType,
/// FieldElement (ark_bn254::Fq) or ScalarElement (ark_bn254::Fr) are ElementTypes
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ElementType {
    /// type to represent second coefficient of normalized Fp12
    Fp6,

    /// type to represent field elements
    FieldElem,

    /// type to represent scalar elements, which are public inputs of groth16 verifier
    ScalarElem,

    /// type to represent G1Affine points, which can be from groth16 proof or its intermediate computations
    G1,

    // The following ElementTypes are wrappers of ElemG2Eval [t(4), partial_product(14)]
    // We merkelize ElemG2Eval because all of its contents aren't used within a single tapscript
    // Therefore a tapscript can only include preimage of the values it needs (t or partial_product) for calculation,
    // and use sibling hash (Hash_partial_product or Hash_t respectively) to show that the preimage are part of the merkle tree
    /// type to represent point G2 accumulator with hash of partial product of line evaluation
    G2EvalPoint, // t, Hash_partial_product

    /// type to represent partial product of line evaluation with hash of G2 point accumulator
    G2EvalMul, // partial_product, Hash_t

    /// type to represent G2 point accumulator and partial product of line evaluation  
    G2Eval, // t, partial_product
}

impl ElementType {
    pub fn number_of_limbs_of_hashing_preimage(&self) -> usize {
        match self {
            ElementType::Fp6 => 6,             // six coefficients of field element
            ElementType::FieldElem => 0,       // field element is not hashed, directly bit-comitted
            ElementType::G1 => 2,              // x, y co-ordinates
            ElementType::ScalarElem => 0, // scalar element is not hashed, directly bit-comitted
            ElementType::G2EvalPoint => 4 + 1, // t, Hash_partial_product
            ElementType::G2EvalMul => 14 + 1, // partial_product, Hash_t
            ElementType::G2Eval => 14 + 4, // t, partial_product
        }
    }
}

pub(crate) type HashBytes = [u8; 64];

/// Data Type to represent an Assertion data (i.e output State of a tapscript).
/// For intermediate values, the type is always HashBytes.
/// For the input groth16 proof, the type is always BigInt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressedStateObject {
    Hash(HashBytes),
    U256(ark_ff::BigInt<4>),
}

impl CompressedStateObject {
    // helper function to represent State as hint
    // used in tests to check the validity of checksig_verify()
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn as_hint_type(self) -> Hint {
        match self {
            CompressedStateObject::Hash(h) => Hint::Hash(extern_nibbles_to_limbs(h)),
            CompressedStateObject::U256(f) => {
                let fuint: BigUint = f.into();
                let fint: BigInt = BigInt::from_biguint(num_bigint::Sign::Plus, fuint);
                Hint::U256(fint)
            }
        }
    }

    // Serialize StateObject to byte array so that it can be wots-signed
    pub(crate) fn serialize_to_byte_array(&self) -> Vec<u8> {
        fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
            let mut msg_bytes = Vec::with_capacity(digits.len() / 2);

            for nibble_pair in digits.chunks(2) {
                let byte = (nibble_pair[1] << 4) | (nibble_pair[0] & 0b00001111);
                msg_bytes.push(byte);
            }

            msg_bytes
        }
        match self {
            CompressedStateObject::Hash(h) => {
                let bal: [u8; 32] = nib_to_byte_array(h).try_into().unwrap();
                let bal: [u8; BLAKE3_HASH_LENGTH] =
                    bal[32 - BLAKE3_HASH_LENGTH..32].try_into().unwrap();
                bal.to_vec()
            }
            CompressedStateObject::U256(n) => {
                let n = extern_bigint_to_nibbles(*n);
                let bal: [u8; 32] = nib_to_byte_array(&n).try_into().unwrap();
                bal.to_vec()
            }
        }
    }

    // Deserialize wots-signed byte array to object
    pub(crate) fn deserialize_from_byte_array(byte_array: Vec<u8>) -> Self {
        assert!(byte_array.len() == BLAKE3_HASH_LENGTH || byte_array.len() == 32);
        fn byte_array_to_nib(bytes: &[u8]) -> Vec<u8> {
            let mut nibbles = Vec::with_capacity(bytes.len() * 2);
            for &b in bytes {
                let high = b >> 4;
                let low = b & 0x0F;
                nibbles.push(low);
                nibbles.push(high);
            }
            nibbles
        }
        if byte_array.len() == BLAKE3_HASH_LENGTH {
            let nib_arr = byte_array_to_nib(&byte_array);
            let nib_arr: [u8; BLAKE3_HASH_LENGTH * 2] = nib_arr.try_into().unwrap();
            let mut padded_nibs = [0u8; 64]; // initialize with zeros
            padded_nibs[64 - (BLAKE3_HASH_LENGTH * 2)..64]
                .copy_from_slice(&nib_arr[0..BLAKE3_HASH_LENGTH * 2]);
            CompressedStateObject::Hash(padded_nibs)
        } else {
            let nib_arr = byte_array_to_nib(&byte_array);
            let nib_arr: [u8; 64] = nib_arr.try_into().unwrap();
            let fint = extern_nibbles_to_bigint(nib_arr);
            CompressedStateObject::U256(fint)
        }
    }
}

impl DataType {
    // Blake3 Hash data types
    // For U256Data (which is a single BigInteger) we do not hash but return as is
    // BigInt are used to represent groth16 proof
    pub fn to_hash(self) -> CompressedStateObject {
        match self {
            DataType::G2EvalData(r) => {
                let hash_t = r.hash_t();
                let hash_le = r.hash_le();
                let hash = extern_hash_nibbles(vec![hash_t, hash_le]);
                CompressedStateObject::Hash(hash)
            }
            DataType::Fp6Data(r) => {
                let hash = extern_hash_fps(
                    r.to_base_prime_field_elements()
                        .collect::<Vec<ark_bn254::Fq>>(),
                );
                CompressedStateObject::Hash(hash)
            }
            DataType::U256Data(f) => CompressedStateObject::U256(f),
            DataType::G1Data(r) => {
                let r = r.recover();
                let hash = extern_hash_fps(vec![r.x(), r.y()]);
                CompressedStateObject::Hash(hash)
            }
        }
    }

    pub fn output_is_field_element(&self) -> bool {
        matches!(self, DataType::U256Data(_))
    }

    // hashing pre-image for the DataType
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_witness(&self, elem_type: ElementType) -> Vec<Hint> {
        match (elem_type, self) {
            (ElementType::G2EvalPoint, DataType::G2EvalData(g)) => {
                as_hints_g2evalpointtype_g2evaldata(*g)
            }
            (ElementType::G2EvalMul, DataType::G2EvalData(g)) => {
                as_hints_g2evalmultype_g2evaldata(*g)
            }
            (ElementType::Fp6, DataType::Fp6Data(r)) => as_hints_fq6type_fq6data(*r),
            (ElementType::G1, DataType::G1Data(r)) => as_hints_g1type_g1data(r),
            (ElementType::FieldElem, DataType::U256Data(r)) => as_hints_fieldelemtype_u256data(*r),
            (ElementType::ScalarElem, DataType::U256Data(r)) => {
                as_hints_scalarelemtype_u256data(*r)
            }
            _ => {
                println!("Unhandled ElementType {:?} ", elem_type);
                unreachable!();
            }
        }
    }
}

/// returns coefficients of Fp6 element
fn as_hints_fq6type_fq6data(elem: ark_bn254::Fq6) -> Vec<Hint> {
    let hints: Vec<Hint> = elem.to_base_prime_field_elements().map(Hint::Fq).collect();
    hints
}

/// returns g2 point accumulator (t) and hash of partial product (Hash_partial_product)
fn as_hints_g2evalpointtype_g2evaldata(g: ElemG2Eval) -> Vec<Hint> {
    let hints = vec![
        Hint::Fq(g.t.x.c0),
        Hint::Fq(g.t.x.c1),
        Hint::Fq(g.t.y.c0),
        Hint::Fq(g.t.y.c1),
        Hint::Hash(extern_nibbles_to_limbs(g.hash_le())),
    ];
    hints
}

/// returns partial_product and hash of g2 point accumulator (Hash_t)
fn as_hints_g2evalmultype_g2evaldata(g: ElemG2Eval) -> Vec<Hint> {
    let mut hints: Vec<Hint> = g
        .a_plus_b
        .iter()
        .flat_map(|pt| [pt.c0, pt.c1]) // each point gives two values
        .chain(g.one_plus_ab_j_sq.to_base_prime_field_elements())
        .chain(g.p2le.iter().flat_map(|pt| [pt.c0, pt.c1]))
        // .chain(g.res_hint.to_base_prime_field_elements())
        .map(Hint::Fq)
        .collect();
    hints.push(Hint::Hash(extern_nibbles_to_limbs(g.hash_t())));
    hints
}

fn as_hints_fieldelemtype_u256data(elem: ark_ff::BigInt<4>) -> Vec<Hint> {
    let v: BigUint = elem.into();
    let v = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, v);
    let hints = vec![Hint::U256(v)];
    hints
}

fn as_hints_scalarelemtype_u256data(elem: ark_ff::BigInt<4>) -> Vec<Hint> {
    let v: BigUint = elem.into();
    let v = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, v);
    let hints = vec![Hint::U256(v)];
    hints
}

fn as_hints_g1type_g1data(r: &FqPair) -> Vec<Hint> {
    let r = r.recover();
    let hints = vec![Hint::Fq(r.x()), Hint::Fq(r.y())];
    hints
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ElemG2Eval {
    /// G2 point accumulator of Miller's Algorithm
    pub(crate) t: TwistPoint,

    // We have,
    // A <- (1 + a), B <- (1 + b), C <- (1 + c), C = A x B
    // c = [(a+b)/(1 + ab w^2)]
    // c = [a_plus_b/ one_plus_ab_j_sq]
    // In our context,
    //  A <- evaluate_line_throught_t3_q3(at_p3),  B <- evaluate_line_throught_t4_q4(at_p4)
    // a_plus_b and one_plus_ab_j_sq are values corresponding to product of line evaluations
    // It's "partial" because we haven't computed the entire result i.e.
    // lev = evaluate_line_throught_t2_q2(at_p2) x evaluate_line_throught_t3_q3(at_p3) x evaluate_line_throught_t4_q4(at_p4)
    /// partial product term for a+b
    pub(crate) a_plus_b: [ark_bn254::Fq2; 2],

    /// partial product term for (1 + ab w^2)
    pub(crate) one_plus_ab_j_sq: ark_bn254::Fq6,

    /// partial product term for p2le = evaluate_line_throught_t2_q2(at_p2)
    pub(crate) p2le: [ark_bn254::Fq2; 2],
}

impl ElemG2Eval {
    pub(crate) fn hash_t(&self) -> HashBytes {
        extern_hash_fps(vec![self.t.x.c0, self.t.x.c1, self.t.y.c0, self.t.y.c1])
    }

    pub(crate) fn hash_le(&self) -> HashBytes {
        let mut le = vec![];
        le.extend_from_slice(&[
            self.a_plus_b[0].c0,
            self.a_plus_b[0].c1,
            self.a_plus_b[1].c0,
            self.a_plus_b[1].c1,
        ]);
        le.extend_from_slice(
            &self
                .one_plus_ab_j_sq
                .to_base_prime_field_elements()
                .collect::<Vec<ark_bn254::Fq>>(),
        );
        le.extend_from_slice(&[
            self.p2le[0].c0,
            self.p2le[0].c1,
            self.p2le[1].c0,
            self.p2le[1].c1,
        ]);
        extern_hash_fps(le)
    }

    pub(crate) fn mock() -> Self {
        let q4xc0: ark_bn254::Fq = ark_bn254::Fq::from(
            BigUint::from_str(
                "18327300221956260726652878806040774028373651771658608258634994907375058801387",
            )
            .unwrap(),
        );
        let q4xc1: ark_bn254::Fq = ark_bn254::Fq::from(
            BigUint::from_str(
                "2791853351403597124265928925229664715548948431563105825401192338793643440152",
            )
            .unwrap(),
        );
        let q4yc0: ark_bn254::Fq = ark_bn254::Fq::from(
            BigUint::from_str(
                "9203020065248672543175273161372438565462224153828027408202959864555260432617",
            )
            .unwrap(),
        );
        let q4yc1: ark_bn254::Fq = ark_bn254::Fq::from(
            BigUint::from_str(
                "21242559583226289516723159151189961292041850314492937202099045542257932723954",
            )
            .unwrap(),
        );
        let tx = ark_bn254::Fq2::new(q4xc0, q4xc1);
        let ty = ark_bn254::Fq2::new(q4yc0, q4yc1);
        let t = TwistPoint::new(tx, ty);
        ElemG2Eval {
            t,
            p2le: [ark_bn254::Fq2::ONE; 2],
            a_plus_b: [ark_bn254::Fq2::ONE; 2],
            one_plus_ab_j_sq: ark_bn254::Fq6::ONE,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bn254::{fp254impl::Fp254Impl, fq::Fq},
        chunk::{
            elements::{ElementType, FqPair, TwistPoint},
            wrap_hasher::hash_messages,
        },
        execute_script,
    };
    use ark_bn254::{g2::Config as G2Config, Fr};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::PrimeField;
    use bitcoin_script::script;
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_hash_witness() {
        let mut prng = ChaCha20Rng::seed_from_u64(117);
        let fld = ark_bn254::Fq6::rand(&mut prng);
        let elem = super::DataType::Fp6Data(fld);

        let check_output_bit = 1;
        let preim = elem.to_witness(ElementType::Fp6);
        let scr = script! {
            for p in preim {
                {p.push()}
            }
            {check_output_bit}
            {elem.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {hash_messages(vec![ElementType::Fp6])}
        };
        let res = execute_script(scr);
        assert!(!res.success && res.final_stack.len() == 1);
    }

    #[test]
    fn test_fq_pair() {
        let zero = ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO);
        let fp_zero = FqPair::from(zero);
        assert!(fp_zero.zero);
        assert_eq!(
            zero,
            ark_bn254::G1Affine::new_unchecked(fp_zero.x(), fp_zero.y())
        );

        let mut rng = thread_rng();
        (0..100).into_iter().for_each(|_| {
            let random = ark_bn254::G1Affine::rand(&mut rng);
            let fp_rand = FqPair::from(random);
            assert!(!fp_rand.zero);
            let lifted = fp_rand.recover();
            assert_eq!(random, ark_bn254::G1Affine::new(lifted.x(), lifted.y()));
        });
    }

    #[test]
    fn test_on_curve_and_addition() {
        let mut rng = thread_rng();
        let p1 = TwistPoint::rand(&mut rng);
        let p2 = TwistPoint::rand(&mut rng);

        assert!(p1.is_on_curve(), "p1 should be on E'");
        assert!(p2.is_on_curve(), "p2 should be on E'");

        // Add and double
        let sum = p1.add(&p2);
        assert!(sum.is_on_curve(), "p1 + p2 should still be on E'");

        let dbl = p1.double();
        assert!(dbl.is_on_curve(), "2*p1 should be on E'");
    }

    #[test]
    fn test_additive_identities() {
        let mut rng = thread_rng();
        let p = TwistPoint::rand(&mut rng);

        let zero = TwistPoint::from(ark_bn254::G2Affine::zero());

        // P + 0 = P
        let s1 = p.add(&zero);
        assert_eq!(s1.x, p.x);
        assert_eq!(s1.y, p.y);

        // 0 + P = P
        let s2 = zero.add(&p);
        assert_eq!(s2.x, p.x);
        assert_eq!(s2.y, p.y);

        // P + (-P) = 0
        let neg = p.neg();
        let s3 = p.add(&neg);
        assert!(s3.zero, "P + (-P) should be zero point");
    }

    #[test]
    fn test_double_equals_add_self() {
        let mut rng = thread_rng();
        let p = TwistPoint::rand(&mut rng);

        let dbl1 = p.double();
        let dbl2 = p.add(&p);

        assert_eq!(dbl1.x, dbl2.x);
        assert_eq!(dbl1.y, dbl2.y);
    }

    fn is_in_g2_subgroup(p: &ark_bn254::G2Projective) -> bool {
        // Check if the point is in the correct G2 subgroup:
        // h * P == O
        let r = <Fr as PrimeField>::MODULUS;
        (p.mul_bigint(r)).is_zero()
    }

    fn random_point_on_twist_not_in_g2() -> TwistPoint {
        let mut rng = thread_rng();
        loop {
            let x = ark_bn254::Fq2::rand(&mut rng);
            let rhs = x * x * x + G2Config::COEFF_B;
            if let Some(y) = rhs.sqrt() {
                // This (x, y) satisfies the twist curve equation but is *not* subgroup-checked.
                let p = ark_bn254::G2Affine::new_unchecked(x, y);
                assert!(p.is_on_curve(), "curve equation must hold");
                assert!(
                    !p.is_in_correct_subgroup_assuming_on_curve(),
                    "point should not be in G2 subgroup"
                );
                return TwistPoint::new(x, y);
            }
        }
    }

    #[test]
    fn test_point_not_on_g2_but_on_twist() {
        // Get a valid but non-G₂ point
        let non_g2 = random_point_on_twist_not_in_g2();

        // Check it's on the twist equation
        let x = non_g2.x();
        let y = non_g2.y();
        assert_eq!(
            y.square(),
            x * x * x + G2Config::COEFF_B,
            "must be on twist"
        );

        // Try converting to a projective point (optional)
        let p = ark_bn254::G2Affine::new_unchecked(x, y);
        assert!(p.is_on_curve(), "curve equation must hold");

        // Check it’s not in G2 subgroup
        let non_g2_proj = p.into_group();
        assert!(
            !is_in_g2_subgroup(&non_g2_proj),
            "point should not be in G2 subgroup"
        );
        println!("Non-G2 point on E': {:?}", non_g2_proj);

        // Basic curve operations sanity checks
        let neg = -non_g2_proj;

        // Check some properties
        assert_ne!(
            non_g2_proj,
            ark_bn254::G2Projective::zero(),
            "point not zero"
        );
        assert_eq!(
            non_g2_proj + neg,
            ark_bn254::G2Projective::zero(),
            "P + (-P) must be identity"
        );

        // Check that group law preserves twist equation
        let doubled = non_g2_proj.double();
        let added = non_g2_proj + doubled;
        let added_affine = added.into_affine();
        let x2 = added_affine.x;
        let y2 = added_affine.y;
        let lhs2 = y2.square();
        let rhs2 = x2 * x2.square() + G2Config::COEFF_B;
        assert_eq!(lhs2, rhs2, "sum must stay on twist curve");
    }
}
