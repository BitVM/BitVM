use std::str::FromStr;

use crate::{
    bn254::utils::Hint,
    chunk::{
        helpers::{extern_bigint_to_nibbles, extern_hash_nibbles, extern_nibbles_to_bigint},
        wrap_hasher::BLAKE3_HASH_LENGTH,
    },
};
use ark_ff::{AdditiveGroup, Field, UniformRand};
use num_bigint::{BigInt, BigUint};
use rand::Rng;
use std::fmt::Debug;

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
/// Use `lift` to convert to evaluation form lazily.
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

    pub fn lift(&self) -> Self {
        let p: ark_bn254::G1Affine = (*self).into();
        Self::new(p.x, p.y)
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

impl From<FqPair> for ark_bn254::G1Affine {
    fn from(pi: FqPair) -> Self {
        use ark_ec::AffineRepr;
        if pi.zero {
            if pi.x == ark_bn254::Fq::ZERO {
                return ark_bn254::G1Affine::zero();
            }
            return ark_bn254::G1Affine::new_unchecked(pi.x, pi.y);
        }

        let (nx, ny) = (pi.x, pi.y);
        let y = ny
            .inverse()
            .expect("ny must be nonzero for evaluation form");
        let x = -nx * y; // equivalent to -nx / ny⁻¹

        ark_bn254::G1Affine::new_unchecked(x, y)
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
                let r = r.lift();
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
    let r = r.lift();
    let hints = vec![Hint::Fq(r.x()), Hint::Fq(r.y())];
    hints
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ElemG2Eval {
    /// G2 point accumulator of Miller's Algorithm
    pub(crate) t: ark_bn254::G2Affine,

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
        let t = ark_bn254::G2Affine::new(tx, ty);
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
    use crate::{
        bn254::{fp254impl::Fp254Impl, fq::Fq},
        chunk::{
            elements::{ElementType, FqPair},
            wrap_hasher::hash_messages,
        },
        execute_script,
    };
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
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
        let zero = ark_bn254::G1Affine::zero();
        assert_eq!(
            zero,
            <FqPair as Into<ark_bn254::G1Affine>>::into(FqPair::from(zero))
        );

        let mut rng = thread_rng();
        (0..100).into_iter().for_each(|_| {
            let random = ark_bn254::G1Affine::rand(&mut rng);
            assert_eq!(
                random,
                <FqPair as Into<ark_bn254::G1Affine>>::into(FqPair::from(random))
            );
        });
    }
}
