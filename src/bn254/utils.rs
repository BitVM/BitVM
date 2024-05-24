use ark_ff::Field;
use num_bigint::BigUint;

use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};

pub fn fq2_push(element: ark_bn254::Fq2) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
    }
}

pub fn fq6_push(element: ark_bn254::Fq6) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

pub fn fq12_push(element: ark_bn254::Fq12) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}
