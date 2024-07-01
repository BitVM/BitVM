use ark_bn254::{Fr, G1Affine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlonkProof {
    pub a: G1Affine,
    pub b: G1Affine,
    pub c: G1Affine,
    pub z: G1Affine,
    pub t1: G1Affine,
    pub t2: G1Affine,
    pub t3: G1Affine,
    pub eval_a: Fr,
    pub eval_b: Fr,
    pub eval_c: Fr,
    pub eval_s1: Fr,
    pub eval_s2: Fr,
    pub eval_zw: Fr,
    pub eval_r: Fr,
    pub pi: Fr,
    pub wxi: G1Affine,
    pub wxiw: G1Affine,
}

pub struct StringifiedPlonkProof {
    pub a: [String; 2],
    pub b: [String; 2],
    pub c: [String; 2],
    pub z: [String; 2],
    pub t1: [String; 2],
    pub t2: [String; 2],
    pub t3: [String; 2],
    pub eval_a: String,
    pub eval_b: String,
    pub eval_c: String,
    pub eval_s1: String,
    pub eval_s2: String,
    pub eval_zw: String,
    pub eval_r: String,
    pub pi: String,
    pub wxi: [String; 2],
    pub wxiw: [String; 2],
}
