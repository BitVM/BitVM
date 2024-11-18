use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::msm::hinted_msm_with_constant_bases_affine;
use crate::chunker::chunk_g1_points::g1_points;
use crate::chunker::chunk_msm::chunk_hinted_msm_with_constant_bases_affine;
use crate::chunker::chunk_non_fixed_point::chunk_q4;
use crate::chunker::elements::{ElementTrait, FrType, G2PointType};
use crate::chunker::{chunk_accumulator, chunk_hinted_accumulator};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use core::ops::Neg;

use super::assigner::BCAssigner;
use super::segment::Segment;

use test_proof::*;
mod test_proof {
    pub use anyhow::{anyhow, Error};
    pub use ark_bn254::Fr;
    pub use ark_bn254::{Bn254, G1Affine, G2Affine};
    pub use ark_groth16::VerifyingKey;
    pub use ark_serialize::CanonicalDeserialize;
    pub use risc0_zkvm::{
        sha::{Digest, Digestible},
        Groth16Receipt, Receipt, ReceiptClaim, VerifierContext,
    };
    use serde::Serialize;
    // Deserialize an element over the G1 group from bytes in big-endian format
    pub(crate) fn g1_from_bytes(elem: &[Vec<u8>]) -> Result<G1Affine, Error> {
        if elem.len() != 2 {
            return Err(anyhow!("Malformed G1 field element"));
        }
        let g1_affine: Vec<u8> = elem[0]
            .iter()
            .rev()
            .chain(elem[1].iter().rev())
            .cloned()
            .collect();

        G1Affine::deserialize_uncompressed(&*g1_affine).map_err(|err| anyhow!(err))
    }

    // Deserialize an element over the G2 group from bytes in big-endian format
    pub(crate) fn g2_from_bytes(elem: &[Vec<Vec<u8>>]) -> Result<G2Affine, Error> {
        if elem.len() != 2 || elem[0].len() != 2 || elem[1].len() != 2 {
            return Err(anyhow!("Malformed G2 field element"));
        }
        let g2_affine: Vec<u8> = elem[0][1]
            .iter()
            .rev()
            .chain(elem[0][0].iter().rev())
            .chain(elem[1][1].iter().rev())
            .chain(elem[1][0].iter().rev())
            .cloned()
            .collect();

        G2Affine::deserialize_uncompressed(&*g2_affine).map_err(|err| anyhow!(err))
    }

    pub struct FullProof {
        pub proof: ark_groth16::Proof<Bn254>,
        pub public_inputs: [Fr; 5],
        pub verifying_key: VerifyingKey<Bn254>,
    }

    pub fn get_params() -> Result<FullProof, Error> {
        use risc0_zkvm::{Receipt, VerifierContext};

        let receipt_json = r#"{"inner":{"Groth16":{"seal":[45,246,218,104,51,104,29,192,142,175,6,64,131,16,66,17,123,125,224,149,74,78,224,25,61,239,72,119,243,161,103,172,47,34,174,32,64,169,5,165,49,68,146,179,8,145,46,120,2,93,150,39,216,18,189,86,217,68,51,191,210,73,100,167,32,182,70,228,7,134,118,104,18,172,167,126,186,1,241,52,128,155,252,205,55,144,162,173,60,109,199,211,105,154,87,183,22,31,133,188,169,187,212,154,28,70,18,119,25,14,45,126,22,34,218,50,81,167,48,151,187,166,49,85,30,164,119,17,13,48,111,197,236,96,188,94,146,60,165,245,80,180,62,61,67,60,187,110,238,90,67,96,21,246,144,196,249,190,255,203,46,227,174,97,56,124,243,151,89,195,166,61,129,252,64,120,209,158,254,84,131,44,38,86,236,45,14,246,253,65,217,155,11,38,58,243,122,100,195,208,46,155,156,59,233,140,19,55,93,23,1,98,6,125,116,128,31,155,213,91,184,27,105,146,46,207,204,63,189,77,164,154,105,16,152,171,67,119,221,78,128,178,102,125,157,148,228,10,108,61,206,248,110,210,101,244],"claim":{"Value":{"pre":{"Value":{"pc":2450036,"merkle_root":[1643847833,2089362361,3872213287,1646020003,316582930,996658657,1869743789,3295678572]}},"post":{"Value":{"pc":0,"merkle_root":[0,0,0,0,0,0,0,0]}},"exit_code":{"Halted":0},"input":{"Pruned":[0,0,0,0,0,0,0,0]},"output":{"Value":{"journal":{"Value":[1,0,0,0]},"assumptions":{"Value":[]}}}}},"verifier_parameters":[1763163472,2876521993,3272685530,2018367509,394453731,2734973759,718893618,4111358395]}},"journal":{"bytes":[1,0,0,0]},"metadata":{"verifier_parameters":[1763163472,2876521993,3272685530,2018367509,394453731,2734973759,718893618,4111358395]}}"#;
        let receipt: Receipt = serde_json::from_str(&receipt_json).unwrap();
        let ctx = VerifierContext::default();
        let proof = receipt.inner.groth16().unwrap();

        let params = ctx
            .groth16_verifier_parameters
            .as_ref()
            .ok_or(anyhow!("VerificationError::VerifierParametersMissing"))?;

        let (a0, a1) = split_digest(params.control_root)
            .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?;
        let (c0, c1) = split_digest(proof.claim.digest())
            .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?;
        let mut id_bn554: Digest = params.bn254_control_id;
        id_bn554.as_mut_bytes().reverse();
        let id_bn254_fr = fr_from_hex_string(&hex::encode(id_bn554))
            .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?;

        let seal = risc0_groth16::Seal::from_vec(&proof.seal)
            .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?;
        let proof = ark_groth16::Proof::<Bn254> {
            a: g1_from_bytes(&seal.a)?,
            b: g2_from_bytes(&seal.b)?,
            c: g1_from_bytes(&seal.c)?,
        };

        // hack: params.verifying_key.0 is private --> just serialize + deserialize
        let serialized_verifying_key = serde_json::to_string(&params.verifying_key).unwrap();
        let deserialized_bytes: Vec<u8> = serde_json::from_str(&serialized_verifying_key).unwrap();
        let deserialized_verifying_key =
            VerifyingKey::<Bn254>::deserialize_uncompressed(deserialized_bytes.as_slice()).unwrap();

        Ok(FullProof {
            proof,
            public_inputs: [a0, a1, c0, c1, id_bn254_fr],
            verifying_key: deserialized_verifying_key,
        })
    }

    /// Splits the digest in half returning a scalar for each halve.
    pub fn split_digest(d: Digest) -> Result<(Fr, Fr), Error> {
        let big_endian: Vec<u8> = d.as_bytes().to_vec().iter().rev().cloned().collect();
        let middle = big_endian.len() / 2;
        let (b, a) = big_endian.split_at(middle);
        Ok((
            fr_from_bytes(&from_u256_hex(&hex::encode(a))?)?,
            fr_from_bytes(&from_u256_hex(&hex::encode(b))?)?,
        ))
    }

    /// Creates an [Fr] from a hex string
    pub fn fr_from_hex_string(val: &str) -> Result<Fr, Error> {
        fr_from_bytes(&from_u256_hex(val)?)
    }

    // Deserialize a scalar field from bytes in big-endian format
    pub(crate) fn fr_from_bytes(scalar: &[u8]) -> Result<Fr, Error> {
        let scalar: Vec<u8> = scalar.iter().rev().cloned().collect();
        ark_bn254::Fr::deserialize_uncompressed(&*scalar)
            // .map(Fr)
            .map_err(|err| anyhow!(err))
    }
    // Convert the U256 value to a byte array in big-endian format
    fn from_u256_hex(value: &str) -> Result<Vec<u8>, Error> {
        Ok(
            to_fixed_array(hex::decode(value).map_err(|_| anyhow!("conversion from u256 failed"))?)
                .to_vec(),
        )
    }

    fn to_fixed_array(input: Vec<u8>) -> [u8; 32] {
        let mut fixed_array = [0u8; 32];
        let start = core::cmp::max(32, input.len()) - core::cmp::min(32, input.len());
        fixed_array[start..].copy_from_slice(&input[input.len().saturating_sub(32)..]);
        fixed_array
    }
}

/// This function outputs a vector segment, which is equivalent to the plain groth16 verifier.
/// Each segment will generate script and witness for each branch of disprove transaction.
/// Bitcommitments are collected into assinger.
fn groth16_verify_to_segments<T: BCAssigner>(
    assigner: &mut T,
    public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> Vec<Segment> {
    let scalars = [
        vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
        public_inputs.clone(),
    ]
    .concat();
    let msm_g1 = G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

    let (exp, sign) = if LAMBDA.gt(&P_POW3) {
        (&*LAMBDA - &*P_POW3, true)
    } else {
        (&*P_POW3 - &*LAMBDA, false)
    };

    // G1/G2 points for pairings
    let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
    let (q1, q2, q3, q4) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
        proof.b,
    );

    // hint from arkworks
    let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
    let (c, wi) = compute_c_wi(f);
    let c_inv = c.inverse().unwrap();
    let hint = if sign {
        f * wi * (c_inv.pow((exp).to_u64_digits()))
    } else {
        f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
    };
    assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

    let q_prepared = vec![
        G2Prepared::from_affine(q1),
        G2Prepared::from_affine(q2),
        G2Prepared::from_affine(q3),
        G2Prepared::from_affine(q4),
    ];

    let p_lst = vec![p1, p2, p3, p4];

    let mut segments = vec![];

    let mut scalar_types = vec![];
    for (idx, scalar) in scalars.iter().enumerate() {
        let mut scalar_type = FrType::new(assigner, &format!("scalar_{}", idx));
        scalar_type.fill_with_data(crate::chunker::elements::DataType::FrData(scalar.clone()));
        scalar_types.push(scalar_type);
    }

    // calculate p1
    let (segment, p1_type) = chunk_hinted_msm_with_constant_bases_affine(
        assigner,
        &vk.gamma_abc_g1,
        &scalars,
        &scalar_types,
    );

    segments.extend(segment);

    let (segment, tp_lst) = g1_points(assigner, p1_type, p1, &proof, &vk);
    segments.extend(segment);

    let (segment, fs, f) = chunk_accumulator::chunk_accumulator(
        assigner,
        tp_lst,
        q_prepared.to_vec(),
        c,
        c_inv,
        wi,
        p_lst,
    );
    segments.extend(segment);

    let segment = chunk_hinted_accumulator::verify_accumulator(fs, hint);
    segments.extend(segment);

    let mut q4_input = G2PointType::new(assigner, "q4");
    q4_input.fill_with_data(crate::chunker::elements::DataType::G2PointData(q4));
    let segment = chunk_q4(q_prepared.to_vec(), q4, q4_input, assigner);

    segments.extend(segment);

    segments
}

#[cfg(test)]
mod tests {
    use crate::chunker::assigner::*;
    use crate::chunker::chunk_groth16_verifier::{get_params, groth16_verify_to_segments};
    use crate::chunker::{common::*, elements::ElementTrait};
    use crate::execute_script_with_inputs;
    use crate::treepp::*;

    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::PrimeField;
    use ark_groth16::Groth16;
    use ark_groth16::{ProvingKey, VerifyingKey};
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{test_rng, UniformRand};
    use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
    use rand::{RngCore, SeedableRng};
    use std::collections::HashMap;

    struct StatisticAssinger {
        commitments: HashMap<String, u32>,
    }
    impl StatisticAssinger {
        fn new() -> StatisticAssinger {
            StatisticAssinger {
                commitments: HashMap::new(),
            }
        }
        fn commitment_count(&self) -> usize {
            let count = self.commitments.len();
            count
        }
    }

    impl BCAssigner for StatisticAssinger {
        fn create_hash(&mut self, id: &str) {
            self.commitments.insert(id.to_owned(), 1);
        }

        fn locking_script<T: ElementTrait + ?Sized>(&self, _: &Box<T>) -> Script {
            script! {}
        }

        fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
            element.to_hash_witness().unwrap()
        }
    }

    #[derive(Copy)]
    struct DummyCircuit<F: PrimeField> {
        pub a: Option<F>,
        pub b: Option<F>,
        pub num_variables: usize,
        pub num_constraints: usize,
    }

    impl<F: PrimeField> Clone for DummyCircuit<F> {
        fn clone(&self) -> Self {
            DummyCircuit {
                a: self.a,
                b: self.b,
                num_variables: self.num_variables,
                num_constraints: self.num_constraints,
            }
        }
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                Ok(a * b)
            })?;

            for _ in 0..(self.num_variables - 3) {
                let _ =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints - 1 {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }

            cs.enforce_constraint(lc!(), lc!(), lc!())?;

            Ok(())
        }
    }

    #[test]
    fn test_hinted_groth16_verifier() {
        type E = Bn254;

        let mut assigner = StatisticAssinger::new();

        let full_proof = get_params().unwrap();

        let segments = groth16_verify_to_segments(
            &mut assigner,
            &full_proof.public_inputs.to_vec(),
            &full_proof.proof,
            &full_proof.verifying_key,
        );

        let mut small_segment_size = 0;

        for (_, segment) in tqdm::tqdm(segments.iter().enumerate()) {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            if script.len() < 1600 * 1000 {
                small_segment_size += 1;
            }

            let mut lenw = 0;
            for w in witness.iter() {
                lenw += w.len();
            }
            assert!(
                script.len() + lenw < 4000000,
                "script and witness len is over 4M {}",
                segment.name
            );

            let res = execute_script_with_inputs(script, witness);
            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{} in {}",
                res.stats.max_nb_stack_items,
                segment.name
            );
        }

        println!("segments number: {}", segments.len());
        println!("small_segment_size: {}", small_segment_size);
        println!("assign commitment size {}", assigner.commitment_count());
    }

    #[test]
    fn test_hinted_groth16_verifier_stable() {
        type E = Bn254;
        let k = 6;
        let mut rng: rand::prelude::StdRng =
            ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit: DummyCircuit<<ark_ec::bn::Bn<ark_bn254::Config> as Pairing>::ScalarField> =
            DummyCircuit::<<E as Pairing>::ScalarField> {
                a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
                b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
                num_variables: 10,
                num_constraints: 1 << k,
            };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        // let mut segmentes = vec![];
        let mut hashes = vec![];
        let count = 2;
        for i in 0..count {
            println!("generate hash {}", i);
            // let (hash, segment) = test_hinted_groth16_verifier_stable_tool();
            let hash = test_hinted_groth16_verifier_stable_tool(&mut rng, &pk, &vk);

            hashes.push(hash);
            // segmentes.push(segment)
        }
        for i in 1..count {
            assert_eq!(
                hashes[i].len(),
                hashes[i - 1].len(),
                "test{} len {}",
                i,
                hashes[i].len()
            );

            for j in 0..hashes[i].len() {
                // assert_eq!(hashes[i][j] , hashes[i-1][j], "segment  {} {} name {}", i, j, segmentes[i][j].name);
                assert_eq!(hashes[i][j], hashes[i - 1][j], "segment  {} {} ", i, j);
            }
        }
    }

    // fn test_hinted_groth16_verifier_stable_tool() -> (Vec<Sha256>, Vec<Segment>) {
    fn test_hinted_groth16_verifier_stable_tool(
        rng: &mut rand::prelude::StdRng,
        pk: &ProvingKey<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> Vec<Sha256> {
        type E = Bn254;
        let k = 6;
        // let mut rng: rand::prelude::StdRng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(<E as Pairing>::ScalarField::rand(rng)),
            b: Some(<E as Pairing>::ScalarField::rand(rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<E>::prove(&pk, circuit, rng).unwrap();

        let mut assigner = DummyAssinger {};
        let segments = groth16_verify_to_segments(&mut assigner, &vec![c], &proof, &vk);

        println!("segments number: {}", segments.len());

        let mut hashes = vec![];
        for (i, segment) in tqdm::tqdm(segments.iter().enumerate()) {
            let script = segment.script(&assigner);
            let hash = Sha256::hash(script.compile().as_bytes());
            println!("segment {} {} hash {}", i, segment.name, hash.clone());

            hashes.push(hash);
        }

        // (hashes, segments)
        hashes
    }
}
