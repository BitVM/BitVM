use crate::chunk::api_runtime_utils::{execute_script_from_signature, get_assertion_from_segments, get_assertions_from_signature, get_segments_from_assertion, get_segments_from_groth16_proof};
use crate::chunk::api_compiletime_utils::{ append_bitcom_locking_script_to_partial_scripts, generate_partial_script, partial_scripts_from_segments, Vkey, NUM_PUBS};
use crate::groth16::g16::{
    Assertions, PublicKeys, Signatures, N_TAPLEAVES
};
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::bn::Bn;


use super::api_runtime_utils::{execute_script_from_assertion, get_pubkeys, get_signature_from_assertion};


// Step 1
// The function takes public parameters (here verifying key) and generates partial script
// partial script is essentially disprove script minus the bitcommitment locking script
pub fn api_generate_partial_script(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<Script> {
    generate_partial_script(vk)
}

// Step 2
// given public keys and the partial scripts generated in api_generate_partial_script()
// it generates the complete disprove scripts
pub fn api_generate_full_tapscripts(
    inpubkeys: PublicKeys,
    ops_scripts_per_link: &[Script],
) -> Vec<Script> {
    let taps_per_link = append_bitcom_locking_script_to_partial_scripts(
        inpubkeys,
        ops_scripts_per_link.to_vec(),
    );
    assert_eq!(ops_scripts_per_link.len(), taps_per_link.len());
    taps_per_link
}

// Step 3
// given public and runtime parameters (proof and scalars) generate Assertions
pub fn generate_assertions(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
) -> Assertions {
    let (success, segments) = get_segments_from_groth16_proof(proof, scalars, vk);
    assert!(success);
    let assts = get_assertion_from_segments(&segments);
    execute_script_from_assertion(&segments, assts);
    assts
}


// Alternate Step 3
// given public and runtime parameters (proof and scalars) generate Assertions
pub fn generate_signatures(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
    secret: &str,
) -> Signatures {
    let (success, segments) = get_segments_from_groth16_proof(proof, scalars, vk);
    assert!(success);
    let assn = get_assertion_from_segments(&segments);
    let sigs = get_signature_from_assertion(assn, secret);
    let pubkeys = get_pubkeys(secret);

    let partial_scripts: Vec<Script> = partial_scripts_from_segments(&segments).into_iter().collect();
    let partial_scripts: [Script; N_TAPLEAVES] = partial_scripts.try_into().unwrap();
    let disprove_scripts = append_bitcom_locking_script_to_partial_scripts( pubkeys, partial_scripts.to_vec());
    let disprove_scripts: [Script; N_TAPLEAVES] = disprove_scripts.try_into().unwrap();

    execute_script_from_signature(&segments, sigs, &disprove_scripts);
    sigs
}

// Step 4
// validate signed assertions
// returns index of disprove script generated in Step 2 
// and the witness required to execute this Disprove Script incase of failure
pub fn validate_assertions(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: Signatures,
    _inpubkeys: PublicKeys,
    disprove_scripts: &[Script; N_TAPLEAVES],
) -> Option<(usize, Script)> {
    let asserts = get_assertions_from_signature(signed_asserts);
    let (success, segments) = get_segments_from_assertion(asserts, vk.clone());
    if !success {
        println!("invalid tapscript at segment {}", segments.len());
    }
    let exec_result = execute_script_from_signature(&segments, signed_asserts, disprove_scripts);
    assert_eq!(success, exec_result.is_none());
    exec_result
}

