
use std::collections::HashMap;

use ark_bn254::Bn254;
use ark_ec::bn::BnConfig;
use ark_ff::Field;
use bitcoin_script::script;
use treepp::Script;
use std::hash::{DefaultHasher, Hash, Hasher};

use crate::chunk::norm_fp12::{chunk_hash_c, chunk_hash_c_inv, chunk_hinted_square, chunk_init_t4, chunk_verify_fq6_is_on_field};
use crate::groth16::g16::{PublicKeys, N_TAPLEAVES};
use crate::{chunk::element::ElemG1Point, treepp};
use crate::chunk::element::ElemTraitExt;

use super::blake3compiled::hash_messages;
use super::element::{ElemFp6, ElemG2Eval, ElemU256, ElementType};
use super::taps_msm::{chunk_hash_p, chunk_msm};
use super::{assert::{groth16, Pubs}, element::{InputProof}, primitives::gen_bitcom, segment::{ScriptType, Segment}, taps_point_ops::*, taps_premiller::*, wots::WOTSPubKey};

pub const ATE_LOOP_COUNT: &'static [i8] = ark_bn254::Config::ATE_LOOP_COUNT;
pub const NUM_PUBS: usize = 1;
pub const NUM_U256: usize = 20;
pub const NUM_U160: usize = 380;
const VALIDATING_TAPS: usize = 7;
const HASHING_TAPS: usize = NUM_U160;
pub const NUM_TAPS: usize = HASHING_TAPS + VALIDATING_TAPS; 

pub(crate) struct Vkey {
    pub(crate) q2: ark_bn254::G2Affine,
    pub(crate) q3: ark_bn254::G2Affine,
    pub(crate) p3vk: Vec<ark_bn254::G1Affine>,
    pub(crate) p1q1: ark_bn254::Fq12,
    pub(crate) vky0: ark_bn254::G1Affine,
}

pub(crate) fn generate_partial_script(
    vk: Vkey,
) -> Vec<bitcoin_script::Script>  {
    println!("Preparing segments");
    let mock_segments = segments_from_pubs(vk, false);
    println!("Generating op scripts");
    let op_scripts: Vec<Script> = op_scripts_from_segments(&mock_segments).into_iter().collect();
    assert_eq!(op_scripts.len(), N_TAPLEAVES);
    op_scripts
}

pub(crate) fn append_bitcom_locking_script_to_partial_scripts(
    mock_vk: Vkey,
    inpubkeys: PublicKeys,
    ops_scripts: Vec<bitcoin_script::Script>,
) ->  Vec<bitcoin_script::Script> {
    let mock_segments = segments_from_pubs(mock_vk, true);

    let mut scalar_pubkeys = inpubkeys.0.to_vec();
    scalar_pubkeys.reverse();
    let mut felts_pubkeys = inpubkeys.1.to_vec();
    felts_pubkeys.reverse();
    let mut hash_pubkeys = inpubkeys.2.to_vec();
    hash_pubkeys.reverse();
    let mock_felt_pub = inpubkeys.0[0];

    let mut pubkeys: HashMap<u32, WOTSPubKey> = HashMap::new();
    for si  in 0..mock_segments.len() {
        let s = &mock_segments[si];
        if s.is_validation {
            let mock_fld_pub_key = WOTSPubKey::P256(mock_felt_pub);
            pubkeys.insert(si as u32, mock_fld_pub_key);
        } else {
            if s.result.1 == ElementType::FieldElem {
                pubkeys.insert(si as u32, WOTSPubKey::P256(felts_pubkeys.pop().unwrap()));
            } else if s.result.1 == ElementType::ScalarElem {
                pubkeys.insert(si as u32, WOTSPubKey::P256(scalar_pubkeys.pop().unwrap()));
            } else {
                pubkeys.insert(si as u32, WOTSPubKey::P160(hash_pubkeys.pop().unwrap()));
            }
        }
    }

    let bitcom_scripts: Vec<treepp::Script> = bitcom_scripts_from_segments(&mock_segments, pubkeys).into_iter().filter(|f| f.len() > 0).collect();
    assert_eq!(ops_scripts.len(), bitcom_scripts.len());
    let res: Vec<treepp::Script>  = ops_scripts.into_iter().zip(bitcom_scripts).map(|(op_scr, bit_scr)| 
        script!(
            {bit_scr}
            {op_scr}
        )   
    ).collect();

    res
}

fn segments_from_pubs(vk: Vkey, skip_evaluation: bool) -> Vec<Segment> {
    // values known only at runtime, can be mocked
    let mut segments: Vec<Segment> = vec![];
    let g1 = ElemG1Point::mock();
    let g2 = ElemG2Eval::mock().t;
    let fr = ElemU256::mock();
    let s = ElemFp6::mock();
    let c = ElemFp6::mock();
    let mocked_eval_ins: InputProof = InputProof { p2: g1, p4: g1, q4: g2, c, s, ks: vec![fr.into()] };

    // public values known at compile time
    let pubs: Pubs = Pubs { q2: vk.q2, q3: vk.q3, fixed_acc: vk.p1q1.c1/vk.p1q1.c0, ks_vks: vk.p3vk, vky0: vk.vky0 };
    groth16(skip_evaluation, &mut segments, mocked_eval_ins.to_raw(), pubs, &mut None);
    segments
}

pub(crate) fn op_scripts_from_segments(segments: &Vec<Segment>) -> Vec<treepp::Script> {
   fn serialize_element_types(elems: &[ElementType]) -> String {
        // 1. Convert each variant to its string representation.
        let joined = elems
            .iter()
            .map(|elem| format!("{:?}", elem)) // uses #[derive(Debug)]
            .collect::<Vec<String>>()
            .join("-");
    
        // 2. Compute a simple 64-bit hash of that string
        let mut hasher = DefaultHasher::new();
        joined.hash(&mut hasher);
        let unique_hash = hasher.finish();
    
        // 3. Concatenate final result as "ENUM1-ENUM2-ENUM3|hash"
        format!("{}|{}", joined, unique_hash)
    }


    let mut op_scripts: Vec<treepp::Script> = vec![];

    let mut hashing_script_cache: HashMap<String, Script> = HashMap::new();
    for s in segments {
        if s.is_validation || s.scr_type == ScriptType::NonDeterministic {
            continue;
        }
        let mut elem_types_to_hash: Vec<ElementType> = s.parameter_ids.iter().rev().map(|f| f.1).collect();
        elem_types_to_hash.push(s.result.1);
        let elem_types_str = serialize_element_types(&elem_types_to_hash);
        if !hashing_script_cache.contains_key(&elem_types_str) {
            let hash_scr = script!(
                {hash_messages(elem_types_to_hash)}
                OP_TRUE
            );
            hashing_script_cache.insert(elem_types_str, hash_scr);
        }
    };

    for i in 0..segments.len() {
        let seg= &segments[i];
        let scr_type = seg.scr_type.clone();
        if scr_type == ScriptType::NonDeterministic {
            continue;
        }

        let op_scr  = seg.scr.clone();

        if seg.is_validation { // validating segments do not have output hash, so don't add hashing layer; they are self sufficient
            op_scripts.push(op_scr);
        } else {
            let mut elem_types_to_hash: Vec<ElementType> = seg.parameter_ids.iter().rev().map(|(_, param_seg_type)| *param_seg_type).collect();
            elem_types_to_hash.push(seg.result.1);
            let elem_types_str = serialize_element_types(&elem_types_to_hash);
            let hash_scr = hashing_script_cache.get(&elem_types_str).unwrap();
            assert!(hash_scr.len() > 0);
            op_scripts.push(script!(
                {op_scr}
                {hash_scr.clone()}
            ));
        }
    }
    op_scripts
}

pub(crate) fn bitcom_scripts_from_segments(segments: &Vec<Segment>, pubkeys_map: HashMap<u32, WOTSPubKey>) -> Vec<treepp::Script> {
    let mut bitcom_scripts: Vec<treepp::Script> = vec![];
    for seg in segments {
        let mut sec = vec![];
        if !seg.is_validation {
            sec.push((seg.id as u32, segments[seg.id as usize].result.0.output_is_field_element()));
        };
        let sec_in: Vec<(u32, bool)> = seg.parameter_ids.iter().map(|(f, _)| {
            let elem = &segments[*(f) as usize];
            let elem_type = elem.result.0.output_is_field_element();
            (*f, elem_type)
        }).collect();
        sec.extend_from_slice(&sec_in);
        match seg.scr_type {
            ScriptType::NonDeterministic => {
                bitcom_scripts.push(script!());
            },
            _ => {
                bitcom_scripts.push(gen_bitcom(&pubkeys_map, sec));
            }
        }
    }
    bitcom_scripts
}
