use rand::Rng; 
use rand::thread_rng;

use crate::treepp::*;
use bitcoin::{ScriptBuf, hashes::{hash160, Hash}, Witness};
use crate::{hash::blake3_u4::{blake3_script, blake3_bitvm_version, bytes_to_nibbles_blake3_output}, signatures::winternitz::{ListpickVerifier, VoidConverter, Winternitz, PublicKey, SecretKey, Parameters, generate_public_key}};
use crate::clementine::utils::{roll_constant, extend_witness};

static WINTERNITZ_VERIFIER: Winternitz<ListpickVerifier, VoidConverter> = Winternitz::new();

// ALL the constants need to be divisible by 4
type ChallengeHashType = [u8; 20];
const COMBINED_METHOD_ID_LEN: usize = 32;
const DEPOSIT_CONSTANT_LEN: usize = 32;
const G16_PUBLIC_INPUT_LEN: usize = 32;
const PAYOUT_TX_BLOCKHASH_LEN: usize = 20;
const LATEST_BLOCKHASH_LEN: usize = 20;
const CHALLENGE_SENDING_WATCHTOWERS_LEN: usize = 20; // this * 8 watchtowers assumed to exist, if there are %8 != 0 wathctowers, we can change the code 
const WATHCTOWER_COUNT: usize = CHALLENGE_SENDING_WATCHTOWERS_LEN * 8;
const NO_ACKNOWLEDGMENT_VALUE: ChallengeHashType = [0u8; 20]; // for not acknowledged preimages, might not be safe, discuss
const WINTERNITZ_SECRET_KEY_LEN: usize = 40;
const WINTERNITZ_BLOCK_LEN: u32 = 4;
const BLAKE3_OUTPUT_LEN: u32 = 32; // should be equal to G16_PUBLIC_INPUT_LEN 

type ScriptInBytes = Vec<u8>;
const REPLACEMENT_INDEX: usize = 17452; // Start of the PAYOUT_TX_BLOCKHASH's checksig's opcodes

// Reverse the whole message, and swap digits of each byte
fn reorder_winternitz_output_for_blake3(len: usize) -> Script {
    script! {
        for i in (0..len).step_by(2).rev() { 
            { roll_constant(i) }
            OP_TOALTSTACK
            { roll_constant(i) }
            OP_TOALTSTACK
        }
        for _ in 0..len {
            OP_FROMALTSTACK
        }
    }
}

fn generate_winternitz_secret_key() -> SecretKey {
    let mut rng = thread_rng(); // might be unsafe, dicuss this (Probably won't be used in production anyway and will be just for tests) 
    (0..WINTERNITZ_SECRET_KEY_LEN).map(|_| rng.gen()).collect() 
}

// in the form of bytes_to_nibbles_for_blake3 i.e. each byte's 4 last and first bits swap places
fn change_the_order_of_operator_challenge_acks_according_to_blake3_stack<T>(operator_challenge_ack: &mut [T; WATHCTOWER_COUNT]) {
    for i in (0..WATHCTOWER_COUNT).step_by(8) {
        let (first_half, second_half) = operator_challenge_ack.split_at_mut(i + 4);
        first_half[i..i+4].swap_with_slice(&mut second_half[..4]);
    }
}

fn get_signatures( 
    g16_public_input: [u8; G16_PUBLIC_INPUT_LEN], 
    payout_tx_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN], 
    latest_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN], 
    challenge_sending_watchtowers: [u8; CHALLENGE_SENDING_WATCHTOWERS_LEN], 
    g16_public_input_sk: SecretKey, 
    payout_tx_blockhash_sk: SecretKey, 
    latest_blockhash_sk: SecretKey, 
    challenge_sending_watchtowers_sk: SecretKey) -> [Witness; 4] {
    [
        WINTERNITZ_VERIFIER.sign(&Parameters::new_by_bit_length((G16_PUBLIC_INPUT_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &g16_public_input_sk, &g16_public_input.to_vec()),
        WINTERNITZ_VERIFIER.sign(&Parameters::new_by_bit_length((PAYOUT_TX_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &payout_tx_blockhash_sk, &payout_tx_blockhash.to_vec()),
        WINTERNITZ_VERIFIER.sign(&Parameters::new_by_bit_length((LATEST_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &latest_blockhash_sk, &latest_blockhash.to_vec()),
        WINTERNITZ_VERIFIER.sign(&Parameters::new_by_bit_length((CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &challenge_sending_watchtowers_sk, &challenge_sending_watchtowers.to_vec()),
    ]
}

fn get_witness_with_signatures(
    g16_public_input_signature: Witness,
    payout_tx_blockhash_signature: Witness,
    latest_blockhash_signature: Witness, 
    challenge_sending_watchtowers_signature: Witness, 
    mut operator_challenge_ack_preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT], // None's are turned into random values 
) -> Witness {
    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(&mut operator_challenge_ack_preimages);
    let operator_challenge_ack_preimages_push_values: [ChallengeHashType; WATHCTOWER_COUNT] = 
    operator_challenge_ack_preimages
        .iter()
        .map(|preimage| preimage.clone().unwrap_or(NO_ACKNOWLEDGMENT_VALUE))
        .collect::<Vec<_>>()
        .try_into()
        .expect("This should be impossible");

    let mut w = Witness::new();
    extend_witness(&mut w, payout_tx_blockhash_signature);
    extend_witness(&mut w, latest_blockhash_signature);
    for preimage in operator_challenge_ack_preimages_push_values {
        w.push(preimage.to_vec());
    }
    extend_witness(&mut w, challenge_sending_watchtowers_signature);
    extend_witness(&mut w, g16_public_input_signature);
    w
}

/* 
fn get_witness_for_additional_script(
    g16_public_input: [u8; G16_PUBLIC_INPUT_LEN], 
    payout_tx_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN], 
    latest_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN], 
    challenge_sending_watchtowers: [u8; CHALLENGE_SENDING_WATCHTOWERS_LEN], 
    operator_challenge_ack_preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT], // None's are turned into random values 
    g16_public_input_sk: SecretKey, 
    payout_tx_blockhash_sk: SecretKey, 
    latest_blockhash_sk: SecretKey, 
    challenge_sending_watchtowers_sk: SecretKey
) -> Witness {
    let (g16_public_input_signature, payout_tx_blockhash_signature, latest_blockhash_signature, challenge_sending_watchtowers_signature) = get_signatures(g16_public_input, payout_tx_blockhash, latest_blockhash, challenge_sending_watchtowers, g16_public_input_sk, payout_tx_blockhash_sk, latest_blockhash_sk, challenge_sending_watchtowers_sk).try_into().expect("impossible");
    get_witness_with_signatures(
        g16_public_input_signature,
        payout_tx_blockhash_signature,
        latest_blockhash_signature,
        challenge_sending_watchtowers_signature,
        operator_challenge_ack_preimages
    )
}
*/

/// Replacable payout_tx_blockhash_pk
/// THIS MIGHT NOT BE WORK SINCE PUSHING ELEMENTS WITH ZEROES CAN RESULT IN HAVING DIFFERENT LENGTHS DUE TO WITNESS OPTIMIZATIONS, BUT SEEMS SAFE FOR NOW
pub struct ReplacableDisproveScript {
    script: ScriptInBytes, 
    //replacement_index: usize
}

//note: instead of maintaining a status variable, you can just alter the hashed inputs which would make the final check invalid, but discuss this optimization
pub fn create_additional_replacable_disprove_script(
    combined_method_id_constant: [u8; COMBINED_METHOD_ID_LEN], 
    deposit_constant: [u8; DEPOSIT_CONSTANT_LEN], 
    g16_public_input_pk: PublicKey, 
    payout_tx_blockhash_pk: PublicKey, 
    latest_blockhash_pk: PublicKey, 
    challenge_sending_watchtowers_pk: PublicKey, 
    mut operator_challenge_ack_hashes: [ChallengeHashType; WATHCTOWER_COUNT]
) -> ReplacableDisproveScript {
    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(&mut operator_challenge_ack_hashes);
    
    let pre_replacement = script! {
        // I'm not checking the number of arguments currently, but I maybe should? Think about this
        
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((G16_PUBLIC_INPUT_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &g16_public_input_pk) }
        { reorder_winternitz_output_for_blake3(G16_PUBLIC_INPUT_LEN * 2) } //Winternitz reverses the message

        for _ in 0..(G16_PUBLIC_INPUT_LEN * 2) {
            OP_TOALTSTACK
        }
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &challenge_sending_watchtowers_pk) }
        { reorder_winternitz_output_for_blake3(CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) } //Winternitz reverses the message

        { 0 } // If all of the hashes are valid, this should stay as zero
        OP_TOALTSTACK
        
        for (i, chunk) in operator_challenge_ack_hashes.chunks(4).enumerate().rev() {
            OP_DUP OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            for b in (0..4).rev() {
                if b != 0 {
                    { 1 << b } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF 
                        OP_SUB
                        { 0 }
                    OP_ELSE 
                        OP_DROP 
                        { 1 }
                    OP_ENDIF
                    { roll_constant(i + 2) }
                } else {
                    //Number is the result
                    OP_NOT // Range shouldn't be an issue due to winternitz bound checks
                    { roll_constant(i + 1) }
                }
                OP_HASH160
                { chunk[b].to_vec() }
                OP_EQUAL
                OP_BOOLAND
                OP_FROMALTSTACK
                OP_BOOLOR
                OP_TOALTSTACK
            }
        }
        
        // {payout_tx_blockhash_signature, latest_blockhash_signature}  {g16_public_input, challenge_sending_watctowers, result_of_the_preimage_check(bool)}
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((LATEST_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &latest_blockhash_pk) }
        { reorder_winternitz_output_for_blake3(LATEST_BLOCKHASH_LEN * 2) } //Winternitz reverses the message

        for _ in 0..(LATEST_BLOCKHASH_LEN * 2) {
            OP_TOALTSTACK
        }
    };
    
    ReplacableDisproveScript {
        script: script! {
            { pre_replacement }
            { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((PAYOUT_TX_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &payout_tx_blockhash_pk) } // This will be replaced
            { reorder_winternitz_output_for_blake3(PAYOUT_TX_BLOCKHASH_LEN * 2) } //Winternitz reverses the message

            for _ in 0..(LATEST_BLOCKHASH_LEN * 2) {
                OP_FROMALTSTACK
            }
            OP_FROMALTSTACK // preimage check result
            for _ in 0..(CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) {
                OP_FROMALTSTACK
            }
            { roll_constant(CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) } //send preimage result to the back
            OP_TOALTSTACK
            { blake3_script((PAYOUT_TX_BLOCKHASH_LEN + LATEST_BLOCKHASH_LEN + CHALLENGE_SENDING_WATCHTOWERS_LEN) as u32) }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_TOALTSTACK
            }
            for x in bytes_to_nibbles_blake3_output(deposit_constant.to_vec()) {
                { x }
            }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_FROMALTSTACK
            }
            { blake3_script(DEPOSIT_CONSTANT_LEN as u32 + BLAKE3_OUTPUT_LEN) }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_TOALTSTACK
            }
            for x in bytes_to_nibbles_blake3_output(combined_method_id_constant.to_vec()) {
                { x }
            }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_FROMALTSTACK
            }
            { blake3_script(COMBINED_METHOD_ID_LEN as u32 + BLAKE3_OUTPUT_LEN) }
            OP_FROMALTSTACK // preimage check result
            for _ in 0..(G16_PUBLIC_INPUT_LEN * 2) {
                OP_FROMALTSTACK
            }
            { roll_constant(G16_PUBLIC_INPUT_LEN * 2) } //send preimage result to the back
            OP_TOALTSTACK 
            // This can be done in reverse more efficiently, but meh. For later revisions
            for i in (0..(G16_PUBLIC_INPUT_LEN * 2)).rev() {
                { roll_constant(i + 1) }
                OP_NUMNOTEQUAL // Both in range, so should be fine
                OP_FROMALTSTACK
                OP_BOOLOR
                if i != 0 {
                    OP_TOALTSTACK
                }
            }
        }.compile().into_bytes(),
    }
}


/// This function changes with the `create_additional_replacable_disprove_script`
fn calculate_additional_replacable_disprove_script_replacement_index(
    _: [u8; COMBINED_METHOD_ID_LEN], 
    _: [u8; DEPOSIT_CONSTANT_LEN], 
    g16_public_input_pk: PublicKey, 
    _: PublicKey, 
    latest_blockhash_pk: PublicKey, 
    challenge_sending_watchtowers_pk: PublicKey, 
    mut operator_challenge_ack_hashes: [ChallengeHashType; WATHCTOWER_COUNT]
) -> usize {    
    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(&mut operator_challenge_ack_hashes);
    
    let pre_replacement = script! {
        // I'm not checking the number of arguments currently, but I maybe should? Think about this
        
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((G16_PUBLIC_INPUT_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &g16_public_input_pk) }
        { reorder_winternitz_output_for_blake3(G16_PUBLIC_INPUT_LEN * 2) } //Winternitz reverses the message

        for _ in 0..(G16_PUBLIC_INPUT_LEN * 2) {
            OP_TOALTSTACK
        }
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &challenge_sending_watchtowers_pk) }
        { reorder_winternitz_output_for_blake3(CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) } //Winternitz reverses the message

        { 0 } // If all of the hashes are valid, this should stay as zero
        OP_TOALTSTACK
        
        for (i, chunk) in operator_challenge_ack_hashes.chunks(4).enumerate().rev() {
            OP_DUP OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            for b in (0..4).rev() {
                if b != 0 {
                    { 1 << b } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF 
                        OP_SUB
                        { 0 }
                    OP_ELSE 
                        OP_DROP 
                        { 1 }
                    OP_ENDIF
                    { roll_constant(i + 2) }
                } else {
                    //Number is the result
                    OP_NOT // Range shouldn't be an issue due to winternitz bound checks
                    { roll_constant(i + 1) }
                }
                OP_HASH160
                { chunk[b].to_vec() }
                OP_EQUAL
                OP_BOOLAND
                OP_FROMALTSTACK
                OP_BOOLOR
                OP_TOALTSTACK
            }
        }
        
        // {payout_tx_blockhash_signature, latest_blockhash_signature}  {g16_public_input, challenge_sending_watctowers, result_of_the_preimage_check(bool)}
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((LATEST_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &latest_blockhash_pk) }
        { reorder_winternitz_output_for_blake3(LATEST_BLOCKHASH_LEN * 2) } //Winternitz reverses the message

        for _ in 0..(LATEST_BLOCKHASH_LEN * 2) {
            OP_TOALTSTACK
        }
    };
    pre_replacement.compile().len()
}

/// These values are acquired from winternitz signatures
pub fn validate_assertions_for_additional_script(
    r_script: ScriptInBytes, 
    g16_public_input_signature: Witness,
    payout_tx_blockhash_signature: Witness,
    latest_blockhash_signature: Witness, 
    challenge_sending_watchtowers_signature: Witness, 
    operator_challenge_ack_preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT], // None's are turned into random values 
) -> Option<Witness> {
    let w = get_witness_with_signatures(g16_public_input_signature, payout_tx_blockhash_signature, latest_blockhash_signature, challenge_sending_watchtowers_signature, operator_challenge_ack_preimages);
    let witness_script = script! {
        { w.clone() }
    };
    if execute_script(witness_script.push_script(ScriptBuf::from_bytes(r_script))).success {
        Some(w)
    } else {
        None
    }
}

impl ReplacableDisproveScript {
    fn replace_payout_tx_blockhash(&mut self, 
        payout_tx_blockhash_pk: PublicKey, 
    ) {
        let replacement = WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((PAYOUT_TX_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &payout_tx_blockhash_pk).compile().to_bytes();
        for i in 0..replacement.len() {
            self.script[REPLACEMENT_INDEX + i] = replacement[i];
        }
    }
}
    

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn concat_all<T: Clone>(lists: &[&[T]]) -> Vec<T> {
        lists.iter().flat_map(|list| list.iter().cloned()).collect()
    }
    struct SignerData {
        combined_method_id_constant: [u8; COMBINED_METHOD_ID_LEN], 
        deposit_constant: [u8; DEPOSIT_CONSTANT_LEN], 
        g16_public_input: [u8; G16_PUBLIC_INPUT_LEN], 
        payout_tx_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN], 
        latest_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN], 
        challenge_sending_watchtowers: [u8; CHALLENGE_SENDING_WATCHTOWERS_LEN], 
        operator_challenge_ack_preimages: [ChallengeHashType; WATHCTOWER_COUNT],
        g16_public_input_sk: SecretKey, 
        payout_tx_blockhash_sk: SecretKey, 
        latest_blockhash_sk: SecretKey, 
        challenge_sending_watchtowers_sk: SecretKey
    }
    struct PublicData {
        combined_method_id_constant: [u8; COMBINED_METHOD_ID_LEN], 
        deposit_constant: [u8; DEPOSIT_CONSTANT_LEN], 
        g16_public_input_pk: PublicKey, 
        payout_tx_blockhash_pk: PublicKey, 
        latest_blockhash_pk: PublicKey, 
        challenge_sending_watchtowers_pk: PublicKey, 
        operator_challenge_ack_hashes: [ChallengeHashType; WATHCTOWER_COUNT]
    }

    fn random_signer_data(seed: u64) -> SignerData {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut s = SignerData {
            combined_method_id_constant: rng.gen::<[u8; COMBINED_METHOD_ID_LEN]>(),
            deposit_constant:  rng.gen::<[u8; DEPOSIT_CONSTANT_LEN]>(),
            g16_public_input: [0; G16_PUBLIC_INPUT_LEN], //calculate later
            payout_tx_blockhash: rng.gen::<[u8; PAYOUT_TX_BLOCKHASH_LEN]>(),
            latest_blockhash: rng.gen::<[u8; PAYOUT_TX_BLOCKHASH_LEN]>(),
            challenge_sending_watchtowers: rng.gen::<[u8; CHALLENGE_SENDING_WATCHTOWERS_LEN]>(),
            operator_challenge_ack_preimages: std::array::from_fn(|_| rng.gen()), 
            g16_public_input_sk: generate_winternitz_secret_key(),
            payout_tx_blockhash_sk: generate_winternitz_secret_key(),
            latest_blockhash_sk: generate_winternitz_secret_key(),
            challenge_sending_watchtowers_sk: generate_winternitz_secret_key(),
        };
        let x = blake3_bitvm_version(concat_all(&[&s.payout_tx_blockhash, &s.latest_blockhash, &s.challenge_sending_watchtowers]));
        let y = blake3_bitvm_version(concat_all(&[&s.deposit_constant, &x]));
        let f = blake3_bitvm_version(concat_all(&[&s.combined_method_id_constant, &y]));
        s.g16_public_input = f;
        s
    }

    fn get_public_data_from_signer(signer_data: &SignerData) -> PublicData {
        let mut p = PublicData {
            combined_method_id_constant: signer_data.combined_method_id_constant,
            deposit_constant: signer_data.deposit_constant, 
            g16_public_input_pk: generate_public_key(&Parameters::new_by_bit_length((G16_PUBLIC_INPUT_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &signer_data.g16_public_input_sk), 
            payout_tx_blockhash_pk: generate_public_key(&Parameters::new_by_bit_length((PAYOUT_TX_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &signer_data.payout_tx_blockhash_sk), 
            latest_blockhash_pk: generate_public_key(&Parameters::new_by_bit_length((LATEST_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &signer_data.latest_blockhash_sk), 
            challenge_sending_watchtowers_pk: generate_public_key(&Parameters::new_by_bit_length((CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &signer_data.challenge_sending_watchtowers_sk), 
            operator_challenge_ack_hashes: [[0u8; 20]; WATHCTOWER_COUNT]
        };
        for i in 0..WATHCTOWER_COUNT {
            p.operator_challenge_ack_hashes[i] = *hash160::Hash::hash(&signer_data.operator_challenge_ack_preimages[i].to_vec()).as_byte_array()
        }
        p
    }

    fn create_script_with_public_data(public_data: &PublicData) -> ReplacableDisproveScript {
        create_additional_replacable_disprove_script(
            public_data.combined_method_id_constant, 
            public_data.deposit_constant, 
            public_data.g16_public_input_pk.clone(), 
            public_data.payout_tx_blockhash_pk.clone(), 
            public_data.latest_blockhash_pk.clone(), 
            public_data.challenge_sending_watchtowers_pk.clone(), 
            public_data.operator_challenge_ack_hashes
        )
    }

    fn calculate_replacement_length_with_public_data(public_data: &PublicData) -> usize {
        calculate_additional_replacable_disprove_script_replacement_index(
            public_data.combined_method_id_constant, 
            public_data.deposit_constant, 
            public_data.g16_public_input_pk.clone(), 
            public_data.payout_tx_blockhash_pk.clone(), 
            public_data.latest_blockhash_pk.clone(), 
            public_data.challenge_sending_watchtowers_pk.clone(), 
            public_data.operator_challenge_ack_hashes
        )
    }

    fn non_malicious_test_validate(script: ScriptInBytes, signer_data: &SignerData) {
        let mut preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT] = 
        std::array::from_fn(|_| None);
        for i in 0..WATHCTOWER_COUNT {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                preimages[i] = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (g16_public_input_signature, payout_tx_blockhash_signature, latest_blockhash_signature, challenge_sending_watchtowers_signature) = get_signatures(signer_data.g16_public_input, signer_data.payout_tx_blockhash, signer_data.latest_blockhash, signer_data.challenge_sending_watchtowers, signer_data.g16_public_input_sk.clone(), signer_data.payout_tx_blockhash_sk.clone(), signer_data.latest_blockhash_sk.clone(), signer_data.challenge_sending_watchtowers_sk.clone()).try_into().expect("impossible");
        assert!(validate_assertions_for_additional_script(script, g16_public_input_signature, payout_tx_blockhash_signature, latest_blockhash_signature, challenge_sending_watchtowers_signature, preimages).is_some() == false);
    }

    fn malicious_revealed_preimage_validate(script: ScriptInBytes, signer_data: &SignerData) {
        let mut preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT] = 
        std::array::from_fn(|_| None);
        let mut first = true;
        for i in 0..WATHCTOWER_COUNT {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                preimages[i] = Some(signer_data.operator_challenge_ack_preimages[i]);
            } else if first {
                first = false;
                preimages[i] = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (g16_public_input_signature, payout_tx_blockhash_signature, latest_blockhash_signature, challenge_sending_watchtowers_signature) = get_signatures(signer_data.g16_public_input, signer_data.payout_tx_blockhash, signer_data.latest_blockhash, signer_data.challenge_sending_watchtowers, signer_data.g16_public_input_sk.clone(), signer_data.payout_tx_blockhash_sk.clone(), signer_data.latest_blockhash_sk.clone(), signer_data.challenge_sending_watchtowers_sk.clone()).try_into().expect("impossible");
        assert!(validate_assertions_for_additional_script(script, g16_public_input_signature, payout_tx_blockhash_signature, latest_blockhash_signature, challenge_sending_watchtowers_signature, preimages).is_some() == true);
    }

    fn malicious_gibberish_g16_data_validate(script: ScriptInBytes, signer_data: &SignerData) {
        let mut preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT] = 
        std::array::from_fn(|_| None);
        for i in 0..WATHCTOWER_COUNT {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                preimages[i] = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (g16_public_input_signature, payout_tx_blockhash_signature, latest_blockhash_signature, challenge_sending_watchtowers_signature) = get_signatures([0u8; G16_PUBLIC_INPUT_LEN], signer_data.payout_tx_blockhash, signer_data.latest_blockhash, signer_data.challenge_sending_watchtowers, signer_data.g16_public_input_sk.clone(), signer_data.payout_tx_blockhash_sk.clone(), signer_data.latest_blockhash_sk.clone(), signer_data.challenge_sending_watchtowers_sk.clone()).try_into().expect("impossible");
        assert!(validate_assertions_for_additional_script(script, g16_public_input_signature, payout_tx_blockhash_signature, latest_blockhash_signature, challenge_sending_watchtowers_signature, preimages).is_some() == true);
    }

    #[test]
    fn test_calculating_public_input() {
        let signer_data = random_signer_data(4237);
        let s = script! {
            for x in bytes_to_nibbles_blake3_output(signer_data.payout_tx_blockhash.to_vec()) {
                { x }
            }
            for x in bytes_to_nibbles_blake3_output(signer_data.latest_blockhash.to_vec()) {
                { x }
            }
            for x in bytes_to_nibbles_blake3_output(signer_data.challenge_sending_watchtowers.to_vec()) {
                { x }
            }
            { blake3_script((PAYOUT_TX_BLOCKHASH_LEN + LATEST_BLOCKHASH_LEN + CHALLENGE_SENDING_WATCHTOWERS_LEN) as u32) }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_TOALTSTACK
            }
            for x in bytes_to_nibbles_blake3_output(signer_data.deposit_constant.to_vec()) {
                { x }
            }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_FROMALTSTACK
            }
            { blake3_script(DEPOSIT_CONSTANT_LEN as u32 + BLAKE3_OUTPUT_LEN) }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_TOALTSTACK
            }
            for x in bytes_to_nibbles_blake3_output(signer_data.combined_method_id_constant.to_vec()) {
                { x }
            }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_FROMALTSTACK
            }
            { blake3_script(COMBINED_METHOD_ID_LEN as u32 + BLAKE3_OUTPUT_LEN) }
            for x in bytes_to_nibbles_blake3_output(signer_data.g16_public_input.to_vec()) {
                { x }
            }
            for i in (0..(G16_PUBLIC_INPUT_LEN * 2)).rev() {
                { roll_constant(i + 1) }
                OP_EQUALVERIFY
            }
            { 1 }
        };
        execute_script(s);
    }

    #[test]
    fn test_preimage_calculation() {
        let signer_data = random_signer_data(37);
        let public_data = get_public_data_from_signer(&signer_data);
        execute_script(script!{
            for i in 0..WATHCTOWER_COUNT {
                { signer_data.operator_challenge_ack_preimages[i].to_vec() }
                OP_HASH160
                { public_data.operator_challenge_ack_hashes[i].to_vec() }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });
    }

    #[test]
    fn test_winternitz_to_blake3() {
        const SAMPLE_SECRET_KEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let secret_key = match hex::decode(SAMPLE_SECRET_KEY) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
        let mut rng = ChaCha20Rng::seed_from_u64(37 as u64);
        for _ in 0..20 {
            let size = rng.gen_range(1..=25) * 4; 
            let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let ps = Parameters::new_by_bit_length(size * 8, 4);
            let result = bytes_to_nibbles_blake3_output(blake3_bitvm_version(v.clone()).to_vec());
            let s = script! {
                { WINTERNITZ_VERIFIER.sign(&ps, &secret_key, &v) }
                { WINTERNITZ_VERIFIER.checksig_verify(&ps, &generate_public_key(&ps, &secret_key))}
                { reorder_winternitz_output_for_blake3(size as usize * 2) }
                { blake3_script(size) }
                for i in (0..64).rev() {
                    { result[i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(s)
        }
    }

    #[test]
    fn test_validate_assertions() {
        for seed in 0..100 {
            let signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            let s = create_script_with_public_data(&public_data);
            let buffer = s.script;
            non_malicious_test_validate(buffer.clone(), &signer_data);
            malicious_revealed_preimage_validate(buffer.clone(), &signer_data);
            malicious_gibberish_g16_data_validate(buffer.clone(), &signer_data);
        } 
    }

    #[test]
    fn test_constant_replacement_index() {
        // This shouldn't change,  but just in case
        for seed in 0..100 {
            let signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            assert!(calculate_replacement_length_with_public_data(&public_data) == REPLACEMENT_INDEX);
        }  
    }

    #[test]
    fn tests_replacement() {
        for seed in 0..100 {
            let mut signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            let mut s = create_script_with_public_data(&public_data);
            signer_data.payout_tx_blockhash_sk = generate_winternitz_secret_key();
            s.replace_payout_tx_blockhash(generate_public_key(&&Parameters::new_by_bit_length(PAYOUT_TX_BLOCKHASH_LEN as u32 * 8, WINTERNITZ_BLOCK_LEN), &signer_data.payout_tx_blockhash_sk));
            let buffer = s.script;
            non_malicious_test_validate(buffer.clone(), &signer_data);
            malicious_revealed_preimage_validate(buffer.clone(), &signer_data);
            malicious_gibberish_g16_data_validate(buffer.clone(), &signer_data);
        }         
    }
}