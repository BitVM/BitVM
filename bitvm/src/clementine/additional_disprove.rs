use crate::clementine::utils::{extend_witness, roll_constant};
use crate::treepp::*;
use crate::{
    hash::blake3_u4::{blake3_script, bytes_to_nibbles},
    signatures::winternitz::{
        generate_public_key, ListpickVerifier, Parameters, PublicKey, VoidConverter, Winternitz,
    },
};
use bitcoin::Witness;

use super::utils::does_unlock;

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
const NO_ACKNOWLEDGMENT_VALUE: ChallengeHashType = [0u8; 20]; // for not acknowledged preimages, might not be safe
const WINTERNITZ_BLOCK_LEN: u32 = 4;
const BLAKE3_OUTPUT_LEN: u32 = 32; // should be equal to G16_PUBLIC_INPUT_LEN

/// Start of the PAYOUT_TX_BLOCKHASH's checksig's opcodes, precalculated for optimization \
/// If any changes are made to the creating script functions, this should be changed to with the corresponding calculation function inside the tests
const PRECALCULATED_REPLACEMENT_INDEX: usize = 17452;

/// The Winternitz output reverses the message, and BLAKE3 swaps the nibbles.
/// This script reorders the nibbles of a Winternitz `checksig_verify` output (message) so that it is in the necessary format for BLAKE3.
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

/// BLAKE3 in bitVM partitions each byte to 4 bits and puts the more significant ones to the back instead of front
/// To accommodate for this change for any operator_challenge_ack related value, ordering of each 8 consecutive elements are changed
/// i.e. from a_0, a_1, a_2, a_3, a_4, a_5, a_6, a_7, to a_4, a_5, a_6, a_7, a_0, a_1, a_2, a_3
fn change_the_order_of_operator_challenge_acks_according_to_blake3_stack<T>(
    operator_challenge_ack: &mut [T; WATHCTOWER_COUNT],
) {
    for i in (0..WATHCTOWER_COUNT).step_by(8) {
        let (first_half, second_half) = operator_challenge_ack.split_at_mut(i + 4);
        first_half[i..i + 4].swap_with_slice(&mut second_half[..4]);
    }
}

/// Given the signatures and acknowledged preimages, returns the witness that will be used to unlock the script (if the parameters are correct)
fn get_witness_with_signatures(
    g16_public_input_signature: Witness,
    payout_tx_blockhash_signature: Witness,
    latest_blockhash_signature: Witness,
    challenge_sending_watchtowers_signature: Witness,
    mut operator_challenge_ack_preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT], // None's are turned into random values
) -> Witness {
    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(
        &mut operator_challenge_ack_preimages,
    );
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

/// Generates the additional disprove script using given parameters.
///
/// Given the provided constants, public keys, and acknowledgment hashes, this script evaluates three conditions:
///
/// 1. **Signature Verification:**  
///    Ensures that all given signatures (provided in the unlocking script - witness)  
///    match the corresponding public keys passed as function arguments.
///
/// 2. **Hash Equality Check:**  
///    Verifies whether the signed values satisfy the following equality constraint  
///    (expressed using two auxiliary variables for clarity):  
///
///    - `X = BLAKE3(payout_tx_blockhash, latest_blockhash, challenge_sending_watchtowers)`  
///    - `Y = BLAKE3(deposit_constant, X)`  
///    - `groth16_public_input = BLAKE3(combined_method_id_constant, Y)`  
///
/// 3. **Compliance of Acknowledged Preimages and `challenge_sending_watchtowers` Check:**  
///    Ensures that there exists at least one watchtower such that:  
///    - Its acknowledgment bit is set to zero.  
///    - The given preimage in the unlocking script (witness), when hashed using `OP_HASH160`, matches the watchtower's expected hash.  
///
///    The script is spendable if **condition 1 is satisfied** and **at least one of conditions 2 or 3 is not met**, meaning the spending condition is:  
///
///    `Signature Verification AND NOT (Hash Equality Check AND Compliance of Acknowledged Preimages and challenge_sending_watchtowers Check)`
///
///    To successfully unlock, the script expects a witness in the following format:  
///
///    ```text
///    [
///      payout_tx_blockhash_signature,  
///      latest_blockhash_signature,  
///      `WATCHTOWER_COUNT` preimages (in the corrected format) (if a preimage is not revealed, a dummy value can be used instead),  
///      challenge_sending_watchtowers_signature,  
///      g16_public_input_signature  
///    ]
///    ```
///     
///     The `payout_tx_blockhash_pk` can be replaced with another public key, using the returned index and the function `replace_payout_tx_blockhash`
///
/// ## Arguments
///
/// * `combined_method_id_constant` - Combined Method ID, in bytes
/// * `deposit_constant` - Deposit Constant, in bytes
/// * `g16_public_input_pk` - Winternitz Public key for Groth16 Public Input used in BitVM
/// * `payout_tx_blockhash_pk` - Winternitz Public key for Payout Transaction Blockhash, this public key is later replacable by other functions
/// * `latest_blockhash_pk` - Winternitz Public key for Latest Blockhash
/// * `challenge_sending_watchtowers_pk` - Winternitz Public key for the array of challenge sending watchtowers; in this array, watchtowers are numerated in the order of the numbers and their least significant bit
/// * `operator_challenge_ack_hashes` - Operator's acknowledgement hashes for each watchtower, i.e. result of OP_HASH160'd preimages
///
/// ## Returns
///
/// A tuple containing:
/// * `Vec<u8>` - The compiled Bitcoin script as a byte vector.
/// * `usize` - The replacement index for payout_tx_blockhash_pk's signature verification
///
/// ## Notes
///
/// - Checking the number of arguments might be necessary, in order to block malicious attempts
/// - To use 'wots_api.rs' public keys, it is enough to cast them to vectors
/// - If another script is pushed to the start of the returned script, returned replacement index needs to be increased by the length of such script, to be used with `replace_payout_tx_blockhash`
pub fn create_additional_replacable_disprove_script(
    combined_method_id_constant: [u8; COMBINED_METHOD_ID_LEN],
    deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
    g16_public_input_pk: PublicKey,
    payout_tx_blockhash_pk: PublicKey,
    latest_blockhash_pk: PublicKey,
    challenge_sending_watchtowers_pk: PublicKey,
    mut operator_challenge_ack_hashes: [ChallengeHashType; WATHCTOWER_COUNT],
) -> (Vec<u8>, usize) {
    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(
        &mut operator_challenge_ack_hashes,
    );
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
    ( script! {
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
        for x in bytes_to_nibbles(deposit_constant.to_vec()) {
            { x }
        }
        for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
            OP_FROMALTSTACK
        }
        { blake3_script(DEPOSIT_CONSTANT_LEN as u32 + BLAKE3_OUTPUT_LEN) }
        for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
            OP_TOALTSTACK
        }
        for x in bytes_to_nibbles(combined_method_id_constant.to_vec()) {
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
    }.compile().to_bytes(), PRECALCULATED_REPLACEMENT_INDEX)
}

/// Exactly the same as `create_additional_replacable_disprove_script`, but creates the script without expecting `payout_tx_blockhash_pk' as an argument, with a dummy value
pub fn create_additional_replacable_disprove_script_with_dummy(
    combined_method_id_constant: [u8; COMBINED_METHOD_ID_LEN],
    deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
    g16_public_input_pk: PublicKey,
    /* payout_tx_blockhash_pk: PublicKey, */
    latest_blockhash_pk: PublicKey,
    challenge_sending_watchtowers_pk: PublicKey,
    operator_challenge_ack_hashes: [ChallengeHashType; WATHCTOWER_COUNT],
) -> (Vec<u8>, usize) {
    create_additional_replacable_disprove_script(
        combined_method_id_constant,
        deposit_constant,
        g16_public_input_pk,
        generate_public_key(
            &Parameters::new_by_bit_length(PAYOUT_TX_BLOCKHASH_LEN as u32 * 8, 4),
            &vec![0u8; 0],
        ),
        latest_blockhash_pk,
        challenge_sending_watchtowers_pk,
        operator_challenge_ack_hashes,
    )
}

/// Returns the unlocking witness from given parameters for the given additional disprove script
///
/// This function constructs a witness from the provided signatures and preimages. \
/// Checks if the given parameters are make the given compiled additional disprove script spendable
/// If so, returns the witness that unlocks the script
///
/// ## Arguments
///
/// * `r_script` - The compiled additional script verifies the conditions for spending.  
/// * `g16_public_input_signature` - The witness signature for the Groth16 Public Input.  
/// * `payout_tx_blockhash_signature` - The witness signature for the Payout Transaction Blockhash.  
/// * `latest_blockhash_signature` - The witness signature for the Latest Blockhash.  
/// * `challenge_sending_watchtowers_signature` - The witness signature for challenge sending watchtowers; in this array, watchtowers are numerated in the order of the numbers and their least significant bit
/// * `operator_challenge_ack_preimages` - An array of optional (given if it is revealed) challenge acknowledgment preimages from watchtowers. If `None`, a random value is substituted.  
///
/// ## Returns
///
/// * `Some(Witness)` - If given parameters unlock the additional script
/// * `None` - If not
///
/// ## Notes
///
/// - MIGHT NOT BE SAFE, DUE TO THE REPLACEMENT INDEX CHANGING WITH WITNESS OPTIMIZATIONS, but seems fine for now
/// - To use `wots_api.rs` signatures, one can use the function wotsxxx.`signature_to_raw_witness`
pub fn validate_assertions_for_additional_script(
    replacable_script: Vec<u8>,
    g16_public_input_signature: Witness,
    payout_tx_blockhash_signature: Witness,
    latest_blockhash_signature: Witness,
    challenge_sending_watchtowers_signature: Witness,
    operator_challenge_ack_preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT], // None's are turned into random values
) -> Option<Witness> {
    let w = get_witness_with_signatures(
        g16_public_input_signature,
        payout_tx_blockhash_signature,
        latest_blockhash_signature,
        challenge_sending_watchtowers_signature,
        operator_challenge_ack_preimages,
    );
    if does_unlock(replacable_script, w.to_vec()) {
        Some(w)
    } else {
        None
    }
}

/// Replaces the Payout Transaction Blockhash Public Key for the given script
///
/// This function modifies the provided script by replacing the `checksig_verify` of the Payout Transaction Blockhash
///
/// ## Arguments
///
/// * `script` - Compiled additional disprove script
/// * `replacement_index` - The index within the script where the replacement should occur. Should be modified after the creation if the additional script is pushed after another script
/// * `payout_tx_blockhash_pk` - The replacement Public Key for Payout Transaction Blockhash
///
/// ## Returns
///
/// * `Vec<u8>` - The modified script with the updated payout transaction blockhash verification.  
///
/// ## Note
/// - MIGHT NOT BE SAFE, DUE TO THE REPLACEMENT INDEX CHANGING WITH WITNESS OPTIMIZATIONS, but seems fine for now
/// - To use `wots_api.rs` public keys, it is enough to cast them to vectors
pub fn replace_payout_tx_blockhash(
    mut script: Vec<u8>,
    replacement_index: usize,
    payout_tx_blockhash_pk: PublicKey,
) -> Vec<u8> {
    let replacement = WINTERNITZ_VERIFIER
        .checksig_verify(
            &Parameters::new_by_bit_length(
                (PAYOUT_TX_BLOCKHASH_LEN * 8) as u32,
                WINTERNITZ_BLOCK_LEN,
            ),
            &payout_tx_blockhash_pk,
        )
        .compile()
        .to_bytes();
    for i in 0..replacement.len() {
        script[replacement_index + i] = replacement[i];
    }
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash::blake3_u4::blake3_bitvm_version, signatures::winternitz::SecretKey};
    use bitcoin::hashes::{hash160, Hash};
    use rand::{thread_rng, Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    const WINTERNITZ_SECRET_KEY_LEN: usize = 40;

    /// Given the secret keys and the values of the variables, generated the signature witnesses for each one
    fn get_signatures(
        g16_public_input: [u8; G16_PUBLIC_INPUT_LEN],
        payout_tx_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN],
        latest_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN],
        challenge_sending_watchtowers: [u8; CHALLENGE_SENDING_WATCHTOWERS_LEN],
        g16_public_input_sk: SecretKey,
        payout_tx_blockhash_sk: SecretKey,
        latest_blockhash_sk: SecretKey,
        challenge_sending_watchtowers_sk: SecretKey,
    ) -> [Witness; 4] {
        [
            WINTERNITZ_VERIFIER.sign(
                &Parameters::new_by_bit_length(
                    (G16_PUBLIC_INPUT_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &g16_public_input_sk,
                &g16_public_input.to_vec(),
            ),
            WINTERNITZ_VERIFIER.sign(
                &Parameters::new_by_bit_length(
                    (PAYOUT_TX_BLOCKHASH_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &payout_tx_blockhash_sk,
                &payout_tx_blockhash.to_vec(),
            ),
            WINTERNITZ_VERIFIER.sign(
                &Parameters::new_by_bit_length(
                    (LATEST_BLOCKHASH_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &latest_blockhash_sk,
                &latest_blockhash.to_vec(),
            ),
            WINTERNITZ_VERIFIER.sign(
                &Parameters::new_by_bit_length(
                    (CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &challenge_sending_watchtowers_sk,
                &challenge_sending_watchtowers.to_vec(),
            ),
        ]
    }

    fn generate_winternitz_secret_key() -> SecretKey {
        let mut rng = thread_rng(); // might be unsafe, dicuss this (Probably won't be used in production anyway and will be just for tests)
        (0..WINTERNITZ_SECRET_KEY_LEN).map(|_| rng.gen()).collect()
    }

    fn concat_all<T: Clone>(lists: &[&[T]]) -> Vec<T> {
        lists.iter().flat_map(|list| list.iter().cloned()).collect()
    }

    /// This function changes with the `create_additional_replacable_disprove_script`and calculates the starting index of the payout_tx_blockhash to make it a constant value
    fn calculate_additional_replacable_disprove_script_replacement_index(
        _: [u8; COMBINED_METHOD_ID_LEN],
        _: [u8; DEPOSIT_CONSTANT_LEN],
        g16_public_input_pk: PublicKey,
        _: PublicKey,
        latest_blockhash_pk: PublicKey,
        challenge_sending_watchtowers_pk: PublicKey,
        mut operator_challenge_ack_hashes: [ChallengeHashType; WATHCTOWER_COUNT],
    ) -> usize {
        change_the_order_of_operator_challenge_acks_according_to_blake3_stack(
            &mut operator_challenge_ack_hashes,
        );

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
        challenge_sending_watchtowers_sk: SecretKey,
    }
    struct PublicData {
        combined_method_id_constant: [u8; COMBINED_METHOD_ID_LEN],
        deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
        g16_public_input_pk: PublicKey,
        payout_tx_blockhash_pk: PublicKey,
        latest_blockhash_pk: PublicKey,
        challenge_sending_watchtowers_pk: PublicKey,
        operator_challenge_ack_hashes: [ChallengeHashType; WATHCTOWER_COUNT],
    }

    fn random_signer_data(seed: u64) -> SignerData {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut s = SignerData {
            combined_method_id_constant: rng.gen::<[u8; COMBINED_METHOD_ID_LEN]>(),
            deposit_constant: rng.gen::<[u8; DEPOSIT_CONSTANT_LEN]>(),
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
        let x = blake3_bitvm_version(concat_all(&[
            &s.payout_tx_blockhash,
            &s.latest_blockhash,
            &s.challenge_sending_watchtowers,
        ]));
        let y = blake3_bitvm_version(concat_all(&[&s.deposit_constant, &x]));
        let f = blake3_bitvm_version(concat_all(&[&s.combined_method_id_constant, &y]));
        s.g16_public_input = f;
        s
    }

    fn get_public_data_from_signer(signer_data: &SignerData) -> PublicData {
        let mut p = PublicData {
            combined_method_id_constant: signer_data.combined_method_id_constant,
            deposit_constant: signer_data.deposit_constant,
            g16_public_input_pk: generate_public_key(
                &Parameters::new_by_bit_length(
                    (G16_PUBLIC_INPUT_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &signer_data.g16_public_input_sk,
            ),
            payout_tx_blockhash_pk: generate_public_key(
                &Parameters::new_by_bit_length(
                    (PAYOUT_TX_BLOCKHASH_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &signer_data.payout_tx_blockhash_sk,
            ),
            latest_blockhash_pk: generate_public_key(
                &Parameters::new_by_bit_length(
                    (LATEST_BLOCKHASH_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &signer_data.latest_blockhash_sk,
            ),
            challenge_sending_watchtowers_pk: generate_public_key(
                &Parameters::new_by_bit_length(
                    (CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &signer_data.challenge_sending_watchtowers_sk,
            ),
            operator_challenge_ack_hashes: [[0u8; 20]; WATHCTOWER_COUNT],
        };
        for i in 0..WATHCTOWER_COUNT {
            p.operator_challenge_ack_hashes[i] =
                *hash160::Hash::hash(&signer_data.operator_challenge_ack_preimages[i].to_vec())
                    .as_byte_array()
        }
        p
    }

    fn create_script_with_public_data(public_data: &PublicData) -> (Vec<u8>, usize) {
        create_additional_replacable_disprove_script(
            public_data.combined_method_id_constant,
            public_data.deposit_constant,
            public_data.g16_public_input_pk.clone(),
            public_data.payout_tx_blockhash_pk.clone(),
            public_data.latest_blockhash_pk.clone(),
            public_data.challenge_sending_watchtowers_pk.clone(),
            public_data.operator_challenge_ack_hashes,
        )
    }

    fn create_script_with_public_data_and_dummy_tx_blockhash_pk(
        public_data: &PublicData,
    ) -> (Vec<u8>, usize) {
        create_additional_replacable_disprove_script_with_dummy(
            public_data.combined_method_id_constant,
            public_data.deposit_constant,
            public_data.g16_public_input_pk.clone(),
            /* public_data.payout_tx_blockhash_pk.clone(), */
            public_data.latest_blockhash_pk.clone(),
            public_data.challenge_sending_watchtowers_pk.clone(),
            public_data.operator_challenge_ack_hashes,
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
            public_data.operator_challenge_ack_hashes,
        )
    }

    fn non_malicious_test_validate(script: Vec<u8>, signer_data: &SignerData) {
        let mut preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT] =
            std::array::from_fn(|_| None);
        for i in 0..WATHCTOWER_COUNT {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                preimages[i] = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            signer_data.g16_public_input,
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .try_into()
        .expect("impossible");
        assert!(
            validate_assertions_for_additional_script(
                script,
                g16_public_input_signature,
                payout_tx_blockhash_signature,
                latest_blockhash_signature,
                challenge_sending_watchtowers_signature,
                preimages
            )
            .is_some()
                == false
        );
    }

    fn malicious_revealed_preimage_validate(script: Vec<u8>, signer_data: &SignerData) {
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
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            signer_data.g16_public_input,
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .try_into()
        .expect("impossible");
        assert!(
            validate_assertions_for_additional_script(
                script,
                g16_public_input_signature,
                payout_tx_blockhash_signature,
                latest_blockhash_signature,
                challenge_sending_watchtowers_signature,
                preimages
            )
            .is_some()
                == true
        );
    }

    fn malicious_gibberish_g16_data_validate(script: Vec<u8>, signer_data: &SignerData) {
        let mut preimages: [Option<ChallengeHashType>; WATHCTOWER_COUNT] =
            std::array::from_fn(|_| None);
        for i in 0..WATHCTOWER_COUNT {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                preimages[i] = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            [0u8; G16_PUBLIC_INPUT_LEN],
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .try_into()
        .expect("impossible");
        assert!(
            validate_assertions_for_additional_script(
                script,
                g16_public_input_signature,
                payout_tx_blockhash_signature,
                latest_blockhash_signature,
                challenge_sending_watchtowers_signature,
                preimages
            )
            .is_some()
                == true
        );
    }

    #[test]
    fn test_calculating_public_input() {
        let signer_data = random_signer_data(4237);
        let s = script! {
            for x in bytes_to_nibbles(signer_data.payout_tx_blockhash.to_vec()) {
                { x }
            }
            for x in bytes_to_nibbles(signer_data.latest_blockhash.to_vec()) {
                { x }
            }
            for x in bytes_to_nibbles(signer_data.challenge_sending_watchtowers.to_vec()) {
                { x }
            }
            { blake3_script((PAYOUT_TX_BLOCKHASH_LEN + LATEST_BLOCKHASH_LEN + CHALLENGE_SENDING_WATCHTOWERS_LEN) as u32) }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_TOALTSTACK
            }
            for x in bytes_to_nibbles(signer_data.deposit_constant.to_vec()) {
                { x }
            }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_FROMALTSTACK
            }
            { blake3_script(DEPOSIT_CONSTANT_LEN as u32 + BLAKE3_OUTPUT_LEN) }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_TOALTSTACK
            }
            for x in bytes_to_nibbles(signer_data.combined_method_id_constant.to_vec()) {
                { x }
            }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_FROMALTSTACK
            }
            { blake3_script(COMBINED_METHOD_ID_LEN as u32 + BLAKE3_OUTPUT_LEN) }
            for x in bytes_to_nibbles(signer_data.g16_public_input.to_vec()) {
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
        execute_script(script! {
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
            let result = bytes_to_nibbles(blake3_bitvm_version(v.clone()).to_vec());
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
            let (s, _) = create_script_with_public_data(&public_data);
            non_malicious_test_validate(s.clone(), &signer_data);
            malicious_revealed_preimage_validate(s.clone(), &signer_data);
            malicious_gibberish_g16_data_validate(s.clone(), &signer_data);
        }
    }

    #[test]
    fn test_constant_replacement_index() {
        // This shouldn't change,  but just in case
        for seed in 0..100 {
            let signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            let actual = calculate_replacement_length_with_public_data(&public_data);
            assert!(
                actual == PRECALCULATED_REPLACEMENT_INDEX,
                "Precalculated length is wrong, it should be {actual}, (generated with {seed})"
            );
        }
    }

    #[test]
    fn tests_replacement() {
        for seed in 0..100 {
            let mut signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            let (mut s, replacement_index) =
                create_script_with_public_data_and_dummy_tx_blockhash_pk(&public_data);
            signer_data.payout_tx_blockhash_sk = generate_winternitz_secret_key();
            s = replace_payout_tx_blockhash(
                s,
                replacement_index,
                generate_public_key(
                    &Parameters::new_by_bit_length(
                        PAYOUT_TX_BLOCKHASH_LEN as u32 * 8,
                        WINTERNITZ_BLOCK_LEN,
                    ),
                    &signer_data.payout_tx_blockhash_sk,
                ),
            );
            non_malicious_test_validate(s.clone(), &signer_data);
            malicious_revealed_preimage_validate(s.clone(), &signer_data);
            malicious_gibberish_g16_data_validate(s.clone(), &signer_data);
        }
    }
}
