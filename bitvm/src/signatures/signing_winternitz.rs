use bitcoin::hex::DisplayHex;
use bitcoin::Witness;
use serde::{Deserialize, Serialize};

use crate::treepp::{script, Script};
use crate::{
    signatures::winternitz::{
        generate_public_key, BruteforceVerifier, ListpickVerifier, Parameters, PublicKey,
        SecretKey, ToBytesConverter, VoidConverter, Winternitz,
    },
    u32::u32_std::u32_compress,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzSecret {
    pub secret_key: SecretKey,
    parameters: Parameters,
}

/// Bits per digit.
pub const LOG_D: u32 = 4;

/// Winternitz verifier, returns the message in digits.
pub const WINTERNITZ_MESSAGE_VERIFIER: Winternitz<ListpickVerifier, VoidConverter> =
    Winternitz::new();

/// Winternitz verifier, returns the message in bytes.
pub const WINTERNITZ_VARIABLE_VERIFIER: Winternitz<ListpickVerifier, ToBytesConverter> =
    Winternitz::new();

/// Winternitz verifier for compact signature representation, returns the message in bytes.
pub const WINTERNITZ_MESSAGE_COMPACT_VERIFIER: Winternitz<BruteforceVerifier, VoidConverter> =
    Winternitz::new();

impl WinternitzSecret {
    /// Creates a secret key from a 160-bit random number,
    /// for signing messages of the given `message_len` (in bytes).
    pub fn new(message_len: usize) -> Self {
        let mut buffer = [0u8; 20];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::fill_bytes(&mut rng, &mut buffer);

        Self::from_bytes(message_len, buffer.to_lower_hex_string().into())
    }

    /// Creates a secret key from the given `secret_bytes`,
    /// for signing messages of the given `message_len` (in bytes).
    pub fn from_bytes(message_len: usize, secret_bytes: Vec<u8>) -> Self {
        let parameters = Parameters::new_by_bit_length(message_len as u32 * 8, LOG_D);
        Self {
            secret_key: secret_bytes,
            parameters,
        }
    }

    /// Creates a secret key from the given `secret` string.
    ///
    /// ## Warning
    ///
    /// The `secret` string is converted into ASCII bytes,
    /// which are in turn converted into lower hex ASCII bytes.
    #[deprecated(note = "It is safer to use WinternitzSecret::from_bytes")]
    pub fn from_string(secret: &str, parameters: &Parameters) -> Self {
        WinternitzSecret {
            secret_key: secret.as_bytes().to_lower_hex_string().into(),
            parameters: *parameters,
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzPublicKey {
    pub public_key: PublicKey,
    pub parameters: Parameters,
}

impl From<&WinternitzSecret> for WinternitzPublicKey {
    fn from(secret: &WinternitzSecret) -> Self {
        WinternitzPublicKey {
            public_key: generate_public_key(&secret.parameters, &secret.secret_key),
            parameters: secret.parameters,
        }
    }
}

pub struct WinternitzSigningInputs<'a, 'b> {
    pub message: &'a [u8],
    pub signing_key: &'b WinternitzSecret,
}

pub fn generate_winternitz_checksig_leave_hash(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    script! {
        {WINTERNITZ_VARIABLE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)}
        for i in 1..message_size {
            {i} OP_ROLL
        }
    }
}

pub fn generate_winternitz_checksig_leave_variable(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    assert_eq!(message_size % 4, 0, "message should be u32s");
    let u32s_size = message_size / 4;
    script! {
        {WINTERNITZ_VARIABLE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)}
        for _ in 0..u32s_size {
            {u32_compress()}
            OP_TOALTSTACK
        }
        for _ in 0..u32s_size {
            OP_FROMALTSTACK
        }
        for i in 1..u32s_size {
            {i} OP_ROLL
        }
    }
}

pub fn generate_winternitz_witness(signing_inputs: &WinternitzSigningInputs) -> Witness {
    WINTERNITZ_MESSAGE_VERIFIER.sign(
        &signing_inputs.signing_key.parameters,
        &signing_inputs.signing_key.secret_key,
        signing_inputs.message,
    )
}

pub fn winternitz_message_checksig(public_key: &WinternitzPublicKey) -> Script {
    WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)
}

pub fn winternitz_message_checksig_verify(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    script! {
        { WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key) }
        // TODO(LucidLuckylee): Instead of using OP_DROP use a Winternitz Verifier that consumes
        // the message
        for _ in 0..message_size {
            OP_DROP
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{WinternitzPublicKey, WinternitzSecret};
    use crate::{bn254::g1::G1Affine, execute_script, signatures::utils};
    use crate::{execute_script_with_inputs, ExecuteInfo};
    use ark_ff::UniformRand as _;
    use ark_std::test_rng;
    use bitcoin::script::read_scriptint;
    use bitcoin_script::script;
    use rand::{RngCore as _, SeedableRng as _};

    const BLAKE3_HASH_LENGTH: usize = 20;

    /// Extracts the items of the final stack after execution.
    fn extract_witness_from_stack(res: ExecuteInfo) -> Vec<Vec<u8>> {
        res.final_stack.0.iter_str().fold(vec![], |mut vector, x| {
            vector.push(x);
            vector
        })
    }

    /// Returns a Bitcoin script that compares two elements of length `n`.
    ///
    /// The script consumes its inputs.
    /// If the two elements are not equal, then the script fails immediately.
    fn equalverify(n: usize) -> Script {
        script!(
            for _ in 0..n {
                OP_TOALTSTACK
            }

            for i in 1..n {
                {i}
                OP_ROLL
            }

            for _ in 0..n {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
        )
    }

    /// Convert the raw Bitcoin witness into a byte vector.
    ///
    /// The witness encodes the signed message in digit form.
    fn u32_witness_to_bytes(witness: Vec<Vec<u8>>) -> Vec<u8> {
        let mut bytes = vec![];
        for element in witness.iter() {
            let limb = read_scriptint(element).unwrap() as u32;
            bytes.append(&mut limb.to_le_bytes().to_vec());
        }
        bytes
    }

    #[test]
    fn test_signing_winternitz_with_message_success() {
        let secret = WinternitzSecret::new(4);
        let public_key = WinternitzPublicKey::from(&secret);
        let start_time_block_number = 860033_u32;

        let s = script! {
          { generate_winternitz_witness(
            &WinternitzSigningInputs {
              message: &start_time_block_number.to_le_bytes(),
              signing_key: &secret,
          },
          ).to_vec() }
          { winternitz_message_checksig(&public_key) }
          { utils::digits_to_number::<{ 4 * 2}, { LOG_D as usize }>() }
          { start_time_block_number }
          OP_EQUAL
        };

        let result = execute_script(s);

        assert!(result.success);
    }

    #[test]
    fn test_generate_winternitz_secret_length() {
        // Uses an arbitrary message size of 1
        let secret = WinternitzSecret::new(1);
        assert_eq!(
            secret.secret_key.len(),
            40,
            "Secret: {0:?}",
            secret.secret_key
        );
    }

    #[test]
    fn test_winternitz_public_key_from_secret() {
        let secret = WinternitzSecret::new(BLAKE3_HASH_LENGTH);
        let public_key = WinternitzPublicKey::from(&secret);
        let reference_public_key = generate_public_key(&secret.parameters, &secret.secret_key);

        for i in 0..secret.parameters.total_digit_len() {
            assert_eq!(
                public_key.public_key[i as usize],
                reference_public_key[i as usize]
            );
        }
    }

    #[test]
    fn test_winternitz_public_key_from_secret_length() {
        let secret = WinternitzSecret::new(BLAKE3_HASH_LENGTH);
        let public_key = WinternitzPublicKey::from(&secret);

        assert_eq!(
            public_key.public_key.len(),
            public_key.parameters.total_digit_len() as usize
        );
        for i in 0..public_key.parameters.total_digit_len() {
            assert_eq!(
                public_key.public_key[i as usize].len(),
                20,
                "public_key[{}]: {:?}",
                i,
                public_key.public_key[i as usize]
            );
        }
    }

    #[test]
    fn test_recover_g1_point_on_stack() {
        let g1_point_bytes_length = 9 * 4 * 2; // two fq element
        let secret = WinternitzSecret::new(g1_point_bytes_length);
        let public_key = WinternitzPublicKey::from(&secret);

        // random g1 point
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let random_g1_point = ark_bn254::G1Affine::rand(&mut rng);

        let res = execute_script(script! {
            {G1Affine::push(random_g1_point)}
        });
        let g1_to_bytes = u32_witness_to_bytes(extract_witness_from_stack(res));
        println!("g1_to_bytes: {:?}", g1_to_bytes);

        let witness = generate_winternitz_witness(&WinternitzSigningInputs {
            message: &g1_to_bytes,
            signing_key: &secret,
        });

        let s = script! {
            { generate_winternitz_checksig_leave_variable(&public_key, g1_point_bytes_length) }
            {G1Affine::push(random_g1_point)}
            {equalverify(g1_point_bytes_length / 4)}
            OP_TRUE
        };

        let result = execute_script_with_inputs(s, witness.to_vec());

        println!("result: {:?}", result);
        assert!(result.success);
    }
}
