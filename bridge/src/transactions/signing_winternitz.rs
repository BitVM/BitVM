use bitcoin::Witness;
use serde::{Deserialize, Serialize};

use bitvm::signatures::{
    winternitz::{generate_public_key, Parameters, PublicKey, SecretKey},
    winternitz_hash::{sign_hash, WINTERNITZ_MESSAGE_VERIFIER},
};
use bitvm::treepp::{script, Script};

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzSecret {
    secret_key: SecretKey,
    parameters: Parameters,
}

// Bits per digit
pub const LOG_D: u32 = 4;

impl WinternitzSecret {
    /// Generate a random 160 bit number and return a hex encoded representation of it.
    pub fn new(message_size: usize) -> Self {
        let mut buffer = [0u8; 20];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::fill_bytes(&mut rng, &mut buffer);

        // TODO: Figure out the best parameters
        //let parameters = Parameters::new((BLAKE3_HASH_LENGTH * 2) as u32, 4);
        let parameters = Parameters::new((message_size * 2) as u32, LOG_D);
        WinternitzSecret {
            secret_key: hex::encode(buffer).into(),
            parameters,
        }
    }

    pub fn from_string(secret: &str, parameters: &Parameters) -> Self {
        WinternitzSecret {
            secret_key: hex::encode(secret.as_bytes()).into(),
            parameters: parameters.clone(),
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
            parameters: secret.parameters.clone(),
        }
    }
}

pub struct WinternitzSigningInputs<'a, 'b> {
    pub message: &'a [u8],
    pub signing_key: &'b WinternitzSecret,
}

pub fn generate_winternitz_hash_witness(signing_inputs: &WinternitzSigningInputs) -> Witness {
    sign_hash(
        &signing_inputs.signing_key.secret_key,
        signing_inputs.message,
    )
}

pub fn generate_winternitz_witness(signing_inputs: &WinternitzSigningInputs) -> Witness {
    WINTERNITZ_MESSAGE_VERIFIER.sign(
        &signing_inputs.signing_key.parameters,
        &signing_inputs.signing_key.secret_key,
        &signing_inputs.message.to_vec(),
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
    use bitcoin_script::script;

    use super::{WinternitzPublicKey, WinternitzSecret};
    use bitvm::{
        chunker::common::BLAKE3_HASH_LENGTH,
        execute_script,
        signatures::{utils::digits_to_number, winternitz::generate_public_key},
    };

    #[test]
    fn test_signing_winternitz_with_message_success() {
        let secret = WinternitzSecret::new(4);
        let public_key = WinternitzPublicKey::from(&secret);
        let start_time_block_number = 860033 as u32;

        let s = script! {
          { generate_winternitz_witness(
            &WinternitzSigningInputs {
              message: &start_time_block_number.to_le_bytes(),
              signing_key: &secret,
          },
          ).to_vec() }
          { winternitz_message_checksig(&public_key) }
          { digits_to_number::<{ 4 * 2}, { LOG_D as usize }>() }
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

        for i in 0..secret.parameters.total_digit_count() {
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
            public_key.parameters.total_digit_count() as usize
        );
        for i in 0..public_key.parameters.total_digit_count() {
            assert_eq!(
                public_key.public_key[i as usize].len(),
                20,
                "public_key[{}]: {:?}",
                i,
                public_key.public_key[i as usize]
            );
        }
    }
}
