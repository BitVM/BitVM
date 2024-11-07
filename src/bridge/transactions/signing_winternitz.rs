use serde::{Deserialize, Serialize};

use crate::signatures::{
    winternitz::{public_key_for_digit, N},
    winternitz_compact::{sign, PublicKeyCompact, HASH160_LENGTH_IN_BYTES, N_32},
    winternitz_hash::sign_hash,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzSecret(String);

impl From<String> for WinternitzSecret {
    fn from(secret: String) -> Self { WinternitzSecret(secret) }
}

impl<'a> From<&'a WinternitzSecret> for &'a str {
    fn from(secret: &'a WinternitzSecret) -> Self { &secret.0 }
}

impl WinternitzSecret {
    /// Generate a random 160 bit number and return a hex encoded representation of it.
    pub fn new() -> Self {
        let mut buffer = [0u8; 20];
        let mut rng = rand::rngs::OsRng::default();
        rand::RngCore::fill_bytes(&mut rng, &mut buffer);

        WinternitzSecret(hex::encode(buffer))
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzPublicKey<const TOTAL_DIGIT_COUNT: usize>(Vec<Vec<u8>>);

impl<const TOTAL_DIGIT_COUNT: usize> From<&WinternitzSecret>
    for WinternitzPublicKey<TOTAL_DIGIT_COUNT>
{
    fn from(secret: &WinternitzSecret) -> Self {
        let mut public_key_vec = Vec::new();
        for i in 0..TOTAL_DIGIT_COUNT {
            public_key_vec.push(public_key_for_digit(&secret.0, i.try_into().unwrap()).to_vec());
        }

        WinternitzPublicKey(public_key_vec)
    }
}

impl<const TOTAL_DIGIT_COUNT: usize> From<&WinternitzPublicKey<TOTAL_DIGIT_COUNT>>
    for PublicKeyCompact<TOTAL_DIGIT_COUNT>
{
    fn from(pubkey: &WinternitzPublicKey<TOTAL_DIGIT_COUNT>) -> Self {
        let mut public_key_array = [[0u8; HASH160_LENGTH_IN_BYTES]; TOTAL_DIGIT_COUNT];
        for i in 0..TOTAL_DIGIT_COUNT {
            public_key_array[i] = pubkey.0[i].clone().try_into().expect(
                format!("A Winternitz public key for a digit must be {HASH160_LENGTH_IN_BYTES} bytes long").as_str(),
            );
        }

        public_key_array
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum WinternitzPublicKeyVariant {
    Standard(WinternitzPublicKey<N>),
    CompactN32(WinternitzPublicKey<N_32>),
}

impl WinternitzPublicKeyVariant {
    pub fn get_standard_variant_ref(&self) -> &WinternitzPublicKey<N> {
        match self {
            WinternitzPublicKeyVariant::Standard(ref pubkey) => pubkey,
            _ => panic!("This enum variant is not a standard Winternitz public key."),
        }
    }

    pub fn get_compact_n32_variant_ref(&self) -> &WinternitzPublicKey<N_32> {
        match self {
            WinternitzPublicKeyVariant::CompactN32(ref pubkey) => pubkey,
            _ => panic!("This enum variant is not a compact N_32 Winternitz public key."),
        }
    }
}

pub struct WinternitzSingingInputs<'a, 'b> {
    pub message_digits: &'a [u8],
    pub signing_key: &'b WinternitzSecret,
}

pub fn generate_winternitz_witness(signing_inputs: &WinternitzSingingInputs) -> Vec<Vec<u8>> {
    let mut unlock_data: Vec<Vec<u8>> = Vec::new();

    // Push the message
    for byte in signing_inputs.message_digits.iter().rev() {
        unlock_data.push(vec![*byte]);
    }

    // Push the signature
    let winternitz_signatures = sign_hash(
        signing_inputs.signing_key.into(),
        &signing_inputs.message_digits,
    );
    for winternitz_signature in winternitz_signatures.into_iter() {
        unlock_data.push(winternitz_signature.hash_bytes);
        unlock_data.push(vec![winternitz_signature.message_digit]);
    }

    unlock_data
}

pub fn generate_compact_winternitz_witness<
    const DIGIT_COUNT: usize,
    const CHECKSUM_DIGIT_COUNT: usize,
>(
    signing_inputs: &WinternitzSingingInputs,
) -> Vec<Vec<u8>> {
    sign::<DIGIT_COUNT, CHECKSUM_DIGIT_COUNT>(
        signing_inputs.signing_key.into(),
        signing_inputs.message_digits.try_into().unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::{WinternitzPublicKey, WinternitzSecret};
    use crate::signatures::winternitz::{generate_public_key, PublicKey, N};

    #[test]
    fn test_generate_winternitz_secret_length() {
        let secret = WinternitzSecret::new();
        assert_eq!(secret.0.len(), 40, "Secret: {0}", secret.0);
    }

    #[test]
    fn test_winternitz_public_key_from_secret() {
        let secret = WinternitzSecret::new();
        let public_key = WinternitzPublicKey::<N>::from(&secret);
        let reference_public_key = generate_public_key((&secret).into());

        for i in 0..N {
            assert_eq!(public_key.0[i as usize], reference_public_key[i as usize]);
        }
    }

    #[test]
    fn test_winternitz_public_key_from_secret_length() {
        let secret = WinternitzSecret::new();
        let public_key = WinternitzPublicKey::<N>::from(&secret);

        assert_eq!(public_key.0.len(), N as usize);
        for i in 0..N {
            assert_eq!(
                public_key.0[i as usize].len(),
                20,
                "public_key[{}]: {:?}",
                i,
                public_key.0[i as usize]
            );
        }
    }

    #[test]
    fn test_convert_winternitz_public_key() {
        let secret = WinternitzSecret::new();
        let public_key = WinternitzPublicKey::from(&secret);
        let converted_public_key = PublicKey::from(&public_key);

        assert_eq!(converted_public_key.len(), N as usize);
        for i in 0..N {
            assert_eq!(public_key.0[i as usize], converted_public_key[i as usize]);
        }
    }
}
