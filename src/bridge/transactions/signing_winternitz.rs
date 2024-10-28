use serde::{Deserialize, Serialize};

use crate::signatures::winternitz::{public_key_for_digit, PublicKey, N};

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
pub struct WinternitzPublicKey(Vec<Vec<u8>>);

impl From<&WinternitzSecret> for WinternitzPublicKey {
    fn from(secret: &WinternitzSecret) -> Self {
        let mut public_key_vec = Vec::new();
        for i in 0..N {
            public_key_vec.push(public_key_for_digit(&secret.0, i).to_vec());
        }

        WinternitzPublicKey(public_key_vec)
    }
}

impl From<&WinternitzPublicKey> for PublicKey {
    fn from(pubkey: &WinternitzPublicKey) -> Self {
        let mut public_key_array = [[0u8; 20]; N as usize];
        for i in 0..N {
            public_key_array[i as usize] = pubkey.0[i as usize]
                .clone()
                .try_into()
                .expect("A Winternitz public key for a digit must be 20 bytes long");
        }

        public_key_array
    }
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
        let public_key = WinternitzPublicKey::from(&secret);
        let reference_public_key = generate_public_key((&secret).into());

        for i in 0..N {
            assert_eq!(public_key.0[i as usize], reference_public_key[i as usize]);
        }
    }

    #[test]
    fn test_winternitz_public_key_from_secret_length() {
        let secret = WinternitzSecret::new();
        let public_key = WinternitzPublicKey::from(&secret);

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
