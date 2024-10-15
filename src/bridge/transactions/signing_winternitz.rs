use crate::signatures::winternitz::{public_key_for_digit, PublicKey, N};

pub type WinternitzSecret = String;
pub type WinternitzPublicKey = Vec<Vec<u8>>;

/// Generate a random 160 bit number and return a hex encoded representation of it.
pub fn generate_winternitz_secret() -> WinternitzSecret {
    let mut buffer = [0u8; 20];
    let mut rng = rand::rngs::OsRng::default();
    rand::RngCore::fill_bytes(&mut rng, &mut buffer);

    hex::encode(buffer)
}

pub fn winternitz_public_key_from_secret(secret: &WinternitzSecret) -> WinternitzPublicKey {
    let mut public_key_vec = Vec::new();
    for i in 0..N {
        public_key_vec.push(public_key_for_digit(&secret, i).to_vec());
    }

    public_key_vec
}

pub fn convert_winternitz_public_key(pubkey: &WinternitzPublicKey) -> PublicKey {
    let mut public_key_array = [[0u8; 20]; N as usize];
    for i in 0..N {
        public_key_array[i as usize] = pubkey[i as usize]
            .clone()
            .try_into()
            .expect("A Winternitz public key for a digit must be 20 bytes long");
    }

    public_key_array
}

#[cfg(test)]
mod tests {
    use crate::signatures::winternitz::generate_public_key;

    use super::*;

    #[test]
    fn test_generate_winternitz_secret_length() {
        let secret = generate_winternitz_secret();
        assert_eq!(secret.len(), 40, "Secret: {secret}");
    }

    #[test]
    fn test_winternitz_public_key_from_secret() {
        let secret = generate_winternitz_secret();
        let public_key = winternitz_public_key_from_secret(&secret);
        let reference_public_key = generate_public_key(secret.as_str());

        for i in 0..N {
            assert_eq!(public_key[i as usize], reference_public_key[i as usize]);
        }
    }

    #[test]
    fn test_winternitz_public_key_from_secret_length() {
        let secret = generate_winternitz_secret();
        let public_key = winternitz_public_key_from_secret(&secret);

        assert_eq!(public_key.len(), N as usize);
        for i in 0..N {
            assert_eq!(
                public_key[i as usize].len(),
                20,
                "public_key[{}]: {:?}",
                i,
                public_key[i as usize]
            );
        }
    }

    #[test]
    fn test_convert_winternitz_public_key() {
        let secret = generate_winternitz_secret();
        let public_key = winternitz_public_key_from_secret(&secret);
        let converted_public_key = convert_winternitz_public_key(&public_key);

        assert_eq!(converted_public_key.len(), N as usize);
        for i in 0..N {
            assert_eq!(public_key[i as usize], converted_public_key[i as usize]);
        }
    }
}
