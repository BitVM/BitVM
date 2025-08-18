use bitcoin::hex::DisplayHex;
use bitcoin_script::Script;

use crate::signatures::utils::bitcoin_representation;
use crate::signatures::winternitz;
use crate::signatures::winternitz::{
    BruteforceVerifier, Converter, ListpickVerifier, Parameters, VoidConverter, Winternitz,
};

/// Secret key for Winternitz signatures.
///
/// The same key type is used for all message lengths.
pub type WinternitzSecret = winternitz::SecretKey;

/// Public key for some Winternitz signature verification algorithm.
///
/// The key has to be converted into the right length before it can be used
/// in any algorithm. The conversion might fail.
pub type GenericWinternitzPublicKey = winternitz::PublicKey;

/// Bundles a message with a secret key for signing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WinternitzSigningInputs<'a, 'b, WOTS: Wots + ?Sized> {
    pub message: &'a WOTS::Message,
    pub signing_key: &'b WinternitzSecret,
}

/// Number of bits per digit.
///
/// We hardcode the base to be 16. Therefore, there are 4 bits.
pub const LOG2_BASE: u32 = 4;

/// High-level functionality for working with Winternitz signatures.
///
/// Signatures contain the signature of each digit as well as the digit itself.
///
/// ## See
///
/// [`CompactWots`]
pub trait Wots {
    type Converter: Converter;
    type PublicKey: AsRef<[[u8; 20]]> + TryFrom<Vec<[u8; 20]>, Error: std::fmt::Debug>;
    type Message: AsRef<[u8]> + TryFrom<Vec<u8>, Error: std::fmt::Debug>;
    type Signature: AsRef<[[u8; 21]]> + TryFrom<Vec<[u8; 21]>, Error: std::fmt::Debug>;

    const ALGORITHM: Winternitz<ListpickVerifier, Self::Converter> = Winternitz::new();
    const MSG_BYTE_LEN: u32;
    const PARAMETERS: Parameters = Parameters::new_by_bit_length(Self::MSG_BYTE_LEN * 8, LOG2_BASE);
    const TOTAL_DIGIT_LEN: u32 = Self::PARAMETERS.total_digit_len();

    /// Generates a random secret key.
    fn generate_secret_key() -> WinternitzSecret {
        let mut buffer = [0u8; 20];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::fill_bytes(&mut rng, &mut buffer);
        Vec::from(buffer)
    }

    /// Creates a secret key from the given `secret` string.
    ///
    /// ## Warning
    ///
    /// For backwards compatibility, the original conversion function is used.
    /// The `secret` string is converted into ASCII bytes,
    /// which are in turn converted into lower hex ASCII bytes.
    #[deprecated(note = "It is safer to use Vec<u8> directly")]
    fn secret_from_str(secret: &str) -> WinternitzSecret {
        secret.as_bytes().to_lower_hex_string().into_bytes()
    }

    /// Generates a public key for the given `secret_key`.
    fn generate_public_key(secret_key: &WinternitzSecret) -> Self::PublicKey {
        let pubkey_vec = winternitz::generate_public_key(&Self::PARAMETERS, secret_key);
        match Self::PublicKey::try_from(pubkey_vec) {
            Ok(public_key) => public_key,
            _ => unreachable!(),
        }
    }

    /// Generates a signature for the given `secret_key` and `message`,
    /// in form of a Bitcoin witness.
    fn sign_to_raw_witness(
        secret_key: &WinternitzSecret,
        message: &Self::Message,
    ) -> bitcoin::Witness {
        let witness = Self::ALGORITHM.sign(&Self::PARAMETERS, secret_key, message.as_ref());
        debug_assert_eq!(witness.len(), 2 * Self::TOTAL_DIGIT_LEN as usize);
        witness
    }

    /// Generates a signature for the given `secret_key` and `message`.
    fn sign(secret_key: &WinternitzSecret, message: &Self::Message) -> Self::Signature {
        let witness = Self::sign_to_raw_witness(secret_key, message);
        Self::raw_witness_to_signature(&witness)
    }

    /// Generates a signature for the given `inputs`.
    fn sign_inputs(inputs: WinternitzSigningInputs<Self>) -> Self::Signature {
        let witness = Self::sign_inputs_to_raw_witness(inputs);
        Self::raw_witness_to_signature(&witness)
    }

    /// Generates a signature for the given `inputs` in form of a Bitcoin witness.
    fn sign_inputs_to_raw_witness(inputs: WinternitzSigningInputs<Self>) -> bitcoin::Witness {
        Self::sign_to_raw_witness(inputs.signing_key, inputs.message)
    }

    /// Parses the given bitcoin `witness` as a Winternitz signature.
    ///
    /// The `witness` must be in the format that is returned by [`Wots::sign`].
    ///
    /// ## Panics
    ///
    /// This method panics if the `witness` is ill-formatted.
    fn raw_witness_to_signature(witness: &bitcoin::Witness) -> Self::Signature {
        assert_eq!(witness.len(), 2 * Self::TOTAL_DIGIT_LEN as usize);
        let mut digit_signatures: Vec<[u8; 21]> =
            Vec::with_capacity(Self::TOTAL_DIGIT_LEN as usize);

        for i in (0..witness.len()).step_by(2) {
            assert_eq!(
                witness[i].len(),
                20,
                "the digit signature should be constant 20 bytes"
            );
            assert!(
                witness[i + 1].len() <= 1,
                "the digit should be a compressed byte, which is the empty vector for digit = 0"
            );

            let mut digit_signature: [u8; 21] = [0; 21];
            digit_signature[0..20].copy_from_slice(&witness[i]);
            if witness[i + 1].is_empty() {
                digit_signature[20] = 0;
            } else {
                digit_signature[20..21].copy_from_slice(&witness[i + 1]);
            }
            digit_signatures.push(digit_signature);
        }

        debug_assert_eq!(digit_signatures.len(), Self::TOTAL_DIGIT_LEN as usize);
        match Self::Signature::try_from(digit_signatures) {
            Ok(signature) => signature,
            _ => unreachable!(),
        }
    }

    /// Encodes the given Winternitz `signature` as a bitcoin witness.
    fn signature_to_raw_witness(signature: &Self::Signature) -> bitcoin::Witness {
        let mut witness = bitcoin::Witness::new();

        for digit_signature in signature.as_ref().iter() {
            witness.push(&digit_signature[0..20]);
            witness.push(bitcoin_representation(u32::from(digit_signature[20])));
        }

        witness
    }

    /// Extracts the message bytes from the given Winternitz `signature`.
    fn signature_to_message(signature: &Self::Signature) -> Self::Message {
        let digits: Vec<u8> = signature
            .as_ref()
            .iter()
            .map(|digit_sig| digit_sig[20])
            // Remove the checksum at the end
            .take(Self::PARAMETERS.message_digit_len as usize)
            // Un-reverse digits
            .rev()
            .collect();
        // Convert little endian digits [LSD, MSD] to big endian [MSD, LSD].
        // "LSD" means "least significant digit" and
        // "MSD" means "most significant digit".
        let bytes = digits
            .chunks(2)
            .map(|bn| (bn[1] << 4) + bn[0])
            .collect::<Vec<u8>>();
        debug_assert_eq!(bytes.len(), Self::MSG_BYTE_LEN as usize);
        Self::Message::try_from(bytes).unwrap()
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The converted message is on the stack top.
    /// The checksum is consumed.
    fn checksig_verify(public_key: &Self::PublicKey) -> Script {
        Self::ALGORITHM.checksig_verify(&Self::PARAMETERS, &public_key.as_ref().to_vec())
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature (in the verifier's format) is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The message and checksum are consumed.
    fn checksig_verify_and_clear_stack(public_key: &Self::PublicKey) -> Script {
        Self::ALGORITHM
            .checksig_verify_and_clear_stack(&Self::PARAMETERS, &public_key.as_ref().to_vec())
    }
}

/// High-level functionality for working with compact Winternitz signatures.
///
/// Compact signatures contain the signature of each digit, but not the digit itself.
///
/// ## See
///
/// [`Wots`]
pub trait CompactWots: Wots {
    type CompactSignature: AsRef<[[u8; 20]]> + TryFrom<Vec<[u8; 20]>, Error: std::fmt::Debug>;
    const COMPACT_ALGORITHM: Winternitz<BruteforceVerifier, Self::Converter> = Winternitz::new();

    /// Generates a compact signature for the given `secret_key` and `message`,
    /// in form of a Bitcoin witness.
    fn compact_sign_to_raw_witness(
        secret_key: &WinternitzSecret,
        message: &Self::Message,
    ) -> bitcoin::Witness {
        let witness = Self::COMPACT_ALGORITHM.sign(&Self::PARAMETERS, secret_key, message.as_ref());
        debug_assert_eq!(witness.len(), Self::TOTAL_DIGIT_LEN as usize);
        witness
    }

    /// Generates a compact signature for the given `secret_key` and `message`.
    fn compact_sign(
        secret_key: &WinternitzSecret,
        message: &Self::Message,
    ) -> Self::CompactSignature {
        let witness = Self::compact_sign_to_raw_witness(secret_key, message);
        Self::compact_raw_witness_to_signature(&witness)
    }

    /// Parses the given bitcoin `witness` as a Winternitz signature.
    ///
    /// The `witness` must be in the format that is returned by [`CompactWots::compact_sign`].
    ///
    /// ## Panics
    ///
    /// This method panics if the `witness` is ill-formatted.
    fn compact_raw_witness_to_signature(witness: &bitcoin::Witness) -> Self::CompactSignature {
        assert_eq!(witness.len(), Self::TOTAL_DIGIT_LEN as usize);
        let mut digit_signatures: Vec<[u8; 20]> =
            Vec::with_capacity(Self::TOTAL_DIGIT_LEN as usize);

        for i in 0..witness.len() {
            assert_eq!(
                witness[i].len(),
                20,
                "the digit signature should be constant 20 bytes"
            );

            let digit_signature: [u8; 20] = witness[i].try_into().unwrap();
            digit_signatures.push(digit_signature);
        }

        debug_assert_eq!(digit_signatures.len(), Self::TOTAL_DIGIT_LEN as usize);
        match Self::CompactSignature::try_from(digit_signatures) {
            Ok(signature) => signature,
            _ => unreachable!(),
        }
    }

    /// Encodes the given Winternitz `signature` as a bitcoin witness.
    fn compact_signature_to_raw_witness(signature: &Self::CompactSignature) -> bitcoin::Witness {
        let mut witness = bitcoin::Witness::new();

        for digit_signature in signature.as_ref().iter() {
            witness.push(digit_signature);
        }

        witness
    }

    /// Converts the given Winternitz `signature` into the compact format.
    fn signature_to_compact_signature(signature: &Self::Signature) -> Self::CompactSignature {
        let digit_signatures: Vec<[u8; 20]> = signature
            .as_ref()
            .iter()
            .map(|digit_sig| std::array::from_fn(|i| digit_sig[i]))
            .collect();
        Self::CompactSignature::try_from(digit_signatures).unwrap()
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The converted message is on the stack top.
    /// The checksum is consumed.
    fn compact_checksig_verify(public_key: &Self::PublicKey) -> Script {
        Self::COMPACT_ALGORITHM.checksig_verify(&Self::PARAMETERS, &public_key.as_ref().to_vec())
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature (in the verifier's format) is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The message and checksum are consumed.
    fn compact_checksig_verify_and_clear_stack(public_key: &Self::PublicKey) -> Script {
        Self::COMPACT_ALGORITHM
            .checksig_verify_and_clear_stack(&Self::PARAMETERS, &public_key.as_ref().to_vec())
    }
}

/// Winternitz signatures for 4-byte messages.
pub struct Wots4;
/// Winternitz signatures for 16-byte messages.
pub struct Wots16;
/// Winternitz signatures for 32-byte messages.
pub struct Wots32;
/// Winternitz signatures for 64-byte messages.
pub struct Wots64;
/// Winternitz signatures for 80-byte messages.
pub struct Wots80;

/// Implements the [`Wots`] and [`CompactWots`] traits for the given type.
///
/// ## Parameters
///
/// - `name`: name of the implementing type
/// - `msg_byte_len`: message length in bytes
/// - `converter`: a type that implements the [`Converter`] trait
#[macro_export]
macro_rules! impl_wots {
    ($name:ident, $msg_byte_len:expr, $converter:ty) => {
        impl Wots for $name {
            /// Converts the message on the stack after signature verification has finished.
            type Converter = $converter;
            /// The public key type for this Winternitz signing algorithm.
            type PublicKey = [[u8; 20]; Self::TOTAL_DIGIT_LEN as usize];
            /// The message type for this Winternitz signing algorithm.
            ///
            /// All messages have the same fixed length.
            type Message = [u8; Self::MSG_BYTE_LEN as usize];
            /// The signature type of this Winternitz signing algorithm.
            type Signature = [[u8; 21]; Self::TOTAL_DIGIT_LEN as usize];

            /// The number of bytes in a message.
            const MSG_BYTE_LEN: u32 = $msg_byte_len;
        }

        impl CompactWots for $name {
            /// The compact signature type of this Winternitz signing algorithm.
            type CompactSignature = [[u8; 20]; Self::TOTAL_DIGIT_LEN as usize];
        }
    };
}

impl_wots!(Wots4, 4, VoidConverter);
impl_wots!(Wots16, 16, VoidConverter);
impl_wots!(Wots32, 32, VoidConverter);
impl_wots!(Wots64, 64, VoidConverter);
impl_wots!(Wots80, 80, VoidConverter);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::winternitz::ToBytesConverter;
    use crate::u32::u32_std::u32_compress;
    use crate::{bn254::g1::G1Affine, execute_script, signatures::utils};
    use crate::{execute_script_with_inputs, ExecuteInfo};

    use std::convert::TryFrom;
    use std::fs::File;
    use std::io;
    use std::io::Read;

    #[expect(unused_imports)]
    use std::io::Write; // needed to generate test vectors (see below)

    use ark_ff::UniformRand as _;
    use ark_std::test_rng;
    use bitcoin::hex::{DisplayHex, FromHex};
    use bitcoin::script::read_scriptint;
    use bitcoin_script::script;
    use rand::{RngCore as _, SeedableRng as _};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_json;

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
        let secret = Wots4::generate_secret_key();
        let public_key = Wots4::generate_public_key(&secret);
        let start_time_block_number = 860033_u32;
        let message = start_time_block_number.to_le_bytes();

        let s = script! {
          { Wots4::sign_to_raw_witness(&secret, &message) }
          { Wots4::checksig_verify(&public_key) }
          { utils::digits_to_number::<{ 4 * 2}, { LOG2_BASE as usize }>() }
          { start_time_block_number }
          OP_EQUAL
        };

        let result = execute_script(s);

        assert!(result.success);
    }

    #[test]
    fn test_generate_winternitz_secret_length() {
        let secret = Wots4::generate_secret_key();
        assert_eq!(secret.len(), 20, "Secret: {0:?}", secret);
    }

    #[test]
    fn test_winternitz_public_key_from_secret_length() {
        let secret = Wots16::generate_secret_key();
        let public_key = Wots16::generate_public_key(&secret);

        assert_eq!(
            public_key.len(),
            Wots16::PARAMETERS.total_digit_len() as usize,
        );

        for i in 0..Wots16::PARAMETERS.total_digit_len() {
            assert_eq!(
                public_key[i as usize].len(),
                20,
                "public_key[{}]: {:?}",
                i,
                public_key[i as usize]
            );
        }
    }

    /// Winternitz signatures for 72-byte messages.
    ///
    /// This is a custom implementation for the G1 unit test.
    /// The checksig script converts the message to bytes.
    struct Wots72;

    impl_wots!(Wots72, 72, ToBytesConverter);

    #[test]
    fn test_recover_g1_point_on_stack() {
        const G1_POINT_BYTES_LENGTH: usize = 9 * 4 * 2; // two fq elements
        assert_eq!(G1_POINT_BYTES_LENGTH, 72);

        let secret = Wots72::generate_secret_key();
        let public_key = Wots72::generate_public_key(&secret);

        // random g1 point
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let random_g1_point = ark_bn254::G1Affine::rand(&mut rng);

        let res = execute_script(script! {
            {G1Affine::push(random_g1_point)}
        });
        let g1_to_bytes = u32_witness_to_bytes(extract_witness_from_stack(res));
        let g1_to_bytes: [u8; G1_POINT_BYTES_LENGTH] = g1_to_bytes.try_into().unwrap();

        println!("g1_to_bytes: {:?}", g1_to_bytes.as_hex());

        let witness = Wots72::sign_to_raw_witness(&secret, &g1_to_bytes);
        let u32s_size = G1_POINT_BYTES_LENGTH / 4;

        let s = script! {
            { Wots72::checksig_verify(&public_key) }
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
            { G1Affine::push(random_g1_point) }
            { equalverify(G1_POINT_BYTES_LENGTH / 4) }
            OP_TRUE
        };

        let result = execute_script_with_inputs(s, witness.to_vec());

        println!("result: {:?}", result);
        assert!(result.success);
    }

    #[test]
    fn secret_key_from_string() {
        assert_eq!(
            Wots16::secret_from_str("password").to_lower_hex_string(),
            "37303631373337333737366637323634"
        );
    }

    /// Test vector for WOTS.
    ///
    /// A message is signed with the WOTS implementation for the given length,
    /// using the provided secret key.
    ///
    /// The test vector records the expected signature, ranging over all possible formats:
    /// - non-compact signature
    /// - non-compact Bitcoin witness
    /// - compact signature
    /// - compact Bitcoin witness
    ///
    /// The expected Bitcoin witness data is included to ensure compliance
    /// with Bitcoin consensus rules and to track any changes to the witness
    /// in future versions of BitVM.
    #[derive(Serialize, Deserialize)]
    struct TestVector {
        #[serde(
            serialize_with = "serialize_bytes_hex",
            deserialize_with = "deserialize_bytes_hex"
        )]
        message: Vec<u8>,
        #[serde(
            serialize_with = "serialize_bytes_hex",
            deserialize_with = "deserialize_bytes_hex",
            rename = "secretKey"
        )]
        secret_key: Vec<u8>,
        #[serde(
            serialize_with = "serialize_byte_matrix_hex",
            deserialize_with = "deserialize_byte_matrix_hex",
            rename = "publicKey"
        )]
        public_key: Vec<Vec<u8>>,
        #[serde(
            serialize_with = "serialize_byte_matrix_hex",
            deserialize_with = "deserialize_byte_matrix_hex"
        )]
        witness: Vec<Vec<u8>>,
        #[serde(
            serialize_with = "serialize_byte_matrix_hex",
            deserialize_with = "deserialize_byte_matrix_hex"
        )]
        signature: Vec<Vec<u8>>,
        #[serde(
            serialize_with = "serialize_byte_matrix_hex",
            deserialize_with = "deserialize_byte_matrix_hex"
        )]
        compact_witness: Vec<Vec<u8>>,
        #[serde(
            serialize_with = "serialize_byte_matrix_hex",
            deserialize_with = "deserialize_byte_matrix_hex"
        )]
        compact_signature: Vec<Vec<u8>>,
    }

    fn serialize_bytes_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&bytes.to_lower_hex_string())
    }

    fn deserialize_bytes_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Vec::<u8>::from_hex(&s).map_err(serde::de::Error::custom)
    }

    fn serialize_byte_matrix_hex<S>(
        byte_matrix: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(byte_matrix.len()))?;
        for entry in byte_matrix {
            seq.serialize_element(&entry.to_lower_hex_string())?;
        }
        seq.end()
    }

    fn deserialize_byte_matrix_hex<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec_s: Vec<String> = Vec::deserialize(deserializer)?;
        vec_s
            .into_iter()
            .map(|s| Vec::<u8>::from_hex(&s).map_err(serde::de::Error::custom))
            .collect()
    }

    /// Creates a test vector for the given `WOTS` implementation.
    ///
    /// The test vector stores the output of signing the given `message`
    /// with the given `secret_key`.
    #[allow(dead_code)]
    fn create_test_vector<WOTS: Wots + CompactWots>(
        message: &WOTS::Message,
        secret_key: WinternitzSecret,
    ) -> TestVector {
        let public_key: Vec<Vec<u8>> = WOTS::generate_public_key(&secret_key)
            .as_ref()
            .iter()
            .map(|entry| entry.to_vec())
            .collect();
        let witness: Vec<Vec<u8>> = WOTS::sign_to_raw_witness(&secret_key, message)
            .iter()
            .map(|entry| entry.to_vec())
            .collect();
        let signature: Vec<Vec<u8>> = WOTS::sign(&secret_key, message)
            .as_ref()
            .iter()
            .map(|entry| entry.to_vec())
            .collect();
        let compact_witness: Vec<Vec<u8>> = WOTS::compact_sign_to_raw_witness(&secret_key, message)
            .iter()
            .map(|entry| entry.to_vec())
            .collect();
        let compact_signature: Vec<Vec<u8>> = WOTS::compact_sign(&secret_key, message)
            .as_ref()
            .iter()
            .map(|entry| entry.to_vec())
            .collect();

        TestVector {
            message: message.as_ref().to_vec(),
            secret_key,
            public_key,
            witness,
            signature,
            compact_witness,
            compact_signature,
        }
    }

    /// Creates randomized test vectors for the given `WOTS` implementation.
    #[allow(dead_code)]
    fn generate_test_vectors_for<WOTS: Wots + CompactWots, const MSG_BYTE_LEN: usize>(
    ) -> Vec<TestVector> {
        // Working around limitations of the Rust compiler
        debug_assert_eq!(WOTS::MSG_BYTE_LEN as usize, MSG_BYTE_LEN);

        let mut test_vectors = Vec::new();

        // Sign all-zeroes message
        let message = WOTS::Message::try_from(vec![0x00; MSG_BYTE_LEN]).unwrap();
        let secret_key = WOTS::generate_secret_key();
        test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

        // Sign all-zeroes message where signature has trailing zero byte
        'grind_trailing_zero: loop {
            let secret_key = WOTS::generate_secret_key();
            let witness = WOTS::sign_to_raw_witness(&secret_key, &message);
            for entry in &witness {
                if entry.last().map(|&byte| byte == 0).unwrap_or(false) {
                    test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));
                    break 'grind_trailing_zero;
                }
            }
        }

        // Sign all-zeroes message where signature has leading zero byte
        'grind_leading_zero: loop {
            let secret_key = WOTS::generate_secret_key();
            let witness = WOTS::sign_to_raw_witness(&secret_key, &message);
            for entry in &witness {
                if entry.first().map(|&byte| byte == 0).unwrap_or(false) {
                    test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));
                    break 'grind_leading_zero;
                }
            }
        }

        // Sign all-ones message
        let message = WOTS::Message::try_from(vec![0xff; MSG_BYTE_LEN]).unwrap();
        let secret_key = WOTS::generate_secret_key();
        test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

        // Sign random message
        let message: Vec<u8> = (0..MSG_BYTE_LEN).map(|_| rand::random()).collect();
        let message = WOTS::Message::try_from(message).unwrap();
        let secret_key = WOTS::generate_secret_key();
        test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

        // Sign half-zeroes, half-ones message
        let message: Vec<u8> = (0..MSG_BYTE_LEN / 2)
            .map(|_| 0x00u8)
            .chain((0..MSG_BYTE_LEN / 2).map(|_| 0xffu8))
            .collect();
        let message = WOTS::Message::try_from(message).unwrap();
        let secret_key = WOTS::generate_secret_key();
        test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

        // Sign third-zeroes, third-ones, third-random message
        let message: Vec<u8> = (0..MSG_BYTE_LEN / 3)
            .map(|_| 0x00u8)
            .chain((0..MSG_BYTE_LEN / 3).map(|_| 0xffu8))
            .chain((0..MSG_BYTE_LEN - MSG_BYTE_LEN / 3 * 2).map(|_| rand::random()))
            .collect();
        let message = WOTS::Message::try_from(message).unwrap();
        let secret_key = WOTS::generate_secret_key();
        test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

        test_vectors
    }

    // Uncomment and run this code to generate fresh test vectors:
    // cargo test generate_and_save_test_vectors
    /*
    #[test]
    fn generate_and_save_test_vectors() -> io::Result<()> {
        let mut test_vectors = Vec::new();
        test_vectors.extend(generate_test_vectors_for::<Wots4, 4>());
        test_vectors.extend(generate_test_vectors_for::<Wots16, 16>());
        test_vectors.extend(generate_test_vectors_for::<Wots32, 32>());

        let json = serde_json::to_string_pretty(&test_vectors)?;

        let file = File::create("wots-test-vectors.json")?;
        let mut writer = io::BufWriter::new(file);
        writer.write_all(json.as_bytes())?;
        writer.flush()?;

        Ok(())
    }
    */

    fn load_test_vectors() -> io::Result<Vec<TestVector>> {
        let mut file = File::open("wots-test-vectors.json")?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let test_vectors: Vec<TestVector> = serde_json::from_str(&contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(test_vectors)
    }

    /// Run the test vector and verify the expected outputs.
    fn verify_test_vector<WOTS: Wots + CompactWots>(test_vector: TestVector) {
        let message =
            WOTS::Message::try_from(test_vector.message.clone()).expect("Invalid message bytes");
        let computed_public_key = WOTS::generate_public_key(&test_vector.secret_key);
        assert_eq!(
            &test_vector.public_key,
            computed_public_key.as_ref(),
            "public key mismatch"
        );
        let computed_signature = WOTS::sign(&test_vector.secret_key, &message);
        assert_eq!(
            &test_vector.signature,
            computed_signature.as_ref(),
            "signature mismatch"
        );
        let computed_witness = WOTS::sign_to_raw_witness(&test_vector.secret_key, &message);
        assert_eq!(
            &test_vector.witness,
            &computed_witness.to_vec(),
            "witness mismatch"
        );
        assert_eq!(
            WOTS::raw_witness_to_signature(&computed_witness).as_ref(),
            computed_signature.as_ref(),
            "bad conversion witness -> signature"
        );
        assert_eq!(
            &WOTS::signature_to_raw_witness(&computed_signature),
            &computed_witness,
            "bad conversion signature -> witness"
        );
        let script = script! {
            { computed_witness }
            { WOTS::checksig_verify_and_clear_stack(&computed_public_key) }
            OP_TRUE
        };
        assert!(execute_script(script).success);

        let computed_compact_signature = WOTS::compact_sign(&test_vector.secret_key, &message);
        assert_eq!(
            &test_vector.compact_signature,
            computed_compact_signature.as_ref(),
            "compact signature mismatch"
        );
        let computed_compact_witness =
            WOTS::compact_sign_to_raw_witness(&test_vector.secret_key, &message);
        assert_eq!(
            &test_vector.compact_witness,
            &computed_compact_witness.to_vec(),
            "compact witness mismatch"
        );
        assert_eq!(
            WOTS::compact_raw_witness_to_signature(&computed_compact_witness).as_ref(),
            computed_compact_signature.as_ref(),
            "bad conversion compact witness -> compact signature"
        );
        assert_eq!(
            &WOTS::compact_signature_to_raw_witness(&computed_compact_signature),
            &computed_compact_witness,
            "bad conversion compact signature -> compact witness"
        );
        let compact_script = script! {
            { computed_compact_witness }
            { WOTS::compact_checksig_verify_and_clear_stack(&computed_public_key) }
            OP_TRUE
        };
        assert!(execute_script(compact_script).success);
    }

    /*
    #[test]
    fn verify_test_vectors() -> io::Result<()> {
        let test_vectors = load_test_vectors()?;

        for test_vector in test_vectors {
            match test_vector.message.len() {
                4 => verify_test_vector::<Wots4>(test_vector),
                16 => verify_test_vector::<Wots16>(test_vector),
                32 => verify_test_vector::<Wots32>(test_vector),
                _ => panic!("Unexpected message length: {}", test_vector.message.len()),
            }
        }

        Ok(())
    }
    */
}
