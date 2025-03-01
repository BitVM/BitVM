use crate::hash::sha256::reference_sha256;
use serde::Deserialize;
use sha2::{Digest};
use std::error::Error;
use std::fs::File;
use std::io::BufReader;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub data: String,
    pub count: u64,
    pub note: String,
}

#[derive(Deserialize, Debug)]
pub struct TestVector {
    pub message: Message,
    #[serde(rename = "SHA-256")]
    pub sha256: String,
}

/// Read test vectors from JSON file
pub fn read_sha256_test_vectors() -> Result<Vec<TestVector>, Box<dyn Error>> {
    let path = "src/hash/sha256_official_test_vectors.json";
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let (_ignored, vectors): (serde::de::IgnoredAny, Vec<TestVector>) =
        serde_json::from_reader(reader)?;
    Ok(vectors)
}

/// Prepare test vector for use in testing. If the input is longer than 512 bytes, it will be hashed twice.
pub fn prepare_test_vector(data: &str, count: u64, expected_hex: &str) -> (String, String) {
    let mut input = data.repeat(count as usize).as_bytes().to_vec();
    let mut expected = hex::decode(expected_hex).unwrap();

    // Some of the test vectors are longer than 512 bytes, so we need to hash them twice
    let double_hashing_needed = input.len() > 512;
    if double_hashing_needed {
        input = reference_sha256(&input);
        expected = reference_sha256(&expected);
    }

    (hex::encode(&input), hex::encode(&expected))
}

/// Generate random test cases for SHA256
pub fn random_test_cases() -> Vec<(String, String)> {
    let test_lengths = [1, 8, 16, 32, 55, 56, 57, 63, 64, 65, 127, 128, 129];
    test_lengths
        .iter()
        .map(|&len| {
            let random_bytes: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
            let input_hex = hex::encode(&random_bytes);
            let expected = reference_sha256(&random_bytes);
            let expected_hex = hex::encode(expected);
            (input_hex, expected_hex)
        })
        .collect()
}
