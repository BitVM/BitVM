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
}

#[derive(Deserialize, Debug)]
pub struct TestVector {
    pub message: Message,
    #[serde(rename = "SHA-256")]
    pub sha256: String,
}

/// Read test vectors from JSON file
pub fn read_sha256_test_vectors() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let path = "src/hash/sha256_official_test_vectors.json";
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let (_ignored, vectors): (serde::de::IgnoredAny, Vec<TestVector>) =
        serde_json::from_reader(reader)?;

    let mut prepared_vectors = vec![];
    for vector in vectors.iter() {
        let input = vector
            .message
            .data
            .repeat(vector.message.count as usize)
            .as_bytes()
            .to_vec();
        if input.len() >= 128 {
            // The implementation only supports inputs up to 128 bytes
            continue;
        }
        let expected = hex::decode(&vector.sha256).unwrap();
        prepared_vectors.push((hex::encode(&input), hex::encode(&expected)));
    }

    Ok(prepared_vectors)
}

/// Generate random test cases for SHA256
pub fn random_test_cases() -> Vec<(String, String)> {
    (1..=127)
        .map(|len| {
            let random_bytes: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
            let input_hex = hex::encode(&random_bytes);
            let expected = reference_sha256(&random_bytes);
            let expected_hex = hex::encode(expected);
            (input_hex, expected_hex)
        })
        .collect()
}
