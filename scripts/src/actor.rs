use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::str::FromStr;

use crate::leaf::Leaf;

use super::opcodes::u160_std::U160;
use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::PublicKey;
use bitcoin::sighash::SighashCache;
use bitcoin::{Address, Opcode, Script};
use serde::{Deserialize, Serialize};
use std::error::Error;

const DELIMITER: char = '=';
const HASH_LEN: usize = 20;

pub type HashDigest = [u8; HASH_LEN];
pub type HashPreimage = [u8; HASH_LEN];

fn hash(bytes: &[u8]) -> HashDigest {
    ripemd160::Hash::hash(bytes).to_byte_array()
}

fn hash_id(identifier: &str, index: Option<u32>, value: u32) -> String {
    // TODO ensure there is no DELIMITER in identifier or index
    match index {
        None => format!("{identifier}{DELIMITER}{value}"),
        Some(index) => format!("{identifier}_{index}{DELIMITER}{value}"),
    }
}

fn to_commitment_id(identifier: &str, index: Option<u32>) -> String {
    match index {
        None => format!("{identifier}"),
        Some(index) => format!("{identifier}{index}"),
    }
}

fn parse_hash_id(hash_id: &str) -> (&str, u8) {
    let split_vec: Vec<&str> = hash_id.splitn(2, DELIMITER).collect();
    let value = u8::from_str(split_vec[1]).unwrap();
    (split_vec[0], value)
}

fn _preimage(secret: &[u8], hash_id: &str) -> HashDigest {
    hash(&[secret, hash_id.as_bytes()].concat())
}

fn _hash_lock(secret: &[u8], hash_id: &str) -> HashDigest {
    hash(&_preimage(secret, hash_id))
}

fn preimage(secret: &[u8], identifier: &str, index: Option<u32>, value: u32) -> HashDigest {
    _preimage(secret, &hash_id(identifier, index, value))
}

fn hash_lock(secret: &[u8], identifier: &str, index: Option<u32>, value: u32) -> HashDigest {
    hash(&_preimage(secret, &hash_id(identifier, index, value)))
}

pub trait Actor {
    fn script_pub_key(&self) -> Address {
        // TODO: Implement properly
        eprintln!("Hardcoded winner address!");
        Address::from_str("tb1p9evrt83ma6e2jjc9ajagl2h0kqtz5y05nutg2xt2tn9xjcm29t0slwpyc9")
            .unwrap()
            .require_network(bitcoin::Network::Testnet)
            .unwrap()
    }

    fn hashlock(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8>;

    fn preimage(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8>;

    fn pubkey(&self) -> Vec<u8>;
}

#[derive(Serialize)]
pub struct Player {
    // We can get the secret with keypair.secret_bytes()
    #[serde(skip_serializing)]
    keypair: Keypair,
    hashes: HashMap<String, HashDigest>,
}

impl Actor for Player {
    fn hashlock(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let hash = hash_lock(&self.keypair.secret_bytes(), identifier, index, value);
        self.hashes
            .insert(hash_id(identifier, index, value), hash.clone());
        hash.to_vec()
    }

    fn preimage(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let commitment_id = to_commitment_id(identifier, index);
        preimage(&self.keypair.secret_bytes(), identifier, index, value).to_vec()
    }

    fn pubkey(&self) -> Vec<u8> {
        self.keypair.public_key().serialize().to_vec()
    }
}

impl Player {
    pub fn new(secret: &str) -> Self {
        let secp = Secp256k1::new();
        Self {
            keypair: Keypair::from_seckey_str(&secp, secret).unwrap(),
            hashes: HashMap::new(),
        }
    }
}

pub struct EquivocationError {
    preimage_a: HashPreimage,
    preimage_b: HashPreimage,
}

impl Display for EquivocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Equivocation detected with preimages: {:?} and {:?}",
            self.preimage_a, self.preimage_b
        )
    }
}

impl Debug for EquivocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Write the debug representation using the provided formatter
        write!(
            f,
            "EquivocationError {{ preimage_a: {:?}, preimage_b: {:?} }}",
            self.preimage_a, self.preimage_b
        )
    }
}

impl Error for EquivocationError {}

pub struct Opponent {
    id_to_hash: HashMap<String, HashDigest>,
    hash_to_id: HashMap<HashDigest, String>,
    // Maps the entire identifier (including the value part) to the preimage
    preimages: HashMap<String, HashPreimage>,
    // Maps commitment_id returned by parse_hash_id to their preimages (so without the value part)
    commitments: HashMap<String, HashPreimage>,
    public_key: PublicKey,
    model: HashMap<String, u8>,
}

impl Actor for Opponent {
    fn hashlock(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let id = hash_id(identifier, index, value);
        self.id_to_hash
            .get(&id)
            .expect(&format!("Hash for {id} is not known"))
            .to_vec()
    }

    fn preimage(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let id = hash_id(identifier, index, value);
        self.preimages
            .get(&id)
            .expect(&format!("Preimage of {id} is not known"))
            .to_vec()
    }

    fn pubkey(&self) -> Vec<u8> {
        self.public_key.serialize().to_vec()
    }
}

impl Opponent {
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            id_to_hash: HashMap::new(),
            hash_to_id: HashMap::new(),
            preimages: HashMap::new(),
            commitments: HashMap::new(),
            model: HashMap::new(),
            public_key,
        }
    }
    // TODO: Implement witnessTx from js version
    // TODO: add a function to provide initial hashes (serde?)
    fn learn_preimage(&mut self, preimage: HashPreimage) -> Result<(), EquivocationError> {
        let hash = hash(&preimage);
        let id = {
            match self.hash_to_id.get(&hash) {
                Some(val) => val,
                None => return Ok(()),
            }
        };
        self.preimages.insert(id.to_string(), preimage);
        let (commitment_id, value) = parse_hash_id(id);

        // Check if we know some conflicting preimage
        match self.commitments.get(commitment_id) {
            Some(prev_preimage) => {
                if *prev_preimage != preimage {
                    // We can equivocate when we know two different preimages for the same commitment
                    return Err(EquivocationError {
                        preimage_a: *prev_preimage,
                        preimage_b: preimage,
                    });
                }
                // Nothing to do if we already learnt the exact same preimage
                return Ok(());
            }
            _ => {
                self.commitments.insert(commitment_id.to_string(), preimage);
                self.set(commitment_id.to_string(), value);
                Ok(())
            }
        }
    }

    pub fn set(&mut self, commitment_id: String, value: u8) {
        let prev_value = self.model.get(&commitment_id);

        // Check for equivocation
        if prev_value != None && *prev_value.unwrap() != value {
            panic!("Value of {commitment_id} is already set to a different value: {value} in model: {}", *prev_value.unwrap());
        }

        self.model.insert(commitment_id, value);
    }

    pub fn get_u160(&self, identifier: String) -> U160 {
        let mut result = U160::new();
        for i in 0..5 {
            let child_id = format!("{}_{}", identifier, 5 - i);
            let value = self.get_u32_endian(child_id);
            result[4 - i] = value;
        }
        result
    }

    pub fn get_u32(&self, identifier: String) -> u32 {
        let mut result: u32 = 0;
        for i in 0..4 {
            let child_id = format!("{}_byte{}", identifier, 3 - i);
            let value: u32 = self.get_u8(child_id).into();
            result <<= 8;
            result += value
        }
        result
    }

    // TODO: it seems like code smell that we need this method at all. Can we get rid of it?
    pub fn get_u32_endian(&self, identifier: String) -> u32 {
        let mut result: u32 = 0;
        for i in 0..4 {
            let child_id = format!("{}_byte{}", identifier, i);
            let value: u32 = self.get_u8(child_id).into();
            result <<= 8;
            result += value
        }
        result
    }

    pub fn get_u8(&self, identifier: String) -> u8 {
        let mut result = 0;
        for i in 0..4 {
            let child_id = format!("{}_{}", identifier, 3 - i);
            let value = self.get_u2(child_id);
            result <<= 2;
            result += value
        }
        result
    }

    pub fn get_u2(&self, identifier: String) -> u8 {
        *self.model.get(&identifier).unwrap()
    }

    pub fn get_u1(&self, identifier: String) -> u8 {
        *self.model.get(&identifier).unwrap()
    }
}
