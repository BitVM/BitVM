use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::Address;

const DELIMITER: char = '=';

fn hash(bytes: &[u8]) -> [u8; 20] {
    ripemd160::Hash::hash(bytes).to_byte_array()
}

fn hash_id(identifier: &str, index: Option<u32>, value: u32) -> String {
    // TODO ensure there is no DELIMITER in identifier or index
    match index {
        None => format!("{identifier}{value}"),
        Some(index) => format!("{identifier}{index}{value}"),
    }
}

fn to_commitment_id(identifier: &str, index: Option<u32>) -> String {
    match index {
        None => format!("{identifier}"),
        Some(index) => format!("{identifier}{index}"),
    }
}

fn parse_hash_id(hash_id: &str) -> (&str, &str) {
    let split_vec: Vec<&str> = hash_id.splitn(2, DELIMITER).collect();
    (split_vec[0], split_vec[1])
}

// TODO: Refactor these. We can store [u8; 20] instead of String in the respective Player/Opponent
// Hashmaps
fn _preimage(secret: &[u8], hash_id: &str) -> [u8; 20] {
    hash(&[secret, hash_id.as_bytes()].concat())
}

fn _hash_lock(secret: &[u8], hash_id: &str) -> String {
    hex::encode(hash(&_preimage(secret, hash_id)))
}

fn preimage(secret: &[u8], identifier: &str, index: Option<u32>, value: u32) -> String {
    hex::encode(_preimage(secret, &hash_id(identifier, index, value)))
}

fn hash_lock(secret: &[u8], identifier: &str, index: Option<u32>, value: u32) -> String {
    hex::encode(hash(&_preimage(secret, &hash_id(identifier, index, value))))
}

pub trait Actor {
    fn script_pub_key() -> Address {
        // TODO: Implement properly
        eprintln!("Hardcoded winner address!");
        Address::from_str("tb1p9evrt83ma6e2jjc9ajagl2h0kqtz5y05nutg2xt2tn9xjcm29t0slwpyc9")
            .unwrap()
            .require_network(bitcoin::Network::Testnet)
            .unwrap()
    }
    fn hashlock(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8>;
    fn preimage(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8>;
}

pub struct Player<'a> {
    // TODO: Might have to write a helper function to get the secret
    // https://docs.rs/bitcoin/latest/bitcoin/key/struct.Keypair.html
    keypair: Keypair,
    hashes: HashMap<String, String>,
    //model:
    opponent: &'a Opponent,
}

impl Actor for Player<'_> {
    fn hashlock(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let hash = hash_lock(&self.keypair.secret_bytes(), identifier, index, value);
        self.hashes
            .insert(hash_id(identifier, index, value), hash.clone());
        hex::decode(hash).unwrap()
    }

    // TODO: Implement Model struct
    fn preimage(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let commitment_id = to_commitment_id(identifier, index);
        // TODO set commitment_id in model
        //self.model...
        hex::decode(preimage(&self.keypair.secret_bytes(), identifier, index, value)).unwrap()
    }
}

impl<'a> Player<'a> {
    pub fn new(secret: &str, opponent: &'a Opponent) -> Self {
        let secp = Secp256k1::new();
        Self {
            keypair: Keypair::from_seckey_str(&secp, secret).unwrap(),
            hashes: HashMap::new(),
            opponent,
        }
    }

    // TODO: Implement remaining functions from js version
}

pub struct Opponent {
    id_to_hash: HashMap<String, String>,
    hash_to_id: HashMap<String, String>,
    preimages: HashMap<String, String>,
    commitments: HashMap<String, String>,
}

impl Actor for Opponent {
    fn hashlock(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let id = hash_id(identifier, index, value);
        hex::decode(self.id_to_hash.get(&id).expect(&format!("Hash for {id} is not known"))).unwrap()
    }

    // TODO: Implement Model struct
    fn preimage(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let id = hash_id(identifier, index, value);
        hex::decode(self.preimages.get(&id).expect(&format!("Preimage of {id} is not known"))).unwrap()
    }
}
impl Opponent {
    pub fn new() -> Self {
        Self {
            id_to_hash: HashMap::new(),
            hash_to_id: HashMap::new(),
            preimages: HashMap::new(),
            commitments: HashMap::new(),
        }
    }
    // TODO: Implement remaining functions from js version
    // TODO add a function to provide initial hashes
}

// TODO put these into the model for bitvm
//impl VickyActor for VickyPlayer{}
//impl VickyActor for VickyOpponent{}
//trait VickyActor {
//
//}
//
//trait PaulActor {
//
//
//}

#[cfg(test)]
mod tests {
    use crate::actor::Actor;

    use super::{Opponent, Player};

    #[test]
    fn test_preimage() {
        let opponent = Opponent::new();
        let mut player = Player::new(
            &String::from("d898098e09898a0980989b980809809809f09809884324874302975287524398"),
            &opponent,
        );
        let hashlock = player.hashlock("TEST", Some(1), 0);

        assert_eq!(
            hashlock,
            hex::decode("8ff5a38b89720ad46caa2828b728795395a0a257").unwrap())
    }
}
