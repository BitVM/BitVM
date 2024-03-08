use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::Address;

const DELIMITER: char = '=';
const HASH_LEN: usize = 20;

fn hash(bytes: &[u8]) -> [u8; 20] {
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

fn parse_hash_id(hash_id: &str) -> (&str, &str) {
    let split_vec: Vec<&str> = hash_id.splitn(2, DELIMITER).collect();
    (split_vec[0], split_vec[1])
}

fn _preimage(secret: &[u8], hash_id: &str) -> [u8; HASH_LEN] {
    println!("Secret: {:?}", hex::encode(secret));
    //hash(&[secret, hash_id.as_bytes()].concat())
    let secret_str = hex::encode(secret);
    println!("total_preimage: {:?}", format!("{secret_str}{hash_id}"));
    hash(format!("{secret_str}{hash_id}").as_bytes())
}

fn _hash_lock(secret: &[u8], hash_id: &str) -> [u8; HASH_LEN] {
    hash(&_preimage(secret, hash_id))
}

fn preimage(secret: &[u8], identifier: &str, index: Option<u32>, value: u32) -> [u8; HASH_LEN] {
    println!("Hash_id: {:?}", hash_id(identifier, index, value));
    _preimage(secret, &hash_id(identifier, index, value))
}

fn hash_lock(secret: &[u8], identifier: &str, index: Option<u32>, value: u32) -> [u8; HASH_LEN] {
    hash(&_preimage(secret, &hash_id(identifier, index, value)))
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
    // We can get the secret with keypair.secret_bytes()
    keypair: Keypair,
    hashes: HashMap<String, [u8; HASH_LEN]>,
    //model:
    opponent: &'a Opponent,
}

impl Actor for Player<'_> {
    fn hashlock(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let hash = hash_lock(&self.keypair.secret_bytes(), identifier, index, value);
        self.hashes
            .insert(hash_id(identifier, index, value), hash.clone());
        hash.to_vec()
    }

    // TODO: Implement Model struct
    fn preimage(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let commitment_id = to_commitment_id(identifier, index);
        // TODO set commitment_id in model
        //self.model...
        preimage(&self.keypair.secret_bytes(), identifier, index, value).to_vec()
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
    id_to_hash: HashMap<String, [u8; HASH_LEN]>,
    hash_to_id: HashMap<[u8; HASH_LEN], String>,
    preimages: HashMap<String, [u8; HASH_LEN]>,
    commitments: HashMap<String, String>,
}

impl Actor for Opponent {
    fn hashlock(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let id = hash_id(identifier, index, value);
        self.id_to_hash.get(&id).expect(&format!("Hash for {id} is not known")).to_vec()
    }

    // TODO: Implement Model struct
    fn preimage(&mut self, identifier: &str, index: Option<u32>, value: u32) -> Vec<u8> {
        let id = hash_id(identifier, index, value);
        self.preimages.get(&id).expect(&format!("Preimage of {id} is not known")).to_vec()
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
        let preimage = player.preimage("TRACE_RESPONSE_0_5_byte0", Some(3), 3);

        assert_eq!(
            hex::encode(preimage),
            "77d965854b38c56ed6d71990a199c3ed0621f6b4")
    }
}
