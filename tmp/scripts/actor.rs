#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]
use std::collections::HashMap;
use std::str::FromStr;


use crate::scripts::opcodes::{pushable, unroll};
use crate::scripts::opcodes::u32_std::{u32_fromaltstack, u32_toaltstack};
use bitcoin::opcodes::{OP_NOP, OP_TOALTSTACK};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

use crate::utils::u160::{
    u160,
    from_le_bytes as u160_from_bytes,
    to_bytes as u160_to_bytes,
};
use crate::utils::u1::u1;
use crate::utils::u2::u2;
use crate::utils::u256::{u256, from_bytes as u256_from_bytes};

use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::Address;

pub trait ID {
    
    // (^^;)

    fn ID(&self) -> u16;

}

pub enum ptr {
    u1(u16),
    u2(u16),
    u8(u16),
    u32(u16),
    u160(u8),
    u256(u8),
}
pub trait as_ptr<T> {
    fn addr(id: T) -> ptr;
}

fn hash(preimage: u160) -> u160 {
    u160_from_bytes(ripemd160::Hash::hash(&u160_to_bytes(preimage)).to_byte_array())
}

fn hash_2(preimage_0: u160, preimage_1: u160) -> u160 {
    let mut preimage = [0u8; 40];
    preimage[0..20].copy_from_slice(&u160_to_bytes(preimage_0));
    preimage[20..40].copy_from_slice(&u160_to_bytes(preimage_1));
    u160_from_bytes(ripemd160::Hash::hash(&preimage).to_byte_array())
}

fn preimage(seckey: u256, id: u16, value: u8) -> u160 {
    hash_2([seckey[0], seckey[1], seckey[2], seckey[3], seckey[4]], [seckey[5], seckey[6], seckey[7], id as u32, value as u32])
}

fn hashlock(secret: u256, id: u16, value: u8) -> u160 {
    hash(preimage(secret, id, value))
}

// The size of preimages in bytes
const PREIMAGE_SIZE: u32 = 20;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// Actor
pub trait Actor {
    fn script_pub_key(&self) -> Address {
        // TODO: Implement properly
        eprintln!("Hardcoded winner address!");
        Address::from_str("tb1p9evrt83ma6e2jjc9ajagl2h0kqtz5y05nutg2xt2tn9xjcm29t0slwpyc9").unwrap().require_network(bitcoin::Network::Testnet).unwrap()
    }

    /* Player-/Opponent- specific */
    
    fn hashlock(&mut self, id: u16, value: u8) -> u160;
    
    fn preimage(&mut self, id: u16, value: u8) -> u160;

    /* justice  go home */

    fn bit_state_justice(&mut self, id: &ptr) -> Script {
        match * id {
            ptr::u1(addr) => script! {
                OP_RIPEMD160
                { u160_to_bytes(self.hashlock(addr, 0b0)).to_vec() }
                OP_EQUALVERIFY
                OP_SWAP
                OP_RIPEMD160
                { u160_to_bytes(self.hashlock(addr, 0b1)).to_vec() }
                OP_EQUALVERIFY
            },
            // Undefined pointer types
            ptr::u2(_) => unimplemented!(),
            ptr::u8(_) => unimplemented!(),
            ptr::u32(_) => unimplemented!(),
            ptr::u160(_) => unimplemented!(),
            ptr::u256(_) => unimplemented!(),
        }
    }

    fn bit_state_justice_unlock(&mut self, id: &ptr) -> Script {
        match * id {
            ptr::u2(addr) =>  script! {
                { u160_to_bytes(self.preimage(addr, 0b1)).to_vec() }
                { u160_to_bytes(self.preimage(addr, 0b0)).to_vec() }
            },
            // Undefined pointer types
            ptr::u1(_) => unimplemented!(),
            ptr::u8(_) => unimplemented!(),
            ptr::u32(_) => unimplemented!(),
            ptr::u160(_) => unimplemented!(),
            ptr::u256(_) => unimplemented!(),
        }
    }
    
    /* commit wrapper */
    
    fn commit(&mut self, id: &ptr) -> Script {
        match * id {
            // Commit 1 bit
            ptr::u1(addr) => script! {
                // Validate size of the preimage
                OP_SIZE { PREIMAGE_SIZE } OP_EQUALVERIFY
                
                // Actual implementation
                OP_RIPEMD160
                OP_DUP
                { u160_to_bytes(self.hashlock(addr, 0b1)).to_vec() }
                OP_EQUAL
                OP_SWAP
                { u160_to_bytes(self.hashlock(addr, 0b0)).to_vec() }
                OP_EQUAL
                OP_BOOLOR
                OP_VERIFY
            },
            // Commit 2 bit
            ptr::u2(addr) => script! {
                // Valu2_idate size of the preimage
                OP_SIZE { PREIMAGE_SIZE } OP_EQUALVERIFY

                // Actual implementation
                OP_RIPEMD160

                OP_DUP
                { u160_to_bytes(self.hashlock(addr, 0b11)).to_vec() }
                OP_EQUAL

                OP_OVER
                { u160_to_bytes(self.hashlock(addr, 0b10)).to_vec() }
                OP_EQUAL
                OP_BOOLOR

                OP_OVER
                { u160_to_bytes(self.hashlock(addr, 0b01)).to_vec() }
                OP_EQUAL
                OP_BOOLOR

                OP_SWAP
                { u160_to_bytes(self.hashlock(addr, 0b00)).to_vec() }
                OP_EQUAL
                OP_BOOLOR
                OP_VERIFY
            },
            // Commit 8 bit
            ptr::u8(addr) => script! {
                { self.commit(&ptr::u2(addr << 2 | 0b11)) }
                { self.commit(&ptr::u2(addr << 2 | 0b10)) }
                { self.commit(&ptr::u2(addr << 2 | 0b01)) }
                { self.commit(&ptr::u2(addr << 2 | 0b00)) }
            },
            // Commit 32 bit
            ptr::u32(addr) => script! {
                { self.commit(&ptr::u8(addr << 2 | 0b00)) }
                { self.commit(&ptr::u8(addr << 2 | 0b01)) }
                { self.commit(&ptr::u8(addr << 2 | 0b10)) }
                { self.commit(&ptr::u8(addr << 2 | 0b11)) }
            },
            // Commit 160 bit
            ptr::u160(addr) => script! {
                { self.commit(&ptr::u32((addr as u16) << 3 | 4)) }
                { self.commit(&ptr::u32((addr as u16) << 3 | 3)) }
                { self.commit(&ptr::u32((addr as u16) << 3 | 2)) }
                { self.commit(&ptr::u32((addr as u16) << 3 | 1)) }
                { self.commit(&ptr::u32((addr as u16) << 3 | 0)) }
            },
            // Undefined pointer types
            ptr::u256(_) => unimplemented!(),
        }
    }
    
    /* push wrapper */

    fn push(&mut self, id: &ptr) -> Script {
        match * id {
            // Push 1 bit
            ptr::u1(addr) => script! {
                // Validate size of the preimage
                OP_SIZE { PREIMAGE_SIZE } OP_EQUALVERIFY
                
                // Actual implementation
                OP_RIPEMD160
                OP_DUP
                { u160_to_bytes(self.hashlock(addr, 0b1)).to_vec() }
                OP_EQUAL
                OP_DUP
                OP_ROT
                { u160_to_bytes(self.hashlock(addr, 0b0)).to_vec() }
                OP_EQUAL
                OP_BOOLOR
                OP_VERIFY
            },
            // Push 2 bit
            ptr::u2(addr) => script! {
                // Validate size of the preimage
                OP_SIZE { PREIMAGE_SIZE } OP_EQUALVERIFY
    
                // Actual implementation
                OP_RIPEMD160
                OP_DUP
                { u160_to_bytes(self.hashlock(addr, 0b11)).to_vec() }
                OP_EQUAL
                OP_IF
                    OP_DROP
                    3
                OP_ELSE
                    OP_DUP
                    { u160_to_bytes(self.hashlock(addr, 0b10)).to_vec() }
                    OP_EQUAL
                    OP_IF
                        OP_DROP
                        2
                    OP_ELSE
                        OP_DUP
                        { u160_to_bytes(self.hashlock(addr, 0b01)).to_vec() }
                        OP_EQUAL
                        OP_IF
                            OP_DROP
                            1
                        OP_ELSE
                            { u160_to_bytes(self.hashlock(addr, 0b00)).to_vec() }
                            OP_EQUALVERIFY
                            0
                        OP_ENDIF
                    OP_ENDIF
                OP_ENDIF
            },
            // Push 8 bit
            ptr::u8(addr) => script! {
                { unroll(4, |i| script!{
                    { self.push(&ptr::u2(addr | 3 - i as u16)) }
    
                    { if i == 0 { script! { OP_TOALTSTACK } } else {
                        script! {
                            OP_FROMALTSTACK
                            OP_DUP
                            OP_ADD
                            OP_DUP
                            OP_ADD
                            OP_ADD
                            { if i != 3 { OP_TOALTSTACK } else { OP_NOP } }
                        }
                    } }
                }) }
            }, // Now there's the u8 value on the stack,

            // Push 32 bit
            ptr::u32(addr) => script! {
                { self.push(&ptr::u8(addr | 0b00000)) }  OP_TOALTSTACK
                { self.push(&ptr::u8(addr | 0b01000)) }  OP_TOALTSTACK
                { self.push(&ptr::u8(addr | 0b10000)) }  OP_TOALTSTACK
                { self.push(&ptr::u8(addr | 0b11000)) }
                OP_FROMALTSTACK
                OP_FROMALTSTACK
                OP_FROMALTSTACK
            },
            // Push 160 bit
            ptr::u160(addr) => script! {
                { self.push(&ptr::u32(addr as u16 + 4)) }  u32_toaltstack
                { self.push(&ptr::u32(addr as u16 + 3)) }  u32_toaltstack
                { self.push(&ptr::u32(addr as u16 + 2)) }  u32_toaltstack
                { self.push(&ptr::u32(addr as u16 + 1)) }  u32_toaltstack
                { self.push(&ptr::u32(addr as u16 + 0)) }
        
                { unroll(4, |_| script! { u32_fromaltstack }) }
            },
            // Undefined pointer types
            ptr::u256(_) => unimplemented!(),
        }
    }

    fn push_bit(&mut self, id: &ptr) -> Script {
        match * id {
            ptr::u2(addr) => if (addr & 1) != 0 {
                script! {
                    OP_RIPEMD160
                    OP_DUP
                    { u160_to_bytes(self.hashlock(addr, 0b11)).to_vec() }
                    OP_EQUAL
                    OP_IF
                        OP_DROP
                        1
                    OP_ELSE
                        OP_DUP
                        { u160_to_bytes(self.hashlock(addr, 0b10)).to_vec() }
                        OP_EQUAL
                        OP_IF
                            OP_DROP
                            1
                        OP_ELSE
                            OP_DUP
                            { u160_to_bytes(self.hashlock(addr, 0b01)).to_vec() }
                            OP_EQUAL
                            OP_IF
                                OP_DROP
                                0
                            OP_ELSE
                            { u160_to_bytes(self.hashlock(addr, 0b00)).to_vec() }
                                OP_EQUALVERIFY
                                0
                            OP_ENDIF
                        OP_ENDIF
                    OP_ENDIF
                }
            } else {
                script! {
                    OP_RIPEMD160
                    OP_DUP
                    { u160_to_bytes(self.hashlock(addr, 0b11)).to_vec() }
                    OP_EQUAL
                    OP_IF
                        OP_DROP
                        1
                    OP_ELSE
                        OP_DUP
                        { u160_to_bytes(self.hashlock(addr, 0b10)).to_vec() }
                        OP_EQUAL
                        OP_IF
                            OP_DROP
                            0
                        OP_ELSE
                            OP_DUP
                            { u160_to_bytes(self.hashlock(addr, 0b01)).to_vec() }
                            OP_EQUAL
                            OP_IF
                                OP_DROP
                                1
                            OP_ELSE
                            { u160_to_bytes(self.hashlock(addr, 0b00)).to_vec() }
                                OP_EQUALVERIFY
                                0
                            OP_ENDIF
                        OP_ENDIF
                    OP_ENDIF
                }
            },
            ptr::u8(addr) => self.push_bit(&ptr::u2(addr << 2)),
            ptr::u32(addr) => self.push_bit(&ptr::u8(addr << 2)),
            // Undefined pointer types
            ptr::u1(_) => unimplemented!(),
            ptr::u160(_) => unimplemented!(),
            ptr::u256(_) => unimplemented!(),
        }
    }

    /* unlock wrapper */

    fn unlock<const N: usize>(&mut self, id: &ptr, value: [u32; N]) -> Script {
        match * id {
            // unlock 1 bit
            ptr::u1(addr) => script! {
                { u160_to_bytes(self.preimage(addr, value[0] as u8)).to_vec() }
            },
            // unlock 2 bit
            ptr::u2(addr) => script! {
                { u160_to_bytes(self.preimage(addr, value[0] as u8)).to_vec() }
            },
            // unlock 8 bit
            ptr::u8(addr) => script! {
                { u160_to_bytes(self.preimage(addr << 3 | 0b000, (value[0] as u8) >> 0 & 0b11)).to_vec() }
                { u160_to_bytes(self.preimage(addr << 3 | 0b010, (value[0] as u8) >> 2 & 0b11)).to_vec() }
                { u160_to_bytes(self.preimage(addr << 3 | 0b100, (value[0] as u8) >> 4 & 0b11)).to_vec() }
                { u160_to_bytes(self.preimage(addr << 3 | 0b110, (value[0] as u8) >> 6 & 0b11)).to_vec() }
            },
            // unlock 32 bit
            ptr::u32(addr) => script! {
                { self.unlock(&ptr::u8(addr << 2 | 0b11), [0xff & value[0] >> 24]) }
                { self.unlock(&ptr::u8(addr << 2 | 0b10), [0xff & value[0] >> 16]) }
                { self.unlock(&ptr::u8(addr << 2 | 0b01), [0xff & value[0] >> 8]) }
                { self.unlock(&ptr::u8(addr << 2 | 0b00), [0xff & value[0] >> 0]) }
            },
            // unlock 160 bit
            ptr::u160(addr) => script! {
                { self.unlock(&ptr::u32((addr as u16) << 3 + 0), [value[0]]) }
                { self.unlock(&ptr::u32((addr as u16) << 3 + 1), [value[1]]) }
                { self.unlock(&ptr::u32((addr as u16) << 3 + 2), [value[2]]) }
                { self.unlock(&ptr::u32((addr as u16) << 3 + 3), [value[3]]) }
                { self.unlock(&ptr::u32((addr as u16) << 3 + 4), [value[4]]) }
            },
            // Undefined pointer types
            ptr::u256(_) => todo!(),
        }
    }

    fn unlock_bit<const N: usize>(&mut self, id: &ptr, value: [u32; N]) -> Script {
        match * id {
            ptr::u8(addr) => self.unlock(&ptr::u2(addr << 1), [value[0] & 0b11]),
            ptr::u32(addr) => self.unlock_bit(&ptr::u8(addr << 2), [value[0] & 0xff]),
            // Undefined pointer types
            ptr::u1(_) => unimplemented!(),
            ptr::u2(_) => unimplemented!(),
            ptr::u160(_) => unimplemented!(),
            ptr::u256(_) => unimplemented!(),
        }
    }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// Player
pub struct Player {
    // We can get the secret with keypair.secret_bytes()
    keypair: u256,
    hashes: HashMap<(u16, u8), u160>,
}

impl Actor for Player {
    fn hashlock(&mut self, id: u16, value: u8) -> u160 {
        let u160 = hashlock(self.keypair, id, value);
        self.hashes.insert((id, value), u160);
        u160
    }

    // TODO: Implement Model struct
    fn preimage(&mut self, id: u16, value: u8) -> u160 {
        let commitment_id = id as u64 | (value as u64) << 32;
        // TODO set commitment_id in model
        //self.model...
        preimage(self.keypair, id, value)
    }
}

impl Player {
    pub fn new(secret: &str) -> Self {
        let secp = Secp256k1::new();
        Self {
            keypair: u256_from_bytes(Keypair::from_seckey_str(&secp, secret).unwrap().secret_bytes()),
            hashes: HashMap::new(),
        }
    }

    // TODO: Implement remaining functions from js version
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// Opponent
pub struct Opponent {
    id_to_hash: HashMap<(ptr, u8), u160>,
    hash_to_id: HashMap<u160, (ptr, u8)>,
    preimages: HashMap<(ptr, u8), u160>,
    commitments: HashMap<(ptr, u8), (ptr, u8)>,
    model: HashMap<ptr, u8>,
}

impl Actor for Opponent {
    fn hashlock(&mut self, id: ptr, value: u8) -> u160 {
        *self.id_to_hash.get(&(id, value)).expect(&format!("Hash for {id} is not known"))
    }

    // TODO: Implement Model struct
    fn preimage(&mut self, id: ptr, value: u8) -> u160 {
        *self.preimages.get(&(id, value)).expect(&format!("Preimage of {id} is not known"))
    }
}

impl Opponent {
    pub fn new() -> Self {
        Self {
            id_to_hash: HashMap::new(),
            hash_to_id: HashMap::new(),
            preimages: HashMap::new(),
            commitments: HashMap::new(),
            model: HashMap::new(),
        }
    }
    // TODO: Implement remaining functions from js version
    // TODO: add a function to provide initial hashes

    pub fn set(&mut self, id: ptr, value: u8) {
        let prev_value = self.model.get(&id);

        // Check for equivocation
        if prev_value != None && *prev_value.unwrap() != value {
            panic!("Value of {id} is already set to a different value: {value} in model: {}", *prev_value.unwrap());
        }

        self.model.insert(id, value);
    }

    pub fn get_u160(&self, id: ptr) -> u160 {
        let mut result: u160 = [0, 0, 0, 0, 0];
        for i in 0..5 {
            result[4 - i] = self.get_u32_endian(id | 5 - i as u16)
        }
        result
    }

    pub fn get_u32(&self, id: ptr) -> u32 {
        let mut result: u32 = 0;
        for i in 0..4 {
            result <<= 8;
            result += self.get_u8(id | 3 - i) as u32
        }
        result
    }

    // TODO: it seems like code smell that we need this method at all. Can we get rid of it?
    pub fn get_u32_endian(&self, id: ptr) -> u32 {
        let mut result: u32 = 0;
        for i in 0..4 {
            result <<= 8;
            result += self.get_u8(id | i) as u32
        }
        result
    }

    pub fn get_u8(&self, id: ptr) -> u8 {
        let mut result = 0;
        for i in 0..4 {
            result <<= 2;
            result += self.get_u2(id | 3 - i);
        }
        result
    }

    pub fn get_u2(&self, id: ptr) -> u2 {
        *self.model.get(&id).unwrap()
    }

    pub fn get_u1(&self, id: ptr) -> u1 {
        *self.model.get(&id).unwrap()
    }

}

#[cfg(test)]
pub mod tests {
    use crate::scripts::actor::ptr;
    use crate::scripts::actor::Actor;
    use crate::utils::u160::from_hex as u160_from_hex;

    use super::Player;

    pub fn test_player() -> Player {
        Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398")
    }

    #[test]
    fn test_preimage() {
        let mut player = test_player();
        let preimage = player.preimage(1337 | 3, 3); // TRACE_RESPONSE_0_5_byte0

        assert_eq!(preimage, u160_from_hex("5e891526241c4418a8206cf51a1a695547e74eb1")); // 7e85b1014de4146f534005c74f309220fe8a5a3c
    }

    // u32_state.rs

    use super::pushable;
    use bitcoin_script::bitcoin_script as script;

    use crate::scripts::opcodes::execute_script;

    #[test]
    fn test_bit() {
        test_u1(0);
        test_u1(1);
    }
    fn test_u1(test_value: u8) {
        let mut player = test_player();
        let test_identifier = ptr::u1(1337); // my_test_identifier
        let script = script! {
            // Unlocking script
            { player.unlock(&test_identifier, [test_value as u32]) }
            // Locking script
            { player.push(&test_identifier) }

            // Ensure the correct value was pushed onto the stack
            {test_value as u32} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }

    #[test]
    fn test_2_bits() {
        test_u2(0);
        test_u2(1);
        test_u2(2);
        test_u2(3);
    }
    fn test_u2(test_value: u8) {
        let mut player = test_player();
        let test_identifier = 1337; // my_test_identifier
        let script = script! {
            // Unlocking script
            { player.unlock(&ptr::u2(test_identifier), [test_value as u32]) }
            // Locking script
            { player.push(&ptr::u2(test_identifier)) }

            // Ensure the correct value was pushed onto the stack
            {test_value as u32} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }

    #[test]
    fn test_8_bits() {
        test_u8(0);
        test_u8(1);
        test_u8(3);
        test_u8(128);
        test_u8(255);
    }
    fn test_u8(test_value: u32) {
        let mut player = test_player();
        let test_identifier = 1337; // my_test_identifier
        let script = script! {
            // Unlocking script
            { player.unlock(&ptr::u8(test_identifier), [test_value]) }
            // Locking script
            { player.push(&ptr::u8(test_identifier)) }

            // Ensure the correct value was pushed onto the stack
            {test_value} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }

    #[test]
    fn test_u32() {
        let mut player = test_player();
        let test_identifier = 1337 << 8; // my_test_identifier
        let bit_index = 15;
        let value = 0b1000_0000_0000_0000;
        let script = script! {
            // Unlocking script
            { player.unlock_bit(&ptr::u32(test_identifier | bit_index), [value]) }
            // Locking script
            { player.push_bit(&ptr::u32(test_identifier | bit_index)) }

            // Ensure the correct value was pushed onto the stack
            {1} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }
}
