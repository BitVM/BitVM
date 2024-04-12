//REF:https://github.com/DrPeterVanNostrand/sha256.git
extern crate bit_vec;
extern crate byteorder;

use bit_vec::BitVec;
use byteorder::{BigEndian, ByteOrder};

const BLOCK_LENGTH_BITS: usize = 512;
const BLOCK_LENGTH_BYTES: usize = BLOCK_LENGTH_BITS / 8;
const N_FREE_BITS_IN_LAST_BLOCK: usize = 447;

static K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

static INIT_HASH_VALUES: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

fn choice(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }

fn majority(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }

fn sigma_lower_0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3) }

fn sigma_lower_1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }

fn sigma_upper_0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }

fn sigma_upper_1(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }

fn pad_msg(msg_bytes: &[u8]) -> Vec<u8> {
    let l = msg_bytes.len() * 8;
    let r = l % BLOCK_LENGTH_BITS;

    let n_zeros = if r < N_FREE_BITS_IN_LAST_BLOCK {
        N_FREE_BITS_IN_LAST_BLOCK - r
    } else {
        BLOCK_LENGTH_BITS - r + N_FREE_BITS_IN_LAST_BLOCK
    };

    let mut padded = BitVec::from_bytes(msg_bytes);
    padded.push(true);
    padded.grow(n_zeros, false);

    let msg_len_as_bitvec = {
        let mut bytes = [0u8; 8];
        BigEndian::write_u64(&mut bytes, l as u64);
        BitVec::from_bytes(&bytes)
    };

    padded.extend(msg_len_as_bitvec.iter());
    padded.to_bytes()
}

/// Splits the padded message into a vector blocks, where each block is 16
/// words long (ie. 512 bits).
fn blocks(msg: &[u8]) -> Vec<[u32; 16]> {
    let mut blocks = vec![];
    let mut block = [0u32; 16];

    for block_bytes in msg.chunks(BLOCK_LENGTH_BYTES) {
        for (i, word_bytes) in block_bytes.chunks(4).enumerate() {
            block[i] = BigEndian::read_u32(word_bytes);
        }
        blocks.push(block);
    }

    blocks
}

pub fn sha256(msg: &[u8]) -> Vec<u8> {
    let padded = pad_msg(msg);
    let mut digest = [0u32; 8];
    digest.copy_from_slice(&INIT_HASH_VALUES);
    let mut msg_sched = [0u32; 64];

    let mut a: u32;
    let mut b: u32;
    let mut c: u32;
    let mut d: u32;
    let mut e: u32;
    let mut f: u32;
    let mut g: u32;
    let mut h: u32;

    for block in blocks(&padded) {
        for i in 0..16 {
            msg_sched[i] = block[i];
        }

        for i in 16..64 {
            msg_sched[i] = sigma_lower_1(msg_sched[i - 2])
                .wrapping_add(msg_sched[i - 7])
                .wrapping_add(sigma_lower_0(msg_sched[i - 15]))
                .wrapping_add(msg_sched[i - 16]);
        }

        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];
        f = digest[5];
        g = digest[6];
        h = digest[7];

        for i in 0..64 {
            let tmp1 = h
                .wrapping_add(sigma_upper_1(e))
                .wrapping_add(choice(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(msg_sched[i]);

            let tmp2 = sigma_upper_0(a).wrapping_add(majority(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(tmp1);
            d = c;
            c = b;
            b = a;
            a = tmp1.wrapping_add(tmp2);
        }

        digest[0] = digest[0].wrapping_add(a);
        digest[1] = digest[1].wrapping_add(b);
        digest[2] = digest[2].wrapping_add(c);
        digest[3] = digest[3].wrapping_add(d);
        digest[4] = digest[4].wrapping_add(e);
        digest[5] = digest[5].wrapping_add(f);
        digest[6] = digest[6].wrapping_add(g);
        digest[7] = digest[7].wrapping_add(h);
    }

    let mut digest_bytes = vec![];
    let mut word_bytes = [0u8; 4];
    for word in digest.iter() {
        BigEndian::write_u32(&mut word_bytes, *word);
        for byte in word_bytes.iter() {
            digest_bytes.push(*byte);
        }
    }
    digest_bytes
}

#[test]
fn test_hello() {
    let hex_digest: String = sha256(b"hello")
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();

    assert_eq!(
        hex_digest,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}
