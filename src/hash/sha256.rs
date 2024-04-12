#![allow(non_snake_case)]

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const CHUNK: usize = 64;
const SIZE: usize = 32;

const INIT0: u32 = 0x6A09E667;
const INIT1: u32 = 0xBB67AE85;
const INIT2: u32 = 0x3C6EF372;
const INIT3: u32 = 0xA54FF53A;
const INIT4: u32 = 0x510E527F;
const INIT5: u32 = 0x9B05688C;
const INIT6: u32 = 0x1F83D9AB;
const INIT7: u32 = 0x5BE0CD19;



fn rotate_left_32(x: u32, k: i32) -> u32 {
    const N: u32 = 32;
    let s = k as u32 & (N - 1);
    x.rotate_left(s)
}


struct Digest {
    h: [u32; 8],
    x: [u8; CHUNK],
    nx: usize,
    len: u64,
    is224: bool,
}

impl Digest {
    fn new() -> Self {
        Self {
            h: [
                INIT0, INIT1, INIT2, INIT3,
                INIT4, INIT5, INIT6, INIT7,
            ],
            x: [0; CHUNK],
            nx: 0,
            len: 0,
            is224: false,
        }
    }

    fn block(&mut self,  pOrg: &[u8]) {
        let mut p =pOrg;
        let mut w = [0u32; 64];
        let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = (
            self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6], self.h[7]
        );

        while p.len() >= CHUNK {
            for i in 0..16 {
                let j = i * 4;
                w[i] = u32::from(p[j]) << 24 | u32::from(p[j + 1]) << 16 | u32::from(p[j + 2]) << 8 | u32::from(p[j + 3]);
            }
            for i in 16..64 {
                let v1 = w[i - 2];
                let t1 = (rotate_left_32(v1,-17) ^ rotate_left_32(v1,-19) ^ (v1 >> 10)) as u32;
                let v2 = w[i - 15];
                let t2 = (rotate_left_32(v2,-7) ^ rotate_left_32(v2,-18) ^ (v2 >> 3)) as u32;
                w[i] = t1.wrapping_add(w[i - 7]).wrapping_add(t2).wrapping_add(w[i - 16]);
            }
        
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (h0, h1, h2, h3, h4, h5, h6, h7);
        
            for i in 0..64 {
                let t1 = h.wrapping_add((rotate_left_32(e, -6)) ^ (rotate_left_32(e, -11)) ^ (rotate_left_32(e, -25))) 
                .wrapping_add((e & f) ^ (!e & g)) 
                .wrapping_add(K[i]) 
                .wrapping_add(w[i]);

                let t2 = ((rotate_left_32(a, -2)) ^ (rotate_left_32(a, -13)) ^ (rotate_left_32(a, -22)))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            
                println!("Computed hash: {:?}", p);
        
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
        
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
            h5 = h5.wrapping_add(f);
            h6 = h6.wrapping_add(g);
            h7 = h7.wrapping_add(h);
        
            println!("Computed hash: {:?}", p);

            p = &p[CHUNK..];
        }
        self.h = [h0, h1, h2, h3, h4, h5, h6, h7];
    }

    fn write(&mut self, p: &[u8]) {
        let nn = p.len();
        self.len += nn as u64;
        let mut nn = nn;

        if self.nx > 0 {
            let n = std::cmp::min(CHUNK - self.nx, nn);
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            nn -= n;
            if self.nx == CHUNK {
                let mut x_copy = self.x; // Make a copy of self.x
                self.block(&mut x_copy); // Pass the copy to the block function
                self.nx = 0;
            }
        }

        if nn >= CHUNK {
            let n = nn & !(CHUNK - 1);
            self.block(&p[..n]);
            nn -= n;
        }

        if nn > 0 {
            self.x[..nn].copy_from_slice(&p[p.len() - nn..]);
            self.nx = nn;
        }
    }


    
    fn check_sum(&mut self) -> [u8; SIZE] {
        let len = self.len;
        // Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
        let mut tmp = [0u8; 64 + 8]; // padding + length buffer
        tmp[0] = 0x80;
        let t: u64;
        if len % 64 < 56 {
            t = 56 - len % 64;
        } else {
            t = 64 + 56 - len % 64;
        }
    
        // Length in bits.
        let len_bits = len << 3;
        let padlen = &mut tmp[..(t as usize + 8)];

        padlen[t as usize..].copy_from_slice(&len_bits.to_be_bytes());
        self.write(padlen);
    
        if self.nx != 0 {
            panic!("d.nx != 0");
        }
    
        let mut digest = [0u8; SIZE];
        let mut bytes = [0u8; 4];
    
        bytes.copy_from_slice(&self.h[0].to_be_bytes());
        digest[0..4].copy_from_slice(&bytes);
    
        bytes.copy_from_slice(&self.h[1].to_be_bytes());
        digest[4..8].copy_from_slice(&bytes);
    
        bytes.copy_from_slice(&self.h[2].to_be_bytes());
        digest[8..12].copy_from_slice(&bytes);
    
        bytes.copy_from_slice(&self.h[3].to_be_bytes());
        digest[12..16].copy_from_slice(&bytes);
    
        bytes.copy_from_slice(&self.h[4].to_be_bytes());
        digest[16..20].copy_from_slice(&bytes);
    
        bytes.copy_from_slice(&self.h[5].to_be_bytes());
        digest[20..24].copy_from_slice(&bytes);
    
        bytes.copy_from_slice(&self.h[6].to_be_bytes());
        digest[24..28].copy_from_slice(&bytes);
    
        if !self.is224 {
            bytes.copy_from_slice(&self.h[7].to_be_bytes());
            digest[28..32].copy_from_slice(&bytes);
        }
    
        digest
    }
    

}


pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut d = Digest::new();
    d.write(data);
    d.check_sum().to_vec()
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        use sha256::digest;
    
        let message = b"Hello, world!";
        let custom_hash = sha256(message);
        let crate_hash = digest(message);
        let mut crate_hash_bytes = [0u8; 32];
        hex::decode_to_slice(crate_hash, &mut crate_hash_bytes).unwrap();
        assert_eq!(custom_hash, crate_hash_bytes);
    }
}
