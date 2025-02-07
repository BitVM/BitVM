use bitcoin_script::script;

use crate::chunk::primitives::{pack_nibbles_to_limbs};
use crate::treepp::Script;

use crate::signatures::wots::{wots160, wots256};



pub(crate) fn wots_compact_checksig_verify_with_pubkey(pub_key: &WOTSPubKey) -> Script {
    match pub_key {
        WOTSPubKey::P160(pb) => {
            let sc_nib = wots160::compact::checksig_verify(*pb);
            const N0: usize = 40;
            return script!{
                {sc_nib}
                for _ in 0..(64-N0) {
                    {0}
                }
                // field element reconstruction
                for i in 1..64 {
                    {i} OP_ROLL
                }
        
                {pack_nibbles_to_limbs()}
            }
        },
        WOTSPubKey::P256(pb) => {
            let sc_nib = wots256::compact::checksig_verify(*pb);
            return script!{
                {sc_nib}
                // field element reconstruction
                for i in 1..64 {
                    {i} OP_ROLL
                }
                {pack_nibbles_to_limbs()}
            }
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WOTSPubKey {
    P160(wots160::PublicKey),
    P256(wots256::PublicKey)
}