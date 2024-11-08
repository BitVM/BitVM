use bitcoin::{ecdsa, taproot};

pub struct DepositorSignatures {
    pub deposit: ecdsa::Signature,
    pub refund: taproot::Signature,
    pub confirm: taproot::Signature,
}

impl DepositorSignatures {
    pub fn from_slices(
        deposit_signature: &[u8],
        refund_signature: &[u8],
        confirm_signature: &[u8],
    ) -> Self {
        Self {
            deposit: ecdsa::Signature::from_slice(deposit_signature)
                .expect("Invalid deposit signature"),
            refund: taproot::Signature::from_slice(refund_signature)
                .expect("Invalid refund signature"),
            confirm: taproot::Signature::from_slice(confirm_signature)
                .expect("Invalid confirm signature"),
        }
    }
}
