mod public;
pub mod signing_winternitz;
pub mod utils;
pub mod winternitz;

pub use public::{
    CompactWots, GenericWinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs, Wots,
    Wots16, Wots32, Wots4, Wots64, Wots80, LOG2_BASE,
};

/// Byte length of messages of the standard WOTS implementation used in BitVM.
pub const HASH_LEN: usize = 16;
