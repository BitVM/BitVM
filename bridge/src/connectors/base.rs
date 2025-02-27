use bitcoin::{
    key::TweakedPublicKey, taproot::TaprootSpendInfo, Address, ScriptBuf, Sequence, TapNodeHash,
    TxIn, Witness,
};
use serde::{Deserialize, Serialize};

use super::super::transactions::base::Input;

pub fn generate_default_tx_in(input: &Input) -> TxIn {
    TxIn {
        previous_output: input.outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    }
}

pub fn generate_timelock_tx_in(input: &Input, num_blocks: u32) -> TxIn {
    let mut tx_in = generate_default_tx_in(input);
    tx_in.sequence = Sequence(num_blocks);
    tx_in
}

/*
// TODO figure out if we need to handle CLTV differently than other timelock txs
https://github.com/BlockchainCommons/Learning-Bitcoin-from-the-Command-Line/blob/master/11_2_Using_CLTV_in_Scripts.md
A locking script will only allow a transaction to respend a UTXO locked with a CLTV if OP_CHECKLOCKTIMEVERIFY verifies all of the following:

The nSequence field must be set to less than 0xffffffff, usually 0xffffffff-1 to avoid conflicts with relative timelocks.
CLTV must pop an operand off the stack and it must be 0 or greater.
Both the stack operand and nLockTime must either be above or below 500 million, to depict the same sort of absolute timelock.
The nLockTime value must be greater than or equal to the stack operand.
So the first thing to note here is that nLockTime is still used with CLTV. To be precise, it's required in the transaction that tries to respend a CLTV-timelocked UTXO. That means that it's not a part of the script's requirements. It's just the timer that's used to release the funds, as defined in the script.

This is managed through a clever understanding of how nLockTime works: a value for nLockTime must always be chosen that is less than or equal to the present time (or blockheight), so that the respending transaction can be put on the blockchain. However, due to CLTV's requirements, a value must also be chosen that is greater than or equal to CLTV's operand. The union of these two sets is NULL until the present time matches the CLTV operand. Afterward, any value can be chosen between CLTV's operand and the present time. Usually, you'd just set it to the present time (or block).
*/
pub fn generate_check_lock_time_tx_in(input: &Input, num_blocks: u32) -> TxIn {
    let mut tx_in = generate_default_tx_in(input);
    tx_in.sequence = Sequence(num_blocks);
    tx_in
}

pub trait P2wshConnector {
    fn generate_script(&self) -> ScriptBuf;

    fn generate_address(&self) -> Address;

    fn generate_tx_in(&self, input: &Input) -> TxIn;
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct TaprootSpendInfoCache {
    pub merkle_root: Option<TapNodeHash>,
    pub output_key: TweakedPublicKey,
}

pub trait TaprootConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf;

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn;

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo;

    fn generate_taproot_address(&self) -> Address;
}
