use crate::treepp::*;
use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, PublicKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        contexts::{operator::OperatorContext, withdrawer::WithdrawerContext},
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PegOutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl PreSignedTransaction for PegOutTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PegOutTransaction {
    pub fn new(
        context: &OperatorContext,
        withdrawer_public_key: &PublicKey,
        input0: Input,
        input1: Input,
    ) -> Self {
        // QUESTION Why do we need this input from Bob?
        let _input0 = TxIn {
            previous_output: input0.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _input1 = TxIn {
            previous_output: input1.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_output_amount = input0.amount + input1.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(
                context.network,
                &withdrawer_public_key,
            )
            .script_pubkey(),
        };

        let mut this = PegOutTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1],
                output: vec![_output0],
            },
            prev_outs: vec![
                TxOut {
                    value: input0.amount,
                    script_pubkey: generate_pay_to_pubkey_script_address(
                        context.network,
                        &withdrawer_public_key,
                    )
                    .script_pubkey(),
                },
                TxOut {
                    value: input1.amount,
                    script_pubkey: generate_pay_to_pubkey_script_address(
                        context.network,
                        &context.operator_public_key,
                    )
                    .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                generate_pay_to_pubkey_script(&withdrawer_public_key),
                generate_pay_to_pubkey_script(&context.operator_public_key),
            ],
        };

        // this.sign_input0(...);
        this.sign_input1(context);

        this
    }

    fn sign_input0(&mut self, context: &WithdrawerContext) {
        todo!();
    }

    fn sign_input1(&mut self, context: &OperatorContext) {
        pre_sign_p2wsh_input(
            self,
            context,
            1,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for PegOutTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
