use bitcoin::{
    hex::{Case::Upper, DisplayHex},
    key::Keypair,
    Amount, Network, OutPoint, PublicKey, Script, ScriptBuf, XOnlyPublicKey,
};
use num_traits::ToPrimitive;
use sha2::{Digest, Sha256};

use crate::bridge::contexts::{base::BaseContext, verifier::VerifierContext};

use super::{
    super::{
        contexts::operator::OperatorContext,
        transactions::{
            assert::AssertTransaction, base::Input, burn::BurnTransaction,
            challenge::ChallengeTransaction, disprove::DisproveTransaction,
            kick_off::KickOffTransaction, peg_out::PegOutTransaction,
            pre_signed::PreSignedTransaction, take1::Take1Transaction, take2::Take2Transaction,
        },
    },
    base::{BaseGraph, DUST_AMOUNT, GRAPH_VERSION},
    peg_in::PegInGraph,
};

pub struct PegOutGraph {
    version: String,
    network: Network,
    id: String,

    // state: State,
    // n_of_n_pre_signing_state: PreSigningState,
    peg_in_graph_id: String,
    kick_off_transaction: KickOffTransaction,
    take1_transaction: Take1Transaction,
    challenge_transaction: ChallengeTransaction,
    assert_transaction: AssertTransaction,
    take2_transaction: Take2Transaction,
    disprove_transaction: DisproveTransaction,
    burn_transaction: BurnTransaction,

    operator_public_key: PublicKey,
    operator_taproot_public_key: XOnlyPublicKey,

    withdrawer_public_key: Option<PublicKey>,
    withdrawer_taproot_public_key: Option<XOnlyPublicKey>,
    withdrawer_evm_address: Option<String>,

    peg_out_transaction: Option<PegOutTransaction>,
}

impl BaseGraph for PegOutGraph {
    fn network(&self) -> Network { self.network }

    fn id(&self) -> &String { &self.id }
}

impl PegOutGraph {
    pub fn new(
        context: &OperatorContext,
        peg_in_graph: &PegInGraph,
        initial_outpoint: OutPoint,
    ) -> Self {
        let mut kick_off_transaction = KickOffTransaction::new(
            context,
            Input {
                outpoint: initial_outpoint,
                amount: Amount::from_sat(DUST_AMOUNT),
            },
        );
        let kick_off_txid = kick_off_transaction.tx().compute_txid();

        let peg_in_confirm_transaction = peg_in_graph.peg_in_confirm_transaction_ref();
        let peg_in_confirm_txid = peg_in_confirm_transaction.tx().compute_txid();
        let take1_vout0 = 0;
        let take1_vout1 = 0;
        let take1_vout2 = 1;
        let take1_vout3 = 2;
        let take1_transaction = Take1Transaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take1_vout0.to_u32().unwrap(),
                },
                amount: peg_in_confirm_transaction.tx().output[take1_vout0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: take1_vout1.to_u32().unwrap(),
                },
                amount: kick_off_transaction.tx().output[take1_vout1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: take1_vout2.to_u32().unwrap(),
                },
                amount: kick_off_transaction.tx().output[take1_vout2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: take1_vout3.to_u32().unwrap(),
                },
                amount: kick_off_transaction.tx().output[take1_vout3].value,
            },
        );

        let input_amount_crowdfunding = Amount::from_btc(1.0).unwrap(); // TODO replace placeholder
        let challenge_vout0 = 1;
        let challenge_transaction = ChallengeTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: challenge_vout0.to_u32().unwrap(),
                },
                amount: kick_off_transaction.tx().output[challenge_vout0].value,
            },
            input_amount_crowdfunding,
        );

        let assert_vout0 = 2;
        let mut assert_transaction = AssertTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: assert_vout0.to_u32().unwrap(),
                },
                amount: kick_off_transaction.tx().output[assert_vout0].value,
            },
        );
        let assert_txid = kick_off_transaction.tx().compute_txid();

        let take2_vout0 = 0;
        let take2_vout1 = 0;
        let take2_vout2 = 1;
        let take2_transaction = Take2Transaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take2_vout0.to_u32().unwrap(),
                },
                amount: peg_in_confirm_transaction.tx().output[take2_vout0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: take2_vout1.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[take2_vout1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: take2_vout2.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[take2_vout2].value,
            },
        );

        let script_index = 1; // TODO replace placeholder
        let disprove_vout0 = 1;
        let disprove_vout1 = 2;
        let disprove_transaction = DisproveTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout0.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[disprove_vout0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout1.to_u32().unwrap(),
                },
                amount: assert_transaction.tx().output[disprove_vout1].value,
            },
            script_index,
        );

        let burn_vout0 = 2;
        let burn_transaction = BurnTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: burn_vout0.to_u32().unwrap(),
                },
                amount: kick_off_transaction.tx().output[burn_vout0].value,
            },
        );

        PegOutGraph {
            version: GRAPH_VERSION.to_string(),
            network: context.network,
            id: generate_id(peg_in_graph, &context.operator_public_key),
            peg_in_graph_id: peg_in_graph.id().clone(),
            kick_off_transaction,
            take1_transaction,
            challenge_transaction,
            assert_transaction,
            take2_transaction,
            disprove_transaction,
            burn_transaction,
            operator_public_key: context.operator_public_key,
            operator_taproot_public_key: context.operator_taproot_public_key,
            withdrawer_public_key: None,
            withdrawer_taproot_public_key: None,
            withdrawer_evm_address: None,
            peg_out_transaction: None,
        }
    }

    pub fn pre_sign(&mut self, context: &VerifierContext) {
        self.assert_transaction.pre_sign(context);
        self.burn_transaction.pre_sign(context);
        self.disprove_transaction.pre_sign(context);
        self.take1_transaction.pre_sign(context);
        self.take2_transaction.pre_sign(context);
    }

    pub fn challenge(
        &mut self,
        context: &dyn BaseContext,
        input: OutPoint,
        script: &Script,
        keypair: &Keypair,
    ) {
        todo!()
    }

    pub fn assert(&mut self) { todo!() }

    pub fn disprove(&mut self, input_script_index: u32, output_script_pubkey: ScriptBuf) {}

    pub fn burn(&mut self, output_script_pubkey: ScriptBuf) {
        // if (!correct state) {
        //   panic()
        // }

        todo!()
    }
}

pub fn generate_id(peg_in_graph: &PegInGraph, operator_public_key: &PublicKey) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_graph.id().to_string() + &operator_public_key.to_string());

    hasher.finalize().to_hex_string(Upper)
}
