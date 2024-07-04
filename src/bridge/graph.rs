use bitcoin::{Amount, OutPoint};
use num_traits::ToPrimitive;
use std::collections::HashMap;

use super::{
    contexts::{depositor::DepositorContext, operator::OperatorContext},
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
        burn::BurnTransaction,
        challenge::{self, ChallengeTransaction},
        disprove::DisproveTransaction,
        kick_off::KickOffTransaction,
        peg_in_confirm::{self, PegInConfirmTransaction},
        peg_in_deposit::PegInDepositTransaction,
        peg_in_refund::{self, PegInRefundTransaction},
        pre_signed::PreSignedTransaction,
        take1::Take1Transaction,
        take2::Take2Transaction,
    },
};

// TODO delete
// DEMO SECRETS
pub const OPERATOR_SECRET: &str =
    "d898098e09898a0980989b980809809809f09809884324874302975287524398";
pub const N_OF_N_SECRET: &str = "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497";
pub const DEPOSITOR_SECRET: &str =
    "b8f17ea979be24199e7c3fec71ee88914d92fd4ca508443f765d56ce024ef1d7";
pub const WITHDRAWER_SECRET: &str =
    "fffd54f6d8f8ad470cb507fd4b6e9b3ea26b4221a4900cc5ad5916ce67c02f1e";

pub const EVM_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

// pub type CompiledBitVMGraph = HashMap<OutPoint, Vec<Box<dyn BaseTransaction + 'static>>>;

pub fn compile_peg_in_graph(context: &DepositorContext, input: Input) -> () {
    let peg_in_deposit = PegInDepositTransaction::new(context, input);
    let peg_in_deposit_txid = peg_in_deposit.tx().compute_txid();

    let peg_in_refund_vout0: usize = 0;
    let peg_in_refund = PegInRefundTransaction::new(
        context,
        Input {
            outpoint: OutPoint {
                txid: peg_in_deposit_txid,
                vout: peg_in_refund_vout0.to_u32().unwrap(),
            },
            amount: peg_in_deposit.tx().output[peg_in_refund_vout0].value,
        },
    );

    let peg_in_confirm_vout0: usize = 0;
    let peg_in_confirm = PegInConfirmTransaction::new(
        context,
        Input {
            outpoint: OutPoint {
                txid: peg_in_deposit_txid,
                vout: peg_in_confirm_vout0.to_u32().unwrap(),
            },
            amount: peg_in_deposit.tx().output[peg_in_confirm_vout0].value,
        },
    );
}

pub fn compile_graph(
    context: &OperatorContext,
    peg_in_confirm: &PegInConfirmTransaction,
    initial_outpoint: OutPoint,
) -> CompiledBitVMGraph {
    let kick_off = KickOffTransaction::new(
        context,
        Input {
            outpoint: initial_outpoint,
            amount: Amount::from_sat(DUST_AMOUNT),
        },
    );
    let kick_off_txid = kick_off.tx().compute_txid();

    let peg_in_confirm_txid = peg_in_confirm.tx().compute_txid();
    let take1_vout0 = 0;
    let take1_vout1 = 0;
    let take1_vout2 = 1;
    let take1_vout3 = 2;
    let take1 = Take1Transaction::new(
        context,
        Input {
            outpoint: OutPoint {
                txid: peg_in_confirm_txid,
                vout: take1_vout0.to_u32().unwrap(),
            },
            amount: peg_in_confirm.tx().output[take1_vout0].value,
        },
        Input {
            outpoint: OutPoint {
                txid: kick_off_txid,
                vout: take1_vout1.to_u32().unwrap(),
            },
            amount: kick_off.tx().output[take1_vout1].value,
        },
        Input {
            outpoint: OutPoint {
                txid: kick_off_txid,
                vout: take1_vout2.to_u32().unwrap(),
            },
            amount: kick_off.tx().output[take1_vout2].value,
        },
        Input {
            outpoint: OutPoint {
                txid: kick_off_txid,
                vout: take1_vout3.to_u32().unwrap(),
            },
            amount: kick_off.tx().output[take1_vout3].value,
        },
    );

    let input_amount_crowdfunding = Amount::from_btc(1.0).unwrap(); // TODO replace placeholder
    let challenge_vout0 = 1;
    let challenge = ChallengeTransaction::new(
        context,
        Input {
            outpoint: OutPoint {
                txid: kick_off_txid,
                vout: challenge_vout0.to_u32().unwrap(),
            },
            amount: kick_off.tx().output[challenge_vout0].value,
        },
        input_amount_crowdfunding,
    );

    let assert_vout0 = 2;
    let assert = AssertTransaction::new(
        context,
        Input {
            outpoint: OutPoint {
                txid: kick_off_txid,
                vout: assert_vout0.to_u32().unwrap(),
            },
            amount: kick_off.tx().output[assert_vout0].value,
        },
    );
    let assert_txid = kick_off.tx().compute_txid();

    let take2_vout0 = 0;
    let take2_vout1 = 0;
    let take2_vout2 = 1;
    let take2 = Take2Transaction::new(
        context,
        Input {
            outpoint: OutPoint {
                txid: peg_in_confirm_txid,
                vout: take2_vout0.to_u32().unwrap(),
            },
            amount: peg_in_confirm.tx().output[take2_vout0].value,
        },
        Input {
            outpoint: OutPoint {
                txid: assert_txid,
                vout: take2_vout1.to_u32().unwrap(),
            },
            amount: assert.tx().output[take2_vout1].value,
        },
        Input {
            outpoint: OutPoint {
                txid: assert_txid,
                vout: take2_vout2.to_u32().unwrap(),
            },
            amount: assert.tx().output[take2_vout2].value,
        },
    );

    let script_index = 1; // TODO replace placeholder
    let disprove_vout0 = 1;
    let disprove_vout1 = 2;
    let disprove = DisproveTransaction::new(
        context,
        Input {
            outpoint: OutPoint {
                txid: assert_txid,
                vout: disprove_vout0.to_u32().unwrap(),
            },
            amount: assert.tx().output[disprove_vout0].value,
        },
        Input {
            outpoint: OutPoint {
                txid: assert_txid,
                vout: disprove_vout1.to_u32().unwrap(),
            },
            amount: assert.tx().output[disprove_vout1].value,
        },
        script_index,
    );

    let burn_vout0 = 2;
    let burn = BurnTransaction::new(
        context,
        Input {
            outpoint: OutPoint {
                txid: kick_off_txid,
                vout: burn_vout0.to_u32().unwrap(),
            },
            amount: kick_off.tx().output[burn_vout0].value,
        },
    );

    // let mut disprove_txs = vec![];
    // for i in 0..1000 {
    //     let disprove_tx = Box::new(DisproveTransaction::new(
    //         context,
    //         Input {
    //             outpoint: initial_outpoint,
    //             amount: Amount::from_sat(INITIAL_AMOUNT),
    //         },
    //         Input {
    //             // TODO this needs to be replaced, this is just to silence errors for now
    //             outpoint: initial_outpoint,
    //             amount: Amount::from_sat(INITIAL_AMOUNT),
    //         },
    //         i,
    //     ));
    //     disprove_txs.push(disprove_tx as Box<dyn BaseTransaction + 'static>);
    // }
    // graph.insert(initial_outpoint, disprove_txs);

    // // Pre-sign transactions in the graph.
    // for transaction_vec in graph.values_mut() {
    //     for bridge_transaction in transaction_vec.iter_mut() {
    //         bridge_transaction.pre_sign(context);
    //     }
    // }
    // HashMap::new()
}
