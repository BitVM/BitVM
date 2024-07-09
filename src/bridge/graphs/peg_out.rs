use bitcoin::{
    hex::{Case::Upper, DisplayHex},
    key::Keypair,
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Txid, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, Error};
use num_traits::ToPrimitive;
use sha2::{Digest, Sha256};

use crate::bridge::{
    constants::{NUM_BLOCKS_PER_2_WEEKS, NUM_BLOCKS_PER_4_WEEKS},
    contexts::{base::BaseContext, verifier::VerifierContext},
    transactions::{base::{BaseTransaction, InputWithScript}},
};

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
    peg_in_confirm_txid: Txid,
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
            peg_in_confirm_txid,
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

    pub async fn kick_off(&mut self, client: &AsyncClient) {
        Self::verify_if_not_mined(&client, self.kick_off_transaction.tx().compute_txid()).await;

        // complete kick_off tx
        let kick_off_tx = self.kick_off_transaction.finalize();

        // broadcast kick_off tx
        let kick_off_result = client.broadcast(&kick_off_tx).await;

        // verify kick_off tx result
        Self::verify_tx_result(&kick_off_result);
    }

    pub async fn challenge(
        &mut self,
        client: &AsyncClient,
        context: &dyn BaseContext,
        crowdfundng_inputs: &Vec<InputWithScript<'_>>,
        keypair: &Keypair,
        output_script_pubkey: ScriptBuf,
    ) {
        Self::verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await;

        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        if kick_off_status.is_ok_and(|status| status.confirmed) {
            // complete challenge tx
            self.challenge_transaction.add_inputs_and_output(
                context,
                crowdfundng_inputs,
                keypair,
                output_script_pubkey,
            );
            let challenge_tx = self.challenge_transaction.finalize();

            // broadcast challenge tx
            let challenge_result = client.broadcast(&challenge_tx).await;

            // verify challenge tx result
            Self::verify_tx_result(&challenge_result);
        } else {
            panic!("Kick-off tx has not been yet confirmed!");
        }
    }

    pub async fn assert(&mut self, client: &AsyncClient) {
        Self::verify_if_not_mined(client, self.assert_transaction.tx().compute_txid()).await;

        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        if kick_off_status.is_ok_and(|status| status.confirmed) {
            // complete assert tx
            // TODO: commit ZK computation result
            let assert_tx = self.assert_transaction.finalize();

            // broadcast assert tx
            let assert_result = client.broadcast(&assert_tx).await;

            // verify assert tx result
            Self::verify_tx_result(&assert_result);
        } else {
            panic!("Kick-off tx has not been yet confirmed!");
        }
    }

    pub async fn disprove(
        &mut self,
        client: &AsyncClient,
        input_script_index: u32,
        output_script_pubkey: ScriptBuf,
    ) {
        Self::verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await;

        let assert_txid = self.assert_transaction.tx().compute_txid();
        let assert_status = client.get_tx_status(&assert_txid).await;

        if assert_status.is_ok_and(|status| status.confirmed) {
            // complete disprove tx
            self.disprove_transaction
                .add_input_output(input_script_index, output_script_pubkey);
            let disprove_tx = self.disprove_transaction.finalize();

            // broadcast disprove tx
            let disprove_result = client.broadcast(&disprove_tx).await;

            // verify disprove tx result
            Self::verify_tx_result(&disprove_result);
        } else {
            panic!("Assert tx has not been yet confirmed!");
        }
    }

    pub async fn burn(&mut self, client: &AsyncClient, output_script_pubkey: ScriptBuf) {
        Self::verify_if_not_mined(client, self.burn_transaction.tx().compute_txid()).await;

        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        let blockchain_height = Self::get_block_height(client).await;

        if kick_off_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + NUM_BLOCKS_PER_4_WEEKS <= blockchain_height
                })
            {
                // complete burn tx
                self.burn_transaction.add_output(output_script_pubkey);
                let burn_tx = self.burn_transaction.finalize();

                // broadcast burn tx
                let burn_result = client.broadcast(&burn_tx).await;

                // verify burn tx result
                Self::verify_tx_result(&burn_result);
            } else {
                panic!("Kick-off timelock has not yet elapsed!");
            }
        } else {
            panic!("Kick-off tx has not been yet confirmed!");
        }
    }

    pub async fn take1(&mut self, client: &AsyncClient) {
        Self::verify_if_not_mined(&client, self.take1_transaction.tx().compute_txid()).await;
        Self::verify_if_not_mined(&client, self.challenge_transaction.tx().compute_txid()).await;
        Self::verify_if_not_mined(&client, self.assert_transaction.tx().compute_txid()).await;
        Self::verify_if_not_mined(&client, self.burn_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;
        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        let blockchain_height = Self::get_block_height(client).await;

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed)
            && kick_off_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
        {
            if kick_off_status
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + NUM_BLOCKS_PER_2_WEEKS <= blockchain_height
                })
            {
                // complete take1 tx
                let take1_tx = self.take1_transaction.finalize();

                // broadcast take1 tx
                let take1_result = client.broadcast(&take1_tx).await;

                // verify take1 tx result
                Self::verify_tx_result(&take1_result);
            } else {
                panic!("Kick-off tx timelock has not yet elapsed!");
            }
        } else {
            panic!("Neither peg-in confirm tx nor kick-off tx has not been yet confirmed!");
        }
    }

    pub async fn take2(&mut self, client: &AsyncClient) {
        Self::verify_if_not_mined(&client, self.take2_transaction.tx().compute_txid()).await;
        Self::verify_if_not_mined(&client, self.take1_transaction.tx().compute_txid()).await;
        Self::verify_if_not_mined(&client, self.disprove_transaction.tx().compute_txid()).await;
        Self::verify_if_not_mined(&client, self.burn_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;
        let assert_txid = self.assert_transaction.tx().compute_txid();
        let assert_status = client.get_tx_status(&assert_txid).await;

        let blockchain_height = Self::get_block_height(client).await;

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed)
            && assert_status.as_ref().is_ok_and(|status| status.confirmed)
        {
            if assert_status
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + NUM_BLOCKS_PER_2_WEEKS <= blockchain_height
                })
            {
                // complete take2 tx
                let take2_tx = self.take2_transaction.finalize();

                // broadcast take2 tx
                let take2_result = client.broadcast(&take2_tx).await;

                // verify take2 tx result
                Self::verify_tx_result(&take2_result);
            } else {
                panic!("Assert tx timelock has not yet elapsed!");
            }
        } else {
            panic!("Neither peg-in confirm tx nor assert tx has not been yet confirmed!");
        }
    }

    async fn get_block_height(client: &AsyncClient) -> u32 {
        let blockchain_height_result = client.get_height().await;
        if blockchain_height_result.is_err() {
            panic!(
                "Failed to fetch blockchain height! Error occurred {:?}",
                blockchain_height_result
            );
        }

        blockchain_height_result.unwrap()
    }

    async fn verify_if_not_mined(client: &AsyncClient, txid: Txid) {
        let tx_status = client.get_tx_status(&txid).await;
        if tx_status.as_ref().is_ok_and(|status| status.confirmed) {
            panic!("Transaction already mined!");
        } else if tx_status.is_err() {
            panic!(
                "Failed to get transaction status, error occurred {:?}",
                tx_status
            );
        }
    }

    fn verify_tx_result(tx_result: &Result<(), Error>) {
        if tx_result.is_ok() {
            println!("Tx mined successfully.");
        } else {
            panic!("Error occurred {:?}", tx_result);
        }
    }
}

pub fn generate_id(peg_in_graph: &PegInGraph, operator_public_key: &PublicKey) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_graph.id().to_string() + &operator_public_key.to_string());

    hasher.finalize().to_hex_string(Upper)
}
