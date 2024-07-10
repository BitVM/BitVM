use bitcoin::{
    hex::{Case::Upper, DisplayHex},
    key::Keypair,
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Txid, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, Error, TxStatus};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bridge::{
    constants::{NUM_BLOCKS_PER_2_WEEKS, NUM_BLOCKS_PER_4_WEEKS},
    contexts::{base::BaseContext, verifier::VerifierContext},
    transactions::base::{BaseTransaction, InputWithScript},
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
    base::{
        get_block_height, verify_if_not_mined, verify_tx_result, BaseGraph,
        GRAPH_VERSION,
    },
    peg_in::PegInGraph,
};

pub enum PegOutDepositorStatus {
    PegOutNotStarted, // peg-out transaction not created yet
    PegOutWait,       // peg-out not confirmed yet, wait
    PegOutComplete,   // peg-out complete
}

pub enum PegOutVerifierStatus {
    PegOutPresign,           // should presign peg-out graph
    PegOutComplete,          // peg-out complete
    PegOutWait,              // no action required, wait
    PegOutChallengeAvailabe, // can challenge
    PegOutBurnAvailable,
    PegOutDisproveAvailable,
    PegOutFailed, // burn or disprove executed
}

pub enum PegOutOperatorStatus {
    PegOutWait,
    PegOutComplete,    // peg-out complete
    PegOutFailed,      // burn or disprove executed
    PegOutStartPegOut, // should execute peg-out tx
    PegOutKickOffAvailable,
    PegOutAssertAvailable,
    PegOutTake1Available,
    PegOutTake2Available,
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PegOutGraph {
    version: String,
    network: Network,
    id: String,

    // state: State,
    // n_of_n_pre_signing_state: PreSigningState,
    n_of_n_presigned: bool,

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
    pub fn new(context: &OperatorContext, peg_in_graph: &PegInGraph, kickoff_input: Input) -> Self {
        let kick_off_transaction = KickOffTransaction::new(context, kickoff_input);
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
        let assert_transaction = AssertTransaction::new(
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
            n_of_n_presigned: false,
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

        self.n_of_n_presigned = true; // TODO: set to true after collecting all n of n signatures
    }

    pub async fn verifier_status(&self, client: &AsyncClient) -> PegOutVerifierStatus {
        if self.n_of_n_presigned {
            let (
                kick_off_status,
                challenge_status,
                assert_status,
                disprove_status,
                burn_status,
                take1_status,
                take2_status,
                _,
            ) = Self::get_peg_out_statuses(self, client).await;
            let blockchain_height = get_block_height(client).await;

            if kick_off_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                // check take1 and take2
                if take1_status.as_ref().is_ok_and(|status| status.confirmed)
                    || take2_status.as_ref().is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutComplete;
                }

                // check burn and disprove
                if burn_status.as_ref().is_ok_and(|status| status.confirmed)
                    || disprove_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutFailed; // TODO: can be also `PegOutVerifierStatus::PegOutComplete`
                }

                if kick_off_status
                    .as_ref()
                    .unwrap()
                    .block_height
                    .is_some_and(|block_height| {
                        block_height + NUM_BLOCKS_PER_4_WEEKS > blockchain_height
                    })
                {
                    if challenge_status
                        .as_ref()
                        .is_ok_and(|status| !status.confirmed)
                    {
                        return PegOutVerifierStatus::PegOutChallengeAvailabe;
                    } else if assert_status.as_ref().is_ok_and(|status| status.confirmed) {
                        return PegOutVerifierStatus::PegOutDisproveAvailable;
                    } else {
                        return PegOutVerifierStatus::PegOutWait;
                    }
                } else {
                    if assert_status.is_ok_and(|status| !status.confirmed) {
                        return PegOutVerifierStatus::PegOutBurnAvailable; // TODO: challange and burn available here
                    } else {
                        return PegOutVerifierStatus::PegOutDisproveAvailable;
                    }
                }
            } else {
                return PegOutVerifierStatus::PegOutWait;
            }
        } else {
            return PegOutVerifierStatus::PegOutPresign;
        }
    }

    pub async fn operator_status(&self, client: &AsyncClient) -> PegOutOperatorStatus {
        if self.n_of_n_presigned {
            let (
                kick_off_status,
                challenge_status,
                assert_status,
                disprove_status,
                burn_status,
                take1_status,
                take2_status,
                peg_out_status,
            ) = Self::get_peg_out_statuses(self, client).await;
            let blockchain_height = get_block_height(client).await;

            if peg_out_status.is_some_and(|status| status.unwrap().confirmed) {
                if kick_off_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    // check take1 and take2
                    if take1_status.as_ref().is_ok_and(|status| status.confirmed)
                        || take2_status.as_ref().is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutComplete;
                    }

                    // check burn and disprove
                    if burn_status.as_ref().is_ok_and(|status| status.confirmed)
                        || disprove_status
                            .as_ref()
                            .is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutFailed; // TODO: can be also `PegOutOperatorStatus::PegOutComplete`
                    }

                    if challenge_status.is_ok_and(|status| status.confirmed) {
                        if assert_status.as_ref().is_ok_and(|status| status.confirmed) {
                            if assert_status.as_ref().unwrap().block_height.is_some_and(
                                |block_height| {
                                    block_height + NUM_BLOCKS_PER_2_WEEKS <= blockchain_height
                                },
                            ) {
                                return PegOutOperatorStatus::PegOutTake2Available;
                            } else {
                                return PegOutOperatorStatus::PegOutWait;
                            }
                        } else {
                            return PegOutOperatorStatus::PegOutAssertAvailable;
                        }
                    } else {
                        if kick_off_status.as_ref().unwrap().block_height.is_some_and(
                            |block_height| {
                                block_height + NUM_BLOCKS_PER_2_WEEKS <= blockchain_height
                            },
                        ) {
                            return PegOutOperatorStatus::PegOutTake1Available;
                        } else {
                            return PegOutOperatorStatus::PegOutWait;
                        }
                    }
                } else {
                    return PegOutOperatorStatus::PegOutKickOffAvailable;
                }
            } else {
                return PegOutOperatorStatus::PegOutStartPegOut;
            }
        } else {
            return PegOutOperatorStatus::PegOutWait;
        }
    }

    pub async fn depositor_status(&self, client: &AsyncClient) -> PegOutDepositorStatus {
        if self.peg_out_transaction.is_some() {
            let peg_out_txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid();
            let peg_out_status = client.get_tx_status(&peg_out_txid).await;

            if peg_out_status.is_ok_and(|status| status.confirmed) {
                return PegOutDepositorStatus::PegOutComplete;
            } else {
                return PegOutDepositorStatus::PegOutWait;
            }
        } else {
            return PegOutDepositorStatus::PegOutNotStarted;
        }
    }

    pub async fn kick_off(&mut self, client: &AsyncClient) {
        verify_if_not_mined(&client, self.kick_off_transaction.tx().compute_txid()).await;

        // complete kick_off tx
        let kick_off_tx = self.kick_off_transaction.finalize();

        // broadcast kick_off tx
        let kick_off_result = client.broadcast(&kick_off_tx).await;

        // verify kick_off tx result
        verify_tx_result(&kick_off_result);
    }

    pub async fn challenge(
        &mut self,
        client: &AsyncClient,
        context: &dyn BaseContext,
        crowdfundng_inputs: &Vec<InputWithScript<'_>>,
        keypair: &Keypair,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await;

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
            verify_tx_result(&challenge_result);
        } else {
            panic!("Kick-off tx has not been yet confirmed!");
        }
    }

    pub async fn assert(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.assert_transaction.tx().compute_txid()).await;

        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        if kick_off_status.is_ok_and(|status| status.confirmed) {
            // complete assert tx
            // TODO: commit ZK computation result
            let assert_tx = self.assert_transaction.finalize();

            // broadcast assert tx
            let assert_result = client.broadcast(&assert_tx).await;

            // verify assert tx result
            verify_tx_result(&assert_result);
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
        verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await;

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
            verify_tx_result(&disprove_result);
        } else {
            panic!("Assert tx has not been yet confirmed!");
        }
    }

    pub async fn burn(&mut self, client: &AsyncClient, output_script_pubkey: ScriptBuf) {
        verify_if_not_mined(client, self.burn_transaction.tx().compute_txid()).await;

        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        let blockchain_height = get_block_height(client).await;

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
                verify_tx_result(&burn_result);
            } else {
                panic!("Kick-off timelock has not yet elapsed!");
            }
        } else {
            panic!("Kick-off tx has not been yet confirmed!");
        }
    }

    pub async fn take1(&mut self, client: &AsyncClient) {
        verify_if_not_mined(&client, self.take1_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.challenge_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.assert_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.burn_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;
        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        let blockchain_height = get_block_height(client).await;

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
                verify_tx_result(&take1_result);
            } else {
                panic!("Kick-off tx timelock has not yet elapsed!");
            }
        } else {
            panic!("Neither peg-in confirm tx nor kick-off tx has not been yet confirmed!");
        }
    }

    pub async fn take2(&mut self, client: &AsyncClient) {
        verify_if_not_mined(&client, self.take2_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.take1_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.disprove_transaction.tx().compute_txid()).await;
        verify_if_not_mined(&client, self.burn_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;
        let assert_txid = self.assert_transaction.tx().compute_txid();
        let assert_status = client.get_tx_status(&assert_txid).await;

        let blockchain_height = get_block_height(client).await;

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
                verify_tx_result(&take2_result);
            } else {
                panic!("Assert tx timelock has not yet elapsed!");
            }
        } else {
            panic!("Neither peg-in confirm tx nor assert tx has not been yet confirmed!");
        }
    }

    async fn get_peg_out_statuses(
        &self,
        client: &AsyncClient,
    ) -> (
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Option<Result<TxStatus, Error>>,
    ) {
        let kick_off_status = client
            .get_tx_status(&self.kick_off_transaction.tx().compute_txid())
            .await;
        let challenge_status = client
            .get_tx_status(&self.challenge_transaction.tx().compute_txid())
            .await;
        let assert_status = client
            .get_tx_status(&self.assert_transaction.tx().compute_txid())
            .await;
        let disprove_status = client
            .get_tx_status(&self.disprove_transaction.tx().compute_txid())
            .await;
        let burn_status = client
            .get_tx_status(&self.burn_transaction.tx().compute_txid())
            .await;
        let take1_status = client
            .get_tx_status(&self.take1_transaction.tx().compute_txid())
            .await;
        let take2_status = client
            .get_tx_status(&self.take2_transaction.tx().compute_txid())
            .await;

        let mut peg_out_status: Option<Result<TxStatus, Error>> = None;
        if self.peg_out_transaction.is_some() {
            peg_out_status = Some(
                client
                    .get_tx_status(&self.take2_transaction.tx().compute_txid())
                    .await,
            );
        }

        return (
            kick_off_status,
            challenge_status,
            assert_status,
            disprove_status,
            burn_status,
            take1_status,
            take2_status,
            peg_out_status,
        );
    }
}

pub fn generate_id(peg_in_graph: &PegInGraph, operator_public_key: &PublicKey) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_graph.id().to_string() + &operator_public_key.to_string());

    hasher.finalize().to_hex_string(Upper)
}
