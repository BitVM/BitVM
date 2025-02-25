use bitcoin::{Address, Amount, OutPoint};
use bridge::{
    connectors::{base::TaprootConnector, connector_c::get_commit_from_assert_commit_tx},
    graphs::base::DUST_AMOUNT,
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        assert_transactions::{
            assert_commit_1::AssertCommit1Transaction, assert_commit_2::AssertCommit2Transaction,
            assert_final::AssertFinalTransaction, utils::sign_assert_tx_with_groth16_proof,
        },
        base::{
            BaseTransaction, Input, MIN_RELAY_FEE_ASSERT_COMMIT1, MIN_RELAY_FEE_ASSERT_COMMIT2,
            MIN_RELAY_FEE_ASSERT_FINAL, MIN_RELAY_FEE_ASSERT_INITIAL, MIN_RELAY_FEE_DISPROVE,
            MIN_RELAY_FEE_KICK_OFF_2,
        },
        disprove::DisproveTransaction,
        pre_signed::PreSignedTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};
use num_traits::ToPrimitive;

use crate::bridge::{
    assert::helper::create_and_mine_assert_initial_tx,
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, verify_funding_inputs, wait_for_timelock_expiry},
    integration::peg_out::utils::create_and_mine_kick_off_2_tx,
    setup::{setup_test_full, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_disprove_success() {
    // TODO: remove lock script cache
    //       OR refactor setup_test to generate lock scripts for connector c
    //       to prevent mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) error
    //       OR verify if making the wrong proof deterministic addresses the issue.
    let config = setup_test_full().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_2_input_amount = Amount::from_sat(
        INITIAL_AMOUNT
            + MIN_RELAY_FEE_KICK_OFF_2
            + DUST_AMOUNT // connector 3 to take 1
            + MIN_RELAY_FEE_ASSERT_INITIAL
            + MIN_RELAY_FEE_ASSERT_COMMIT1
            + MIN_RELAY_FEE_ASSERT_COMMIT2
            + MIN_RELAY_FEE_ASSERT_FINAL
            + DUST_AMOUNT // connector 4 to take 2
            + MIN_RELAY_FEE_DISPROVE,
    );
    let kick_off_2_funding_utxo_address = config.connector_1.generate_taproot_address();
    funding_inputs.push((&kick_off_2_funding_utxo_address, kick_off_2_input_amount));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    // kick-off 2
    let (kick_off_2_tx, kick_off_2_txid) = create_and_mine_kick_off_2_tx(
        &config.client_0,
        &config.operator_context,
        &config.connector_1,
        &config.connector_b,
        &kick_off_2_funding_utxo_address,
        kick_off_2_input_amount,
        &config.commitment_secrets,
    )
    .await;

    // assert initial
    let vout = 1; // connector B
    let assert_initial_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };

    let (assert_initial_tx, assert_initial_txid) = create_and_mine_assert_initial_tx(
        &config.client_0.esplora,
        config.network,
        &config.verifier_0_context,
        &config.verifier_1_context,
        &config.connector_b,
        &config.connector_d,
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_e_2,
        assert_initial_input_0,
    )
    .await;

    // gen incorrect proof and witness
    let (witness_for_commit1, witness_for_commit2) =
        sign_assert_tx_with_groth16_proof(&config.commitment_secrets, &config.invalid_proof);

    // assert commit 1
    let mut vout_base = 1; // connector E
    let mut assert_commit_1 = AssertCommit1Transaction::new(
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_f.connector_f_1,
        (0..config.assert_commit_connectors_e_1.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: (idx + vout_base).to_u32().unwrap(),
                },
                amount: assert_initial_tx.output[idx + vout_base].value,
            })
            .collect(),
    );
    assert_commit_1.sign(
        &config.assert_commit_connectors_e_1,
        witness_for_commit1.clone(),
    );
    let assert_commit_1_tx = assert_commit_1.finalize();
    let assert_commit_1_txid = assert_commit_1_tx.compute_txid();
    println!(
        "txid: {}, assert_commit_1_tx inputs {}, outputs {}",
        assert_commit_1_txid,
        assert_commit_1.tx().input.len(),
        assert_commit_1.tx().output.len()
    );
    let assert_commit_1_result = config.client_0.esplora.broadcast(&assert_commit_1_tx).await;
    assert!(
        assert_commit_1_result.is_ok(),
        "error: {:?}",
        assert_commit_1_result.err()
    );

    // assert commit 2
    vout_base += config.assert_commit_connectors_e_1.connectors_num(); // connector E

    let mut assert_commit_2 = AssertCommit2Transaction::new(
        &config.assert_commit_connectors_e_2,
        &config.assert_commit_connectors_f.connector_f_2,
        (0..config.assert_commit_connectors_e_2.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: (idx + vout_base).to_u32().unwrap(),
                },
                amount: assert_initial_tx.output[idx + vout_base].value,
            })
            .collect(),
    );
    assert_commit_2.sign(
        &config.assert_commit_connectors_e_2,
        witness_for_commit2.clone(),
    );
    let assert_commit_2_tx = assert_commit_2.finalize();
    let assert_commit_2_txid = assert_commit_2_tx.compute_txid();
    println!(
        "txid: {}, assert_commit_2_tx inputs {}, outputs {}",
        assert_commit_2_txid,
        assert_commit_2.tx().input.len(),
        assert_commit_2.tx().output.len()
    );
    let assert_commit_2_result = config.client_0.esplora.broadcast(&assert_commit_2_tx).await;
    assert!(
        assert_commit_2_result.is_ok(),
        "error: {:?}",
        assert_commit_2_result.err()
    );

    // assert final
    let vout_0 = 0; // connector D
    let vout_1 = 0; // connector F
    let vout_2 = 0; // connector F
    let assert_final_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout: vout_0,
        },
        amount: assert_initial_tx.output[vout_0 as usize].value,
    };
    let assert_final_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_commit_1_txid,
            vout: vout_1,
        },
        amount: assert_commit_1_tx.output[vout_1 as usize].value,
    };
    let assert_final_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_commit_2_txid,
            vout: vout_2,
        },
        amount: assert_commit_2_tx.output[vout_2 as usize].value,
    };
    let mut assert_final = AssertFinalTransaction::new(
        &config.operator_context,
        &config.connector_4,
        &config.connector_5,
        &config.connector_c,
        &config.connector_d,
        &config.assert_commit_connectors_f,
        assert_final_input_0,
        assert_final_input_1,
        assert_final_input_2,
    );

    let secret_nonces_0 = assert_final.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_final.push_nonces(&config.verifier_1_context);

    assert_final.pre_sign(
        &config.verifier_0_context,
        &config.connector_d,
        &secret_nonces_0,
    );
    assert_final.pre_sign(
        &config.verifier_1_context,
        &config.connector_d,
        &secret_nonces_1,
    );

    let assert_final_tx = assert_final.finalize();
    let assert_final_txid = assert_final_tx.compute_txid();
    let assert_final_result = config.client_0.esplora.broadcast(&assert_final_tx).await;
    assert!(
        assert_final_result.is_ok(),
        "error: {:?}",
        assert_final_result.err()
    );

    // disprove
    let vout = 1;

    // get witness from assert_commit txs
    let assert_commit_1_witness = get_commit_from_assert_commit_tx(&assert_commit_1_tx);
    let assert_commit_2_witness = get_commit_from_assert_commit_tx(&assert_commit_2_tx);

    let (script_index, disprove_witness) = config
        .connector_c
        .generate_disprove_witness(
            assert_commit_1_witness,
            assert_commit_2_witness,
            &config.invalid_proof.vk,
        )
        .unwrap();
    // let script_index = 1;

    let disprove_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout,
        },
        amount: assert_final_tx.output[vout as usize].value,
    };

    let vout = 2;
    let disprove_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout,
        },
        amount: assert_final_tx.output[vout as usize].value,
    };

    let mut disprove = DisproveTransaction::new(
        &config.operator_context,
        &config.connector_5,
        &config.connector_c,
        disprove_input_0,
        disprove_input_1,
    );

    let secret_nonces_0 = disprove.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove.push_nonces(&config.verifier_1_context);

    disprove.pre_sign(
        &config.verifier_0_context,
        &config.connector_5,
        &secret_nonces_0,
    );
    disprove.pre_sign(
        &config.verifier_1_context,
        &config.connector_5,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove.add_input_output(
        &config.connector_c,
        script_index as u32,
        disprove_witness,
        verifier_reward_script,
    );

    let disprove_tx = disprove.finalize();
    let disprove_txid = disprove_tx.compute_txid();

    // mine disprove
    check_tx_output_sum(INITIAL_AMOUNT, &disprove_tx);
    wait_for_timelock_expiry(config.network, Some("Assert connector 4")).await;
    let disprove_result = config.client_0.esplora.broadcast(&disprove_tx).await;
    println!("Disprove tx result: {disprove_result:?}");
    assert!(disprove_result.is_ok());

    // reward balance
    let reward_utxos = config
        .client_0
        .esplora
        .get_address_utxo(reward_address)
        .await
        .unwrap();
    let reward_utxo = reward_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == disprove_txid);

    // assert
    assert!(reward_utxo.is_some());
    assert_eq!(reward_utxo.unwrap().value, disprove_tx.output[1].value);
}
