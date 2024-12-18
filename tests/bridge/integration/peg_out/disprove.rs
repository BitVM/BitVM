use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        assert_transactions::{
            assert_commit_1::AssertCommit1Transaction, assert_commit_2::AssertCommit2Transaction,
            assert_commit_3::AssertCommit3Transaction, assert_commit_4::AssertCommit4Transaction,
            assert_commit_5::AssertCommit5Transaction, assert_final::AssertFinalTransaction,
            assert_initial::AssertInitialTransaction,
        },
        base::{BaseTransaction, Input},
        disprove::DisproveTransaction,
        kick_off_2::MIN_RELAY_FEE_AMOUNT,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::verify_funding_inputs,
    integration::peg_out::utils::create_and_mine_kick_off_2_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_disprove_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_2_input_amount =
        Amount::from_sat(INITIAL_AMOUNT + 7 * FEE_AMOUNT + MIN_RELAY_FEE_AMOUNT + 13 * DUST_AMOUNT);
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
    let mut assert_initial = AssertInitialTransaction::new(
        &config.connector_b,
        &config.connector_d,
        &config.assert_commit_connectors,
        assert_initial_input_0,
    );

    let secret_nonces_0 = assert_initial.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_initial.push_nonces(&config.verifier_1_context);

    assert_initial.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    assert_initial.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let assert_initial_tx = assert_initial.finalize();
    let assert_initial_txid = assert_initial_tx.compute_txid();
    let assert_initial_result = config.client_0.esplora.broadcast(&assert_initial_tx).await;
    assert!(assert_initial_result.is_ok());

    // assert commit 1
    let vout = 1; // connector E
    let assert_commit_1_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout,
        },
        amount: assert_initial_tx.output[vout as usize].value,
    };
    let assert_commit_1 = AssertCommit1Transaction::new(
        &config.operator_context,
        &config.assert_commit_connectors.connector_e_1,
        assert_commit_1_input_0,
    );
    let assert_commit_1_tx = assert_commit_1.finalize();
    let assert_commit_1_txid = assert_commit_1_tx.compute_txid();
    let assert_commit_1_result = config.client_0.esplora.broadcast(&assert_commit_1_tx).await;
    assert!(assert_commit_1_result.is_ok());

    // assert commit 2
    let vout = 2; // connector E
    let assert_commit_2_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout,
        },
        amount: assert_initial_tx.output[vout as usize].value,
    };
    let assert_commit_2 = AssertCommit2Transaction::new(
        &config.operator_context,
        &config.assert_commit_connectors.connector_e_2,
        assert_commit_2_input_0,
    );
    let assert_commit_2_tx = assert_commit_2.finalize();
    let assert_commit_2_txid = assert_commit_2_tx.compute_txid();
    let assert_commit_2_result = config.client_0.esplora.broadcast(&assert_commit_2_tx).await;
    assert!(assert_commit_2_result.is_ok());

    // assert commit 3
    let vout = 3; // connector E
    let assert_commit_3_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout,
        },
        amount: assert_initial_tx.output[vout as usize].value,
    };
    let assert_commit_3 = AssertCommit3Transaction::new(
        &config.operator_context,
        &config.assert_commit_connectors.connector_e_3,
        assert_commit_3_input_0,
    );
    let assert_commit_3_tx = assert_commit_3.finalize();
    let assert_commit_3_txid = assert_commit_3_tx.compute_txid();
    let assert_commit_3_result = config.client_0.esplora.broadcast(&assert_commit_3_tx).await;
    assert!(assert_commit_3_result.is_ok());

    // assert commit 4
    let vout = 4; // connector E
    let assert_commit_4_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout,
        },
        amount: assert_initial_tx.output[vout as usize].value,
    };
    let assert_commit_4 = AssertCommit4Transaction::new(
        &config.operator_context,
        &config.assert_commit_connectors.connector_e_4,
        assert_commit_4_input_0,
    );
    let assert_commit_4_tx = assert_commit_4.finalize();
    let assert_commit_4_txid = assert_commit_4_tx.compute_txid();
    let assert_commit_4_result = config.client_0.esplora.broadcast(&assert_commit_4_tx).await;
    assert!(assert_commit_4_result.is_ok());

    // assert commit 5
    let vout = 5; // connector E
    let assert_commit_5_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout,
        },
        amount: assert_initial_tx.output[vout as usize].value,
    };
    let assert_commit_5 = AssertCommit5Transaction::new(
        &config.operator_context,
        &config.assert_commit_connectors.connector_e_5,
        assert_commit_5_input_0,
    );
    let assert_commit_5_tx = assert_commit_5.finalize();
    let assert_commit_5_txid = assert_commit_5_tx.compute_txid();
    let assert_commit_5_result = config.client_0.esplora.broadcast(&assert_commit_5_tx).await;
    assert!(assert_commit_5_result.is_ok());

    // assert final
    let vout_0 = 0; // connector D
    let vout_1 = 0; // connector E
    let vout_2 = 0; // connector E
    let vout_3 = 0; // connector E
    let vout_4 = 0; // connector E
    let vout_5 = 0; // connector E
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
    let assert_final_input_3 = Input {
        outpoint: OutPoint {
            txid: assert_commit_3_txid,
            vout: vout_3,
        },
        amount: assert_commit_3_tx.output[vout_3 as usize].value,
    };
    let assert_final_input_4 = Input {
        outpoint: OutPoint {
            txid: assert_commit_4_txid,
            vout: vout_4,
        },
        amount: assert_commit_4_tx.output[vout_4 as usize].value,
    };
    let assert_final_input_5 = Input {
        outpoint: OutPoint {
            txid: assert_commit_5_txid,
            vout: vout_5,
        },
        amount: assert_commit_5_tx.output[vout_5 as usize].value,
    };
    let mut assert_final = AssertFinalTransaction::new(
        &config.operator_context,
        &config.connector_4,
        &config.connector_5,
        &config.connector_c,
        &config.connector_d,
        &config.assert_commit_connectors,
        assert_final_input_0,
        assert_final_input_1,
        assert_final_input_2,
        assert_final_input_3,
        assert_final_input_4,
        assert_final_input_5,
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
    assert!(assert_final_result.is_ok());

    // disprove
    let vout = 1;
    let script_index = 1;
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
        script_index,
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
    disprove.add_input_output(&config.connector_c, script_index, verifier_reward_script);

    let disprove_tx = disprove.finalize();
    let disprove_txid = disprove_tx.compute_txid();

    // mine disprove
    let disprove_result = config.client_0.esplora.broadcast(&disprove_tx).await;
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
