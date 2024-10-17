use std::collections::HashMap;

use bitcoin::{Network, PublicKey};

use bitvm::bridge::{
    client::client::BitVMClient,
    connectors::{
        connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
        connector_3::Connector3, connector_4::Connector4, connector_5::Connector5,
        connector_6::Connector6, connector_a::ConnectorA, connector_b::ConnectorB,
        connector_c::ConnectorC, connector_z::ConnectorZ,
    },
    constants::DestinationNetwork,
    contexts::{
        base::generate_keys_from_secret, depositor::DepositorContext, operator::OperatorContext,
        verifier::VerifierContext, withdrawer::WithdrawerContext,
    },
    graphs::base::{
        DEPOSITOR_EVM_ADDRESS, DEPOSITOR_SECRET, OPERATOR_SECRET, VERIFIER_0_SECRET,
        VERIFIER_1_SECRET, WITHDRAWER_EVM_ADDRESS, WITHDRAWER_SECRET,
    },
    transactions::signing_winternitz::{
        winternitz_public_key_from_secret, WinternitzPublicKey, WinternitzSecret,
    },
};

pub struct SetupConfig {
    pub client_0: BitVMClient,
    pub client_1: BitVMClient,
    pub depositor_context: DepositorContext,
    pub operator_context: OperatorContext,
    pub verifier_0_context: VerifierContext,
    pub verifier_1_context: VerifierContext,
    pub withdrawer_context: WithdrawerContext,
    pub connector_a: ConnectorA,
    pub connector_b: ConnectorB,
    pub connector_c: ConnectorC,
    pub connector_z: ConnectorZ,
    pub connector_0: Connector0,
    pub connector_1: Connector1,
    pub connector_2: Connector2,
    pub connector_3: Connector3,
    pub connector_4: Connector4,
    pub connector_5: Connector5,
    pub connector_6: Connector6,
    pub depositor_evm_address: String,
    pub withdrawer_evm_address: String,
    pub connector_1_winternitz_secrets: HashMap<u8, WinternitzSecret>,
    pub connector_2_winternitz_secrets: HashMap<u8, WinternitzSecret>,
    pub connector_6_winternitz_secrets: HashMap<u8, WinternitzSecret>,
}

pub async fn setup_test() -> SetupConfig {
    let source_network = Network::Testnet;
    let destination_network = DestinationNetwork::EthereumSepolia;

    let (_, _, verifier_0_public_key) =
        generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, _, verifier_1_public_key) =
        generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);

    let depositor_context =
        DepositorContext::new(source_network, DEPOSITOR_SECRET, &n_of_n_public_keys);
    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);
    let verifier_0_context =
        VerifierContext::new(source_network, VERIFIER_0_SECRET, &n_of_n_public_keys);
    let verifier_1_context =
        VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);
    let withdrawer_context =
        WithdrawerContext::new(source_network, WITHDRAWER_SECRET, &n_of_n_public_keys);

    let client_0 = BitVMClient::new(
        source_network,
        destination_network,
        &n_of_n_public_keys,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(VERIFIER_0_SECRET),
        Some(WITHDRAWER_SECRET),
        None,
    )
    .await;

    let client_1 = BitVMClient::new(
        source_network,
        destination_network,
        &n_of_n_public_keys,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(VERIFIER_1_SECRET),
        Some(WITHDRAWER_SECRET),
        None,
    )
    .await;

    let connector_a = ConnectorA::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_b = ConnectorB::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_c = ConnectorC::new(
        source_network,
        &operator_context.operator_taproot_public_key,
    );
    let connector_z = ConnectorZ::new(
        source_network,
        DEPOSITOR_EVM_ADDRESS,
        &depositor_context.depositor_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_0 = Connector0::new(source_network, &operator_context.n_of_n_taproot_public_key);

    let (mut connector_1, _) = Connector1::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let (mut connector_2, _) = Connector2::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_3 = Connector3::new(source_network, &operator_context.operator_public_key);
    let connector_4 = Connector4::new(source_network, &operator_context.operator_public_key);
    let connector_5 = Connector5::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let (mut connector_6, _) = Connector6::new(
        source_network,
        &operator_context.operator_taproot_public_key,
    );

    // Swap out Winternitz secrets for testing.
    let (connector_1_winternitz_secrets, connector_1_winternitz_public_keys) =
        get_test_winternitz_keys(&[0]);
    let (connector_2_winternitz_secrets, connector_2_winternitz_public_keys) =
        get_test_winternitz_keys(&[0]);
    let (connector_6_winternitz_secrets, connector_6_winternitz_public_keys) =
        get_test_winternitz_keys(&[0]);
    connector_1.winternitz_public_keys = connector_1_winternitz_public_keys;
    connector_2.winternitz_public_keys = connector_2_winternitz_public_keys;
    connector_6.winternitz_public_keys = connector_6_winternitz_public_keys;

    return SetupConfig {
        client_0,
        client_1,
        depositor_context,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        withdrawer_context,
        connector_a,
        connector_b,
        connector_c,
        connector_z,
        connector_0,
        connector_1,
        connector_2,
        connector_3,
        connector_4,
        connector_5,
        connector_6,
        depositor_evm_address: DEPOSITOR_EVM_ADDRESS.to_string(),
        withdrawer_evm_address: WITHDRAWER_EVM_ADDRESS.to_string(),
        connector_1_winternitz_secrets,
        connector_2_winternitz_secrets,
        connector_6_winternitz_secrets,
    };
}

// Use fixed secrets for testing to ensure repeatable tx output addresses.
// The keys in the returned hash maps are the leaf indexes.
fn get_test_winternitz_keys(
    leaf_indexes: &[u8],
) -> (
    HashMap<u8, WinternitzSecret>,
    HashMap<u8, WinternitzPublicKey>,
) {
    let winternitz_secrets: HashMap<u8, WinternitzSecret> = leaf_indexes
        .iter()
        .map(|leaf_index| (*leaf_index, generate_test_winternitz_secret(leaf_index)))
        .collect();

    let winternitz_public_keys: HashMap<u8, WinternitzPublicKey> = winternitz_secrets
        .iter()
        .map(|(&k, v)| (k, winternitz_public_key_from_secret(&v)))
        .collect();

    (winternitz_secrets, winternitz_public_keys)
}

fn generate_test_winternitz_secret(leaf_index: &u8) -> String {
    format!("b138982ce17ac813d505b5b40b665d404e9528{:02x}", leaf_index)
}
