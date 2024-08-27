use bitcoin::{Network, PublicKey};

use bitvm::bridge::{
    client::client::BitVMClient,
    connectors::{
        connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
        connector_3::Connector3, connector_a::ConnectorA, connector_b::ConnectorB,
        connector_c::ConnectorC, connector_z::ConnectorZ,
    },
    constants::DestinationNetwork,
    contexts::{
        base::generate_keys_from_secret, depositor::DepositorContext, operator::OperatorContext,
        verifier::VerifierContext, withdrawer::WithdrawerContext,
    },
    graphs::base::{
        DEPOSITOR_EVM_ADDRESS, DEPOSITOR_SECRET, OPERATOR_SECRET, VERIFIER0_SECRET,
        VERIFIER1_SECRET, WITHDRAWER_EVM_ADDRESS, WITHDRAWER_SECRET,
    },
};

pub async fn setup_test() -> (
    BitVMClient,
    BitVMClient,
    DepositorContext,
    OperatorContext,
    VerifierContext,
    VerifierContext,
    WithdrawerContext,
    ConnectorA,
    ConnectorB,
    ConnectorC,
    ConnectorZ,
    Connector0,
    Connector1,
    Connector2,
    Connector3,
    String,
    String,
) {
    let source_network = Network::Testnet;
    let destination_network = DestinationNetwork::EthereumSepolia;

    let (_, _, verifier0_public_key) = generate_keys_from_secret(source_network, VERIFIER0_SECRET);
    let (_, _, verifier1_public_key) = generate_keys_from_secret(source_network, VERIFIER1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier0_public_key);
    n_of_n_public_keys.push(verifier1_public_key);

    let depositor_context =
        DepositorContext::new(source_network, DEPOSITOR_SECRET, &n_of_n_public_keys);
    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);

    let verifier0_context =
        VerifierContext::new(source_network, VERIFIER0_SECRET, &n_of_n_public_keys);
    let verifier1_context =
        VerifierContext::new(source_network, VERIFIER1_SECRET, &n_of_n_public_keys);
    let withdrawer_context =
        WithdrawerContext::new(source_network, WITHDRAWER_SECRET, &n_of_n_public_keys);

    let client0 = BitVMClient::new(
        source_network,
        destination_network,
        &n_of_n_public_keys,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(VERIFIER0_SECRET),
        Some(WITHDRAWER_SECRET),
    )
    .await;

    let client1 = BitVMClient::new(
        source_network,
        destination_network,
        &n_of_n_public_keys,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(VERIFIER1_SECRET),
        Some(WITHDRAWER_SECRET),
    )
    .await;

    let connector_a = ConnectorA::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_b = ConnectorB::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_c = ConnectorC::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_z = ConnectorZ::new(
        source_network,
        DEPOSITOR_EVM_ADDRESS,
        &depositor_context.depositor_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_0 = Connector0::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_1 = Connector1::new(source_network, &operator_context.operator_public_key);
    let connector_2 = Connector2::new(source_network, &operator_context.operator_public_key);
    let connector_3 = Connector3::new(source_network, &operator_context.n_of_n_taproot_public_key);

    return (
        client0,
        client1,
        depositor_context,
        operator_context,
        verifier0_context,
        verifier1_context,
        withdrawer_context,
        connector_a,
        connector_b,
        connector_c,
        connector_z,
        connector_0,
        connector_1,
        connector_2,
        connector_3,
        DEPOSITOR_EVM_ADDRESS.to_string(),
        WITHDRAWER_EVM_ADDRESS.to_string(),
    );
}
