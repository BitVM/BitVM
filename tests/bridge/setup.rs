use bitcoin::Network;

use bitvm::bridge::{
    client::BitVMClient,
    connectors::{
        connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
        connector_3::Connector3, connector_a::ConnectorA, connector_b::ConnectorB,
        connector_c::ConnectorC, connector_z::ConnectorZ,
    },
    contexts::{
        base::generate_keys_from_secret, depositor::DepositorContext, operator::OperatorContext,
        verifier::VerifierContext, withdrawer::WithdrawerContext,
    },
    graphs::base::{
        DEPOSITOR_SECRET, EVM_ADDRESS, N_OF_N_SECRET, OPERATOR_SECRET, WITHDRAWER_SECRET,
    },
};

pub fn setup_test() -> (
    BitVMClient,
    DepositorContext,
    OperatorContext,
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
) {
    let network = Network::Testnet;

    let depositor_keys = generate_keys_from_secret(network, DEPOSITOR_SECRET);
    let operator_keys = generate_keys_from_secret(network, OPERATOR_SECRET);
    let verifier_keys = generate_keys_from_secret(network, N_OF_N_SECRET);
    let withdrawer_keys = generate_keys_from_secret(network, WITHDRAWER_SECRET);

    let depositor_context = DepositorContext::new(
        network,
        DEPOSITOR_SECRET,
        &verifier_keys.2,
        &verifier_keys.3,
    );
    let operator_context =
        OperatorContext::new(network, OPERATOR_SECRET, &verifier_keys.2, &verifier_keys.3);
    let verifier_context =
        VerifierContext::new(network, N_OF_N_SECRET, &operator_keys.2, &operator_keys.3);
    let withdrawer_context = WithdrawerContext::new(
        network,
        WITHDRAWER_SECRET,
        &verifier_keys.2,
        &verifier_keys.3,
    );

    let client = BitVMClient::new(
        network,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(N_OF_N_SECRET),
        Some(WITHDRAWER_SECRET),
    );

    let connector_a = ConnectorA::new(
        network,
        &operator_context.operator_taproot_public_key,
        &verifier_context.n_of_n_taproot_public_key,
    );
    let connector_b = ConnectorB::new(network, &verifier_context.n_of_n_taproot_public_key);
    let connector_c = ConnectorC::new(network, &verifier_context.n_of_n_taproot_public_key);
    let connector_z = ConnectorZ::new(
        network,
        EVM_ADDRESS,
        &depositor_context.depositor_taproot_public_key,
        &verifier_context.n_of_n_taproot_public_key,
    );
    let connector_0 = Connector0::new(network, &verifier_context.n_of_n_public_key);
    let connector_1 = Connector1::new(network, &operator_context.operator_public_key);
    let connector_2 = Connector2::new(network, &operator_context.operator_public_key);
    let connector_3 = Connector3::new(network, &verifier_context.n_of_n_public_key);

    return (
        client,
        depositor_context,
        operator_context,
        verifier_context,
        withdrawer_context,
        connector_a,
        connector_b,
        connector_c,
        connector_z,
        connector_0,
        connector_1,
        connector_2,
        connector_3,
        EVM_ADDRESS.to_string(),
    );
}
