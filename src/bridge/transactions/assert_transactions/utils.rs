use serde::{Deserialize, Serialize};

use crate::bridge::connectors::{
    connector_e_1::ConnectorE1, connector_e_2::ConnectorE2, connector_e_3::ConnectorE3,
    connector_e_4::ConnectorE4, connector_e_5::ConnectorE5,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitConnectors {
    pub connector_e_1: ConnectorE1,
    pub connector_e_2: ConnectorE2,
    pub connector_e_3: ConnectorE3,
    pub connector_e_4: ConnectorE4,
    pub connector_e_5: ConnectorE5,
}
