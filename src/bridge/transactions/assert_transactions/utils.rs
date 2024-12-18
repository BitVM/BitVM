use serde::{Deserialize, Serialize};

use crate::bridge::connectors::{
    connector_e_1::ConnectorE1, connector_e_2::ConnectorE2, connector_e_3::ConnectorE3,
    connector_e_4::ConnectorE4, connector_e_5::ConnectorE5, connector_f_1::ConnectorF1,
    connector_f_2::ConnectorF2, connector_f_3::ConnectorF3, connector_f_4::ConnectorF4,
    connector_f_5::ConnectorF5,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitConnectorsE {
    pub connector_e_1: ConnectorE1,
    pub connector_e_2: ConnectorE2,
    pub connector_e_3: ConnectorE3,
    pub connector_e_4: ConnectorE4,
    pub connector_e_5: ConnectorE5,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitConnectorsF {
    pub connector_f_1: ConnectorF1,
    pub connector_f_2: ConnectorF2,
    pub connector_f_3: ConnectorF3,
    pub connector_f_4: ConnectorF4,
    pub connector_f_5: ConnectorF5,
}
