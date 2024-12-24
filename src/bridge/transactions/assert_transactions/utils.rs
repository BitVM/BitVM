use serde::{Deserialize, Serialize};
use std::borrow::BorrowMut;

use crate::bridge::connectors::{
    connector_e::ConnectorE, connector_f_1::ConnectorF1, connector_f_2::ConnectorF2,
};

/// The number of connector e is related to the number of intermediate values.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommit1ConnectorsE {
    pub connectors_e: Vec<ConnectorE>,
}

impl AssertCommit1ConnectorsE {
    pub fn connectors_num(&self) -> usize {
        self.connectors_e.len()
    }

    pub fn get_connector_e(&self, idx: usize) -> &ConnectorE {
        &self.connectors_e[idx]
    }
}

/// The number of connector e is related to the number of intermediate values.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommit2ConnectorsE {
    pub connectors_e: Vec<ConnectorE>,
}

impl AssertCommit2ConnectorsE {
    pub fn connectors_num(&self) -> usize {
        self.connectors_e.len()
    }

    pub fn get_connector_e(&self, idx: usize) -> &ConnectorE {
        &self.connectors_e[idx]
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitConnectorsF {
    pub connector_f_1: ConnectorF1,
    pub connector_f_2: ConnectorF2,
}
