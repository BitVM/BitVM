use strum::Display;

use serde_json::{json, Value};

#[derive(Display, PartialEq, Eq)]
pub enum ResponseStatus {
    OK,
    NOK(String),
}
pub struct Response {
    pub status: ResponseStatus,
    pub data: Option<Value>,
}

impl Response {
    pub fn new(status: ResponseStatus, data: Option<Value>) -> Self {
        Self { status, data }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self::new(ResponseStatus::NOK("".to_string()), None)
    }

    pub fn flush(&self) {
        println!(">>>> BitVM Query Response <<<<");

        match &self.status {
            ResponseStatus::OK => {
                println!(
                    "{}",
                    json!({
                        "status": "OK",
                        "data": match &self.data {
                            Some(data) => data.clone(),
                            None => json!({}),
                        },
                        "error": "",
                    })
                );
            }
            ResponseStatus::NOK(msg) => {
                println!(
                    "{}",
                    json!({
                        "status": "NOK",
                        "data": "",
                        "error": msg
                    })
                );
            }
        }

        std::process::exit(match self.status {
            ResponseStatus::OK => 0,
            ResponseStatus::NOK(_) => 1,
        });
    }
}
