use super::{
    super::base::DataStoreDriver,
    lib::{self, FtpCredentials},
};
use async_trait::async_trait;
use dotenv;

// To use this data store, create a .env file in the base directory with the following values:
// export BRIDGE_FTP_HOST="..."
// export BRIDGE_FTP_PORT="..."
// export BRIDGE_FTP_USERNAME="..."
// export BRIDGE_FTP_PASSWORD="..."
// export BRIDGE_FTP_BASE_PATH="..."

pub struct Ftp {
    credentials: lib::FtpCredentials,
}

impl Ftp {
    pub fn new() -> Option<Self> {
        dotenv::dotenv().ok();
        let host = dotenv::var("BRIDGE_FTP_HOST");
        let port = dotenv::var("BRIDGE_FTP_PORT");
        let username = dotenv::var("BRIDGE_FTP_USERNAME");
        let password = dotenv::var("BRIDGE_FTP_PASSWORD");
        let base_path = dotenv::var("BRIDGE_FTP_BASE_PATH");

        if host.is_err()
            || port.is_err()
            || username.is_err()
            || password.is_err()
            || base_path.is_err()
        {
            return None;
        }

        let credentials = FtpCredentials {
            is_secure: false,
            host: host.unwrap(),
            port: port.unwrap(),
            username: username.unwrap(),
            password: password.unwrap(),
            base_path: base_path.unwrap(),
        };

        match lib::test_connection(&credentials) {
            Ok(_) => Some(Self { credentials }),
            Err(err) => {
                eprintln!("{err:?}");
                None
            }
        }
    }
}

#[async_trait]
impl DataStoreDriver for Ftp {
    async fn list_objects(&self) -> Result<Vec<String>, String> {
        lib::list_objects(&self.credentials).await
    }

    async fn fetch_json(&self, key: &str) -> Result<String, String> {
        lib::fetch_json(&self.credentials, key).await
    }

    async fn upload_json(&self, key: &str, json: String) -> Result<usize, String> {
        lib::upload_json(&self.credentials, key, json).await
    }
}
