use super::{
    super::base::DataStoreDriver,
    lib::{self, FtpCredentials},
};
use async_trait::async_trait;
use dotenv;

// To use this data store, create a .env file in the base directory with the following values:
// export BRIDGE_FTPS_HOST="..."
// export BRIDGE_FTPS_PORT="..."
// export BRIDGE_FTPS_USERNAME="..."
// export BRIDGE_FTPS_PASSWORD="..."
// export BRIDGE_FTPS_BASE_PATH="..."

// NOTE: BRIDGE_FTPS_HOST should be a domain that supports SSL

pub struct Ftps {
    credentials: lib::FtpCredentials,
}

impl Ftps {
    pub async fn new() -> Option<Self> {
        dotenv::dotenv().ok();
        let host = dotenv::var("BRIDGE_FTPS_HOST");
        let port = dotenv::var("BRIDGE_FTPS_PORT");
        let username = dotenv::var("BRIDGE_FTPS_USERNAME");
        let password = dotenv::var("BRIDGE_FTPS_PASSWORD");
        let base_path = dotenv::var("BRIDGE_FTPS_BASE_PATH");

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

        match lib::test_connection(&credentials).await {
            Ok(_) => Some(Self { credentials }),
            Err(err) => {
                eprintln!("{err:?}");
                None
            }
        }
    }
}

#[async_trait]
impl DataStoreDriver for Ftps {
    async fn list_objects(&self, file_path: Option<&str>) -> Result<Vec<String>, String> {
        lib::list_objects(&self.credentials, file_path).await
    }

    async fn fetch_object(
        &self,
        file_name: &str,
        file_path: Option<&str>,
    ) -> Result<String, String> {
        lib::fetch_object(&self.credentials, file_name, file_path).await
    }

    async fn upload_object(
        &self,
        file_name: &str,
        contents: &str,
        file_path: Option<&str>,
    ) -> Result<usize, String> {
        lib::upload_object(&self.credentials, file_name, contents, file_path).await
    }

    async fn fetch_compressed_object(
        &self,
        file_name: &str,
        file_path: Option<&str>,
    ) -> Result<(Vec<u8>, usize), String> {
        lib::fetch_compressed_object(&self.credentials, file_name, file_path).await
    }

    async fn upload_compressed_object(
        &self,
        file_name: &str,
        contents: &Vec<u8>,
        file_path: Option<&str>,
    ) -> Result<usize, String> {
        lib::upload_compressed_object(&self.credentials, file_name, contents, file_path).await
    }
}
