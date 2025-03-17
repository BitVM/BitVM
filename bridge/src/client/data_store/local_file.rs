use crate::{
    error::err_to_string,
    utils::{compress, decompress, DEFAULT_COMPRESSION_LEVEL},
};

use super::base::DataStoreDriver;
use async_trait::async_trait;
use dotenv;

pub const TEST_DATA_DIRECTORY_NAME: &str = "test_data";
const DATA_STORE_DIRECTORY_NAME: &str = "shared_file_store";
// To use this data store, create a .env file in the base directory with the following values:
// export BRIDGE_USE_LOCAL_FILE_DATA_STORE=true
// This data store driver will only be used in testing, DO NOT use in production
pub struct LocalFile {
    base_path: std::path::PathBuf,
}

impl LocalFile {
    pub fn new() -> Option<Self> {
        dotenv::dotenv().ok();
        let env_var = dotenv::var("BRIDGE_USE_LOCAL_FILE_DATA_STORE");

        if env_var.is_err()
            || env_var.is_ok_and(|v| {
                let flag = v.parse::<bool>();
                flag.is_err() || !flag.is_ok_and(|f| f)
            })
        {
            return None;
        } else if !cfg!(debug_assertions) {
            println!("Disabling local file data store in release mode, please remove BRIDGE_USE_LOCAL_FILE_DATA_STORE or set it to false in .env");
            return None;
        }

        let base_path =
            std::path::Path::new(TEST_DATA_DIRECTORY_NAME).join(DATA_STORE_DIRECTORY_NAME);
        if !base_path.exists() {
            if let Err(e) = std::fs::create_dir_all(&base_path) {
                eprintln!("Failed to create shared file store base path: {e}");
                return None;
            }
        }

        Some(Self { base_path })
    }

    async fn get_object(
        &self,
        file_name: &str,
        file_path: Option<&str>,
    ) -> std::io::Result<Vec<u8>> {
        let path = match file_path {
            Some(file_path) => self.base_path.join(file_path).join(file_name),
            None => self.base_path.join(file_name),
        };

        std::fs::read(path)
    }

    async fn upload_object(
        &self,
        file_name: &str,
        data: Vec<u8>,
        file_path: Option<&str>,
    ) -> std::io::Result<()> {
        let path = match file_path {
            Some(file_path) => self.base_path.join(file_path).join(file_name),
            None => self.base_path.join(file_name),
        };
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        std::fs::write(path, data)
    }
}

#[async_trait]
impl DataStoreDriver for LocalFile {
    async fn list_objects(&self, file_path: Option<&str>) -> Result<Vec<String>, String> {
        let path = match file_path {
            Some(file_path) => self.base_path.join(file_path),
            None => self.base_path.clone(),
        };
        if !path.exists() {
            std::fs::create_dir_all(&path).map_err(err_to_string)?;
        }
        let paths = std::fs::read_dir(path).unwrap();

        Ok(paths
            .filter_map(|path| {
                path.ok()
                    .filter(|path| path.path().is_file())
                    .map(|p| p.path().to_string_lossy().to_string())
            })
            .collect())
    }

    async fn fetch_object(
        &self,
        file_name: &str,
        file_path: Option<&str>,
    ) -> Result<String, String> {
        let response = self.get_object(file_name, file_path).await;
        match response {
            Ok(buffer) => {
                let json = String::from_utf8(buffer);
                match json {
                    Ok(json) => Ok(json),
                    Err(err) => Err(format!("Failed to parse json: {}", err)),
                }
            }
            Err(err) => Err(format!("Failed to get json file: {}", err)),
        }
    }

    async fn upload_object(
        &self,
        file_name: &str,
        contents: &str,
        file_path: Option<&str>,
    ) -> Result<usize, String> {
        let size = contents.len();
        let data = contents.as_bytes().to_vec();

        match self.upload_object(file_name, data, file_path).await {
            Ok(_) => Ok(size),
            Err(err) => Err(format!("Failed to save json file: {}", err)),
        }
    }

    async fn fetch_compressed_object(
        &self,
        file_name: &str,
        file_path: Option<&str>,
    ) -> Result<(Vec<u8>, usize), String> {
        let response = self.get_object(file_name, file_path).await;
        match response {
            Ok(buffer) => {
                let size = buffer.len();
                Ok((decompress(&buffer).map_err(err_to_string)?, size))
            }
            Err(err) => Err(format!("Failed to get json file: {}", err)),
        }
    }

    async fn upload_compressed_object(
        &self,
        file_name: &str,
        contents: &Vec<u8>,
        file_path: Option<&str>,
    ) -> Result<usize, String> {
        let compressed_data =
            compress(contents, DEFAULT_COMPRESSION_LEVEL).map_err(err_to_string)?;
        let size = compressed_data.len();

        match self
            .upload_object(file_name, compressed_data, file_path)
            .await
        {
            Ok(_) => Ok(size),
            Err(err) => Err(format!("Failed to save json file: {}", err)),
        }
    }
}
