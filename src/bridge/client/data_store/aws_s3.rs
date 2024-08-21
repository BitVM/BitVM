use super::base::DataStoreDriver;
use async_trait::async_trait;
use aws_sdk_s3::{
    config::{Credentials, Region},
    error::SdkError,
    operation::put_object::{PutObjectError, PutObjectOutput},
    primitives::ByteStream,
    Client, Config,
};
use dotenv;

// To use this data store, create a .env file in the base directory with the following values:
// export BRIDGE_AWS_ACCESS_KEY_ID="..."
// export BRIDGE_AWS_SECRET_ACCESS_KEY="..."
// export BRIDGE_AWS_REGION="..."
// export BRIDGE_AWS_BUCKET="..."

pub struct AwsS3 {
    client: Client,
    bucket: String,
}

impl AwsS3 {
    pub fn new() -> Option<Self> {
        dotenv::dotenv().ok();
        let access_key = dotenv::var("BRIDGE_AWS_ACCESS_KEY_ID");
        let secret = dotenv::var("BRIDGE_AWS_SECRET_ACCESS_KEY");
        let region = dotenv::var("BRIDGE_AWS_REGION");
        let bucket = dotenv::var("BRIDGE_AWS_BUCKET");

        if access_key.is_err() || secret.is_err() || region.is_err() || bucket.is_err() {
            return None;
        }

        let credentials =
            Credentials::new(access_key.unwrap(), secret.unwrap(), None, None, "Bridge");

        let config = Config::builder()
            .credentials_provider(credentials)
            .region(Region::new(region.unwrap()))
            .behavior_version_latest()
            .build();

        Some(Self {
            client: Client::from_conf(config),
            bucket: bucket.unwrap(),
        })
    }

    async fn get_object(&self, key: &str) -> Result<Vec<u8>, String> {
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;

        match object {
            Ok(mut data) => {
                let mut buffer: Vec<u8> = vec![];
                while let Some(bytes) = data.body.try_next().await.unwrap() {
                    buffer.append(&mut bytes.to_vec());
                }

                Ok(buffer)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn upload_object(
        &self,
        key: &str,
        data: ByteStream,
    ) -> Result<PutObjectOutput, SdkError<PutObjectError>> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(data)
            .send()
            .await
    }
}

#[async_trait]
impl DataStoreDriver for AwsS3 {
    async fn list_objects(&self) -> Result<Vec<String>, String> {
        let mut response = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .max_keys(50) // Paginate 50 results at a time
            .into_paginator()
            .send();

        let mut keys: Vec<String> = vec![];
        while let Some(result) = response.next().await {
            match result {
                Ok(output) => {
                    for object in output.contents() {
                        keys.push(object.key().unwrap_or("Unknown").to_string());
                    }
                }
                Err(err) => {
                    eprintln!("{err:?}");
                    return Err("Unable to list objects".to_string());
                }
            }
        }

        Ok(keys)
    }

    async fn fetch_json(&self, key: &str) -> Result<String, String> {
        let response = self.get_object(key).await;
        match response {
            Ok(buffer) => {
                let json = String::from_utf8(buffer);
                match json {
                    Ok(json) => Ok(json),
                    Err(err) => Err(format!("Failed to parse json: {}", err.to_string())),
                }
            }
            Err(err) => Err(format!("Failed to get json file: {}", err.to_string())),
        }
    }

    async fn upload_json(&self, key: &str, json: String) -> Result<usize, String> {
        let bytes = json.as_bytes().to_vec();
        let size = bytes.len();
        let byte_stream = ByteStream::from(bytes);

        // println!("Writing data file to {} (size: {})", key, size);

        match self.upload_object(&key, byte_stream).await {
            Ok(_) => Ok(size),
            Err(err) => Err(format!("Failed to save json file: {}", err)),
        }
    }
}
