use once_cell::sync::Lazy;
use regex::Regex;
use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_s3::{
    config::{Credentials, Region},
    error::SdkError,
    operation::put_object::{PutObjectError, PutObjectOutput},
    primitives::ByteStream,
    Client, Config,
};
use dotenv;

static CLIENT_DATA_SUFFIX: &str = "-bridge-client-data.json";
static CLIENT_DATA_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r"(\d{{13}}){}", CLIENT_DATA_SUFFIX)).unwrap());

static CLIENT_MISSING_CREDENTIALS_ERROR: &str = "Bridge client is missing AWS S3 credentials";

pub struct AwsS3 {
    initialized: bool,
    client: Option<Client>,
    bucket: Option<String>,
}

impl AwsS3 {
    pub fn new() -> Self {
        dotenv::dotenv().ok();
        let access_key = dotenv::var("BRIDGE_AWS_ACCESS_KEY_ID");
        let secret = dotenv::var("BRIDGE_AWS_SECRET_ACCESS_KEY");
        let region = dotenv::var("BRIDGE_AWS_REGION");
        let bucket = dotenv::var("BRIDGE_AWS_BUCKET");

        if access_key.is_err() || secret.is_err() || region.is_err() || bucket.is_err() {
            println!("{}", CLIENT_MISSING_CREDENTIALS_ERROR);
            return Self {
                initialized: false,
                client: None,
                bucket: None,
            };
        }

        let credentials =
            Credentials::new(access_key.unwrap(), secret.unwrap(), None, None, "Bridge");

        let config = Config::builder()
            .credentials_provider(credentials)
            .region(Region::new(region.unwrap()))
            .behavior_version_latest()
            .build();

        Self {
            initialized: true,
            client: Some(Client::from_conf(config)),
            bucket: Some(bucket.unwrap()),
        }
    }

    pub async fn fetch_latest_data(&self) -> Result<Option<String>, &str> {
        if !self.initialized {
            return Err(CLIENT_MISSING_CREDENTIALS_ERROR);
        }

        let keys = self.list_objects().await;
        let mut data_keys: Vec<String> = keys
            .iter()
            .filter(|key| CLIENT_DATA_REGEX.is_match(key))
            .cloned()
            .collect();
        data_keys.sort_by(|x, y| {
            if x < y {
                return Ordering::Less;
            }
            return Ordering::Greater;
        });

        while let Some(key) = data_keys.pop() {
            let json = self.get_object(&key).await;
            if json.is_ok() {
                println!("Fetched latest data file: {}", key);
                return Ok(Some(json.unwrap()));
            }
        }

        println!("No data file found");
        Ok(None)
    }

    pub async fn write_data(&self, json: String) -> Result<String, &str> {
        if !self.initialized {
            return Err(CLIENT_MISSING_CREDENTIALS_ERROR);
        }

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        println!("Time: {}", time);

        let key = format!("{}{}", time, CLIENT_DATA_SUFFIX);
        let bytes = json.as_bytes().to_vec();
        let size = bytes.len();
        let byte_stream = ByteStream::from(bytes);

        println!("Writing data file to {} ({})", key, size);
        let response = self.upload_object(&key, byte_stream).await;

        match response {
            Ok(_) => Ok(key),
            Err(_) => Err("Failed to save data file"),
        }
    }

    async fn list_objects(&self) -> Vec<String> {
        let mut response = self
            .client
            .as_ref()
            .unwrap()
            .list_objects_v2()
            .bucket(self.bucket.as_ref().unwrap())
            .max_keys(10) // In this example, go 10 at a time.
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
                    eprintln!("{err:?}")
                }
            }
        }

        keys
    }

    async fn get_object(&self, key: &str) -> Result<String, String> {
        let mut object = self
            .client
            .as_ref()
            .unwrap()
            .get_object()
            .bucket(self.bucket.as_ref().unwrap())
            .key(key)
            .send()
            .await
            .unwrap();

        let mut buffer: Vec<u8> = vec![];
        while let Some(bytes) = object.body.try_next().await.unwrap() {
            buffer.append(&mut bytes.to_vec());
        }

        let json = String::from_utf8(buffer);
        match json {
            Ok(json) => Ok(json),
            Err(err) => Err(format!("Failed to parse json: {}", err.to_string())),
        }
    }

    async fn upload_object(
        &self,
        key: &str,
        data: ByteStream,
    ) -> Result<PutObjectOutput, SdkError<PutObjectError>> {
        self.client
            .as_ref()
            .unwrap()
            .put_object()
            .bucket(self.bucket.as_ref().unwrap())
            .key(key)
            .body(data)
            .send()
            .await
    }
}
