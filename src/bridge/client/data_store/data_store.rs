use once_cell::sync::Lazy;
use regex::Regex;
use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use super::aws_s3::AwsS3;

static CLIENT_MISSING_CREDENTIALS_ERROR: &str = "Bridge client is missing AWS S3 credentials";

static CLIENT_DATA_SUFFIX: &str = "-bridge-client-data.json";
static CLIENT_DATA_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r"(\d{{13}}){}", CLIENT_DATA_SUFFIX)).unwrap());

pub struct DataStore {
    aws_s3: Option<AwsS3>,
}

impl DataStore {
    pub fn new() -> Self {
        Self {
            aws_s3: AwsS3::new(),
        }
    }

    pub async fn fetch_latest_data(&self) -> Result<Option<String>, &str> {
        if self.aws_s3.is_none() {
            return Err(CLIENT_MISSING_CREDENTIALS_ERROR);
        }

        let keys = self.aws_s3.as_ref().unwrap().list_objects().await;
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
            let json = self.aws_s3.as_ref().unwrap().fetch_json(&key).await;
            if json.is_ok() {
                println!("Fetched latest data file: {}", key);
                return Ok(Some(json.unwrap()));
            }
        }

        println!("No data file found");
        Ok(None)
    }

    pub async fn write_data(&self, json: String) -> Result<String, &str> {
        if self.aws_s3.is_none() {
            return Err(CLIENT_MISSING_CREDENTIALS_ERROR);
        }

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let key = format!("{}{}", time, CLIENT_DATA_SUFFIX);

        let response = self.aws_s3.as_ref().unwrap().upload_json(&key, json).await;

        match response {
            Ok(_) => Ok(key),
            Err(_) => Err("Failed to save data file"),
        }
    }
}
